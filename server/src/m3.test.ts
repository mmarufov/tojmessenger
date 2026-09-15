import { beforeEach, describe, expect, test } from "bun:test";
import { makeSql } from "./db";
import {
  startVerification,
  checkVerification,
  lookupAccountByPhone,
  lookupAccountByUsername,
  getProfile,
  updateProfile,
  startAccountDeletion,
  startSecurityChange,
  otpDeliveryRegistryFromEnvironment,
  deleteAccount,
  requireActiveDevice,
  resolveDevice,
  revokeDevice,
  AuthError,
  type OTPDelivery,
} from "./auth";
import { bodyAAD, hashToken, mediaFileNameAAD, pushTokenAAD } from "./crypto";
import { openForScope } from "./envelope-crypto";
import { CLOUD_CAPABILITIES, revalidateSocketSessions, startCloudServer } from "./cloud";
import { updateDialogPreferences } from "./dialog-preferences";
import { profilePhotosSchemaReadiness, updateProfilePhoto } from "./profile-photos";
import {
  cleanupExpiredData,
  drainExpiredData,
  OperationalMetrics,
  requestIdFrom,
  safeRoute,
} from "./ops";
import { fanoutDialogEvent } from "./fanout";
import {
  buildAPNsPayload,
  processPushBatch,
  registerPushToken,
  registerVoIPPushToken,
  type APNsSendRequest,
  type APNsSendResult,
  type PushSender,
} from "./push";
import {
  getBootstrapDialogsPage,
  getDifference,
  getHistory,
  loadProfiles,
  getOrCreateDirectDialog,
  readHistory,
  sendMessage,
  editMessage,
  deleteMessage,
  setReaction,
  startBootstrap,
} from "./sync";
import {
  cancelMediaUpload,
  completeMediaUpload,
  createMediaUpload,
  downloadMediaChunk,
  DEFAULT_MEDIA_CHUNK_BYTES,
  getMediaUpload,
  MEDIA_PART_SIZE,
  mediaLimits,
  MediaError,
  uploadMediaChunk,
  uploadMediaPart,
  uploadMediaThumbnail,
} from "./media";
import { createHash } from "node:crypto";
import { Client } from "pg";
import { TelegramOTPDelivery } from "./telegram-otp";

const TEST_URL = process.env.TEST_DATABASE_URL ?? "postgres://localhost:5432/toj_test";
const db = makeSql(TEST_URL);

async function resetDb() {
  delete process.env.TOJ_BLIND_INDEX_KEYRING;
  delete process.env.TOJ_BLIND_INDEX_ACTIVE_KEY_ID;
  await db`
    TRUNCATE
      abuse_report_actions,
      abuse_report_submission_budgets,
      abuse_reports,
      content_access_audit,
      bootstrap_snapshot_dialogs,
      bootstrap_snapshots,
      message_mutation_requests,
      message_reactions,
      send_requests,
      push_deliveries,
      account_events,
      messages,
      media_chunks,
      media_objects,
      media_upload_attempts,
      contact_lookup_attempts,
      dialog_members,
      direct_dialog_pairs,
      dialogs,
      devices,
      account_sync_states,
      accounts,
      otp_challenges
    RESTART IDENTITY CASCADE`;
}

async function makeAccount(phone: string, name: string) {
  const { code } = await startVerification(db, phone);
  return await checkVerification(db, phone, code, "ios", "Test iPhone", name);
}

async function waitForBackendLock(client: Client, pid: number): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const result = await client.query<{ wait_event_type: string | null }>(
      "SELECT wait_event_type FROM pg_stat_activity WHERE pid = $1",
      [pid],
    );
    if (result.rows[0]?.wait_event_type === "Lock") return;
    await Bun.sleep(10);
  }
  throw new Error(`backend ${pid} did not block on the account lock`);
}

/** One-channel registry, so a test can keep naming a single delivery object. */
function registryOf(delivery: OTPDelivery) {
  return new Map([[delivery.channel, delivery]]);
}

function testPhone(suffix: number): string {
  return ["+", "1650", "555", String(suffix).padStart(4, "0")].join("");
}

function tinyJpeg(width = 1, height = 1): Buffer {
  return Buffer.from([
    0xff, 0xd8,
    0xff, 0xc0, 0x00, 0x11, 0x08,
    (height >>> 8) & 0xff, height & 0xff,
    (width >>> 8) & 0xff, width & 0xff,
    0x03, 0x01, 0x11, 0x00, 0x02, 0x11, 0x00, 0x03, 0x11, 0x00,
    0xff, 0xd9,
  ]);
}

function tinyPng(width = 1, height = 1): Buffer {
  const bytes = Buffer.alloc(24);
  Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]).copy(bytes, 0);
  bytes.writeUInt32BE(13, 8);
  bytes.write("IHDR", 12, "ascii");
  bytes.writeUInt32BE(width, 16);
  bytes.writeUInt32BE(height, 20);
  return bytes;
}

async function addIOSDevice(accountId: string): Promise<{ deviceId: string }> {
  const authTokenHash = hashToken(crypto.randomUUID());
  const row = (await db`
    INSERT INTO devices (account_id, platform, device_name, auth_token_hash)
    VALUES (${accountId}, 'ios', 'Test iPhone', ${authTokenHash})
    RETURNING id`)[0];
  return { deviceId: row.id };
}

class StubPushSender implements PushSender {
  requests: APNsSendRequest[] = [];

  constructor(private readonly responses: APNsSendResult[]) {}

  async send(request: APNsSendRequest): Promise<APNsSendResult> {
    this.requests.push(request);
    return this.responses.shift() ?? { status: 200 };
  }
}

class PausedPushSender implements PushSender {
  requests: APNsSendRequest[] = [];
  readonly started: Promise<void>;
  private readonly releasePromise: Promise<void>;
  private markStarted!: () => void;
  private releaseSend!: () => void;

  constructor(private readonly response: APNsSendResult) {
    this.started = new Promise((resolve) => { this.markStarted = resolve; });
    this.releasePromise = new Promise((resolve) => { this.releaseSend = resolve; });
  }

  async send(request: APNsSendRequest): Promise<APNsSendResult> {
    this.requests.push(request);
    this.markStarted();
    await this.releasePromise;
    return this.response;
  }

  release(): void {
    this.releaseSend();
  }
}

class FailingOTPDelivery implements OTPDelivery {
  readonly channel = "sms" as const;
  async send(_phone: string, _code: string, _purpose: "login" | "account_deletion"): Promise<void> {
    throw new Error("provider unavailable");
  }
}

async function makePair() {
  const alice = await makeAccount("+16505550100", "Alice");
  const bob = await makeAccount("+16505550101", "Bob");
  const direct = await getOrCreateDirectDialog(db, alice.accountId, bob.accountId);
  return { alice, bob, dialogId: direct.dialogId };
}

describe("M3 cloud sync", () => {
  test("media uploads default to one-megabyte WAN chunks", () => {
    expect(DEFAULT_MEDIA_CHUNK_BYTES).toBe(1024 * 1024);
  });

  beforeEach(resetDb);

  test("phone OTP creates an account, device, and sync state", async () => {
    const alice = await makeAccount("+16505550110", "Alice");
    expect(alice.accountId).toBeString();
    expect(alice.deviceId).toBeString();
    expect(alice.token.length).toBeGreaterThan(20);

    const state = (await db`SELECT pts, pruned_through_pts FROM account_sync_states WHERE account_id = ${alice.accountId}`)[0];
    expect(Number(state.pts)).toBe(0);
    expect(Number(state.pruned_through_pts)).toBe(0);
  });

  test("OTP requests enforce cooldown and store a per-challenge salt", async () => {
    const phone = testPhone(120);
    const first = await startVerification(db, phone, { networkKey: "test-network" });
    expect(first.code).toMatch(/^\d{6}$/);
    expect(first.retryAfter).toBe(30);
    const stored = (await db`
      SELECT code_salt, network_hash FROM otp_challenges`)[0];
    expect(Buffer.from(stored.code_salt)).toHaveLength(16);
    expect(stored.network_hash).not.toBeNull();

    let error: unknown;
    try {
      await startVerification(db, phone, { networkKey: "test-network" });
    } catch (value) {
      error = value;
    }
    expect(error).toBeInstanceOf(AuthError);
    expect((error as AuthError).status).toBe(429);
    expect((error as AuthError).retryAfter).toBeGreaterThan(0);
  });

  test("OTP request windows cap phone and network abuse", async () => {
    const phone = testPhone(130);
    for (let request = 0; request < 5; request += 1) {
      await startVerification(db, phone, { networkKey: "phone-limit-network" });
      await db`
        UPDATE otp_challenges SET created_at = created_at - interval '31 seconds'
        WHERE id = (SELECT id FROM otp_challenges ORDER BY created_at DESC LIMIT 1)`;
    }
    let phoneError: unknown;
    try { await startVerification(db, phone, { networkKey: "phone-limit-network" }); }
    catch (value) { phoneError = value; }
    expect(phoneError).toBeInstanceOf(AuthError);
    expect((phoneError as AuthError).status).toBe(429);

    await resetDb();
    for (let request = 0; request < 20; request += 1) {
      await startVerification(db, testPhone(200 + request), { networkKey: "shared-network" });
    }
    let networkError: unknown;
    try { await startVerification(db, testPhone(220), { networkKey: "shared-network" }); }
    catch (value) { networkError = value; }
    expect(networkError).toBeInstanceOf(AuthError);
    expect((networkError as AuthError).status).toBe(429);
  });

  test.each(["production", "staging"])("%s refuses to issue an OTP without a delivery adapter", async (environment) => {
    const previous = process.env.NODE_ENV;
    const previousReturnOTP = process.env.TOJ_RETURN_OTP;
    const previousHmacKey = process.env.TOJ_HMAC_KEY;
    process.env.NODE_ENV = environment;
    process.env.TOJ_HMAC_KEY = Buffer.alloc(32, 0x31).toString("base64");
    delete process.env.TOJ_RETURN_OTP;
    let error: unknown;
    try { await startVerification(db, testPhone(131)); }
    catch (value) { error = value; }
    finally {
      if (previous === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = previous;
      if (previousReturnOTP === undefined) delete process.env.TOJ_RETURN_OTP;
      else process.env.TOJ_RETURN_OTP = previousReturnOTP;
      if (previousHmacKey === undefined) delete process.env.TOJ_HMAC_KEY;
      else process.env.TOJ_HMAC_KEY = previousHmacKey;
    }
    expect(error).toBeInstanceOf(AuthError);
    expect((error as AuthError).status).toBe(503);
    expect(await db`SELECT id FROM otp_challenges`).toHaveLength(0);
  });

  test.each(["production", "staging"])("private-beta OTP return requires the explicit switch and %s phone allowlist", async (environment) => {
    const previousNodeEnv = process.env.NODE_ENV;
    const previousReturnOTP = process.env.TOJ_RETURN_OTP;
    const previousAllowlist = process.env.TOJ_DEV_OTP_ALLOWLIST;
    const previousHmacKey = process.env.TOJ_HMAC_KEY;
    process.env.NODE_ENV = environment;
    process.env.TOJ_HMAC_KEY = Buffer.alloc(32, 0x32).toString("base64");
    process.env.TOJ_RETURN_OTP = "1";
    delete process.env.TOJ_DEV_OTP_ALLOWLIST;
    const phone = testPhone(132);
    try {
      await expect(startVerification(db, phone)).rejects.toMatchObject({ status: 503 });
      process.env.TOJ_DEV_OTP_ALLOWLIST = phone;
      const issued = await startVerification(db, phone);
      expect(issued.code).toMatch(/^\d{6}$/);
      expect(issued.retryAfter).toBe(30);
    } finally {
      if (previousNodeEnv === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = previousNodeEnv;
      if (previousReturnOTP === undefined) delete process.env.TOJ_RETURN_OTP;
      else process.env.TOJ_RETURN_OTP = previousReturnOTP;
      if (previousAllowlist === undefined) delete process.env.TOJ_DEV_OTP_ALLOWLIST;
      else process.env.TOJ_DEV_OTP_ALLOWLIST = previousAllowlist;
      if (previousHmacKey === undefined) delete process.env.TOJ_HMAC_KEY;
      else process.env.TOJ_HMAC_KEY = previousHmacKey;
    }
  });

  test("wrong OTP attempts persist and lock the challenge", async () => {
    const phone = testPhone(121);
    const { code } = await startVerification(db, phone);
    const wrongCode = code === "000000" ? "000001" : "000000";
    for (let attempt = 0; attempt < 5; attempt += 1) {
      try { await checkVerification(db, phone, wrongCode); } catch { /* expected */ }
    }
    expect(Number((await db`SELECT attempts FROM otp_challenges`)[0].attempts)).toBe(5);
    let error: unknown;
    try { await checkVerification(db, phone, code!); } catch (value) { error = value; }
    expect(error).toBeInstanceOf(AuthError);
    expect((error as AuthError).status).toBe(429);
  });

  test("a verification code can create only one session under concurrency", async () => {
    const phone = testPhone(122);
    const { code } = await startVerification(db, phone);
    const results = await Promise.allSettled([
      checkVerification(db, phone, code!),
      checkVerification(db, phone, code!),
    ]);
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(results.filter((result) => result.status === "rejected")).toHaveLength(1);
    expect(await db`SELECT id FROM devices`).toHaveLength(1);
  });

  test("account deletion requires a purpose-bound fresh code and erases identity", async () => {
    const phone = testPhone(133);
    const alice = await makeAccount(phone, "Alice Personal Name");
    const bob = await makeAccount(testPhone(134), "Bob");
    await db`UPDATE accounts SET username = 'alice_delete' WHERE id = ${alice.accountId}`;
    const secondDevice = await addIOSDevice(alice.accountId);
    await registerPushToken(db, secondDevice.deviceId, "88".repeat(32), "sandbox");
    await registerVoIPPushToken(db, secondDevice.deviceId, "99".repeat(32), "sandbox");
    const dialog = await getOrCreateDirectDialog(db, alice.accountId, bob.accountId);
    await updateDialogPreferences(db, {
      accountId: alice.accountId,
      deviceId: alice.deviceId,
      dialogId: dialog.dialogId,
      clientMutationId: crypto.randomUUID(),
      patch: { pinned: true, muted: true, archived: true },
    });
    await sendMessage(db, {
      senderAccountId: alice.accountId,
      senderDeviceId: alice.deviceId,
      dialogId: dialog.dialogId,
      clientMsgId: crypto.randomUUID(),
      body: "history remains for the other participant",
    });
    await startBootstrap(db, alice.accountId);

    const original = (await db`
      SELECT phone_lookup_hash, phone_e164_ciphertext FROM accounts WHERE id = ${alice.accountId}`)[0];
    process.env.TOJ_BLIND_INDEX_KEYRING = JSON.stringify({
      "identity-v2": Buffer.alloc(32, 0x6a).toString("base64"),
    });
    process.env.TOJ_BLIND_INDEX_ACTIVE_KEY_ID = "identity-v2";
    const deletion = await startAccountDeletion(db, alice.accountId);
    expect(deletion.code).toMatch(/^\d{6}$/);
    const activeChallenge = (await db`
      SELECT purpose FROM otp_challenges WHERE consumed_at IS NULL`)[0];
    expect(activeChallenge.purpose).toBe("account_deletion");

    let loginError: unknown;
    try { await checkVerification(db, phone, deletion.code!, "ios", "Wrong purpose", "Alice"); }
    catch (error) { loginError = error; }
    expect(loginError).toBeInstanceOf(AuthError);
    expect(await db`SELECT id FROM devices WHERE account_id = ${alice.accountId}`).toHaveLength(2);

    const result = await deleteAccount(db, alice.accountId, deletion.code!);
    expect(result).toEqual({ deleted: true });
    const deleted = (await db`
      SELECT username, phone_lookup_hash, phone_e164_ciphertext, display_name, status
      FROM accounts WHERE id = ${alice.accountId}`)[0];
    expect(deleted.status).toBe("deleted");
    expect(deleted.username).toBeNull();
    expect(deleted.display_name).toBe("Deleted Account");
    expect(Buffer.from(deleted.phone_lookup_hash).equals(Buffer.from(original.phone_lookup_hash))).toBe(false);
    expect(Buffer.from(deleted.phone_e164_ciphertext).includes(Buffer.from(phone))).toBe(false);
    expect(await db`
      SELECT id FROM devices WHERE account_id = ${alice.accountId} AND revoked_at IS NULL`).toHaveLength(0);
    expect(await db`
      SELECT dialog_id FROM dialog_preferences WHERE account_id = ${alice.accountId}`).toHaveLength(0);
    expect(await db`
      SELECT client_mutation_id FROM dialog_preference_requests
      WHERE account_id = ${alice.accountId}`).toHaveLength(0);
    expect(await db`
      SELECT account_id FROM dialog_preference_action_budgets
      WHERE account_id = ${alice.accountId}`).toHaveLength(0);
    expect(await db`
      SELECT pts FROM account_events
      WHERE account_id = ${alice.accountId}
        AND type = 'dialog.preferences_updated'`).toHaveLength(0);
    expect(await db`
      SELECT id FROM bootstrap_snapshots
      WHERE account_id = ${alice.accountId}`).toHaveLength(0);
    const erasedDevice = (await db`
      SELECT auth_token_key_id, push_token_hash, push_token_hash_key_id,
        voip_push_token_hash, voip_push_token_hash_key_id, device_name
      FROM devices WHERE id = ${secondDevice.deviceId}`)[0];
    expect(erasedDevice.push_token_hash).toBeNull();
    expect(erasedDevice.push_token_hash_key_id).toBeNull();
    expect(erasedDevice.voip_push_token_hash).toBeNull();
    expect(erasedDevice.voip_push_token_hash_key_id).toBeNull();
    expect(erasedDevice.auth_token_key_id).toBe("random-deleted");
    expect(erasedDevice.device_name).toBeNull();
    expect(await db`SELECT id FROM otp_challenges WHERE phone_lookup_hash = ${Buffer.from(original.phone_lookup_hash)}`)
      .toHaveLength(0);
    expect(await lookupAccountByPhone(db, bob.accountId, phone)).toBeNull();
    await expect(resolveDevice(db, alice.token)).rejects.toBeInstanceOf(AuthError);
    await expect(sendMessage(db, {
      senderAccountId: alice.accountId,
      senderDeviceId: alice.deviceId,
      dialogId: dialog.dialogId,
      clientMsgId: crypto.randomUUID(),
      body: "must not send after deletion",
    })).rejects.toThrow("account unavailable");
    expect((await getHistory(db, bob.accountId, dialog.dialogId)).messages.map((message) => message.text))
      .toContain("history remains for the other participant");

    const replacement = await makeAccount(phone, "New Alice");
    expect(replacement.accountId).not.toBe(alice.accountId);
  });

  test("concurrent account deletion consumes one code once and never partially deletes", async () => {
    const phone = testPhone(135);
    const account = await makeAccount(phone, "Concurrency");
    const { code } = await startAccountDeletion(db, account.accountId);
    const wrong = code === "000000" ? "000001" : "000000";
    let wrongError: unknown;
    try { await deleteAccount(db, account.accountId, wrong); } catch (error) { wrongError = error; }
    expect(wrongError).toBeInstanceOf(AuthError);
    expect((wrongError as AuthError).status).toBe(400);
    expect(Number((await db`
      SELECT attempts FROM otp_challenges WHERE purpose = 'account_deletion'`)[0].attempts)).toBe(1);
    expect((await db`SELECT status FROM accounts WHERE id = ${account.accountId}`)[0].status).toBe("active");

    const results = await Promise.allSettled([
      deleteAccount(db, account.accountId, code!),
      deleteAccount(db, account.accountId, code!),
    ]);
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(results.filter((result) => result.status === "rejected")).toHaveLength(1);
    expect((await db`SELECT status FROM accounts WHERE id = ${account.accountId}`)[0].status).toBe("deleted");
    expect(await db`
      SELECT id FROM devices WHERE account_id = ${account.accountId} AND revoked_at IS NULL`).toHaveLength(0);
  });

  test("device revalidation takes the account lock before the device lock", async () => {
    const account = await makeAccount(testPhone(136), "Lock order");
    const accountBlocker = new Client({ connectionString: TEST_URL });
    const deviceProbe = new Client({ connectionString: TEST_URL });
    await Promise.all([accountBlocker.connect(), deviceProbe.connect()]);

    let validation: Promise<void> | null = null;
    let deviceWasAvailable = false;
    let validationError: unknown;
    try {
      await accountBlocker.query("BEGIN");
      await accountBlocker.query(
        "SELECT id FROM accounts WHERE id = $1 FOR UPDATE",
        [account.accountId],
      );

      let announcePID!: (pid: number) => void;
      const validationPID = new Promise<number>((resolve) => { announcePID = resolve; });
      validation = db.begin(async (tx) => {
        const row = (await tx`SELECT pg_backend_pid() AS pid`)[0];
        announcePID(Number(row.pid));
        await requireActiveDevice(tx, account.accountId, account.deviceId);
      });
      await waitForBackendLock(deviceProbe, await validationPID);

      await deviceProbe.query("BEGIN");
      await deviceProbe.query("SET LOCAL lock_timeout = '250ms'");
      try {
        await deviceProbe.query(
          "SELECT id FROM devices WHERE id = $1 FOR UPDATE",
          [account.deviceId],
        );
        deviceWasAvailable = true;
      } catch {
        deviceWasAvailable = false;
      }
    } finally {
      await deviceProbe.query("ROLLBACK").catch(() => {});
      await accountBlocker.query("ROLLBACK").catch(() => {});
      if (validation) {
        try { await validation; } catch (error) { validationError = error; }
      }
      await Promise.all([accountBlocker.end(), deviceProbe.end()]);
    }

    expect(validationError).toBeUndefined();
    expect(deviceWasAvailable).toBe(true);
  });

  test("legacy notification writes serialize with account deletion", async () => {
    const { alice, dialogId } = await makePair();
    const deletion = await startAccountDeletion(db, alice.accountId);
    if (!deletion.code) throw new Error("missing deletion code");
    let reachedCommit!: () => void;
    const atCommit = new Promise<void>((resolve) => { reachedCommit = resolve; });
    let releaseCommit!: () => void;
    const released = new Promise<void>((resolve) => { releaseCommit = resolve; });

    const deleting = deleteAccount(db, alice.accountId, deletion.code, {
      beforeCommit: async () => {
        reachedCommit();
        await released;
      },
    });
    await atCommit;

    let writeSettled = false;
    const legacyWrite = (async () => {
      try {
        await db`
          UPDATE dialog_members
          SET notification_mode = 'muted'
          WHERE dialog_id = ${dialogId} AND account_id = ${alice.accountId}`;
        return null;
      } catch (error) {
        return error;
      } finally {
        writeSettled = true;
      }
    })();
    await Bun.sleep(40);
    expect(writeSettled).toBe(false);
    releaseCommit();
    await deleting;
    const writeError = await legacyWrite;
    expect(String((writeError as Error)?.message)).toContain(
      "dialog_preference_account_unavailable",
    );
    expect(await db`
      SELECT dialog_id FROM dialog_preferences WHERE account_id = ${alice.accountId}`)
      .toHaveLength(0);
    expect(await db`
      SELECT pts FROM account_events
      WHERE account_id = ${alice.accountId}
        AND type = 'dialog.preferences_updated'`).toHaveLength(0);
  }, 10_000);

  test("account deletion HTTP flow requires auth and invalidates the session", async () => {
    const server = startCloudServer(0, db, null, null);
    const base = `http://127.0.0.1:${server.port}`;
    try {
      const account = await makeAccount(testPhone(136), "HTTP Delete");
      const unauthorized = await fetch(`${base}/v1/account/deletion/start`, { method: "POST" });
      expect(unauthorized.status).toBe(401);
      const started = await fetch(`${base}/v1/account/deletion/start`, {
        method: "POST",
        headers: { authorization: `Bearer ${account.token}` },
      });
      expect(started.status).toBe(200);
      const { code } = await started.json() as { code: string };
      const deleted = await fetch(`${base}/v1/account`, {
        method: "DELETE",
        headers: { authorization: `Bearer ${account.token}`, "content-type": "application/json" },
        body: JSON.stringify({ code }),
      });
      expect(deleted.status).toBe(200);
      expect(await deleted.json()).toEqual({ deleted: true });
      const oldSession = await fetch(`${base}/v1/devices`, {
        headers: { authorization: `Bearer ${account.token}` },
      });
      expect(oldSession.status).toBe(401);
    } finally {
      await server.stop(true);
    }
  });

  test("cloud auth maps throttles and accepts WebSocket bearer tokens only in headers", async () => {
    const server = startCloudServer(0, db, null, null);
    const base = `http://127.0.0.1:${server.port}`;
    try {
      const invalid = await fetch(`${base}/v1/auth/start`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ phone: "invalid" }),
      });
      expect(invalid.status).toBe(400);
      expect(invalid.headers.get("cache-control")).toBe("no-store");

      const session = await makeAccount(testPhone(124), "Alice");
      const extraDevice = await addIOSDevice(session.accountId);
      const queryToken = await fetch(`${base}/v1/ws?token=${encodeURIComponent(session.token)}`);
      expect(queryToken.status).toBe(401);
      let legacyQueryToken: Response;
      try {
        process.env.TOJ_ALLOW_LEGACY_WS_QUERY_TOKEN = "1";
        legacyQueryToken = await fetch(`${base}/v1/ws?token=${encodeURIComponent(session.token)}`);
      } finally {
        delete process.env.TOJ_ALLOW_LEGACY_WS_QUERY_TOKEN;
      }
      expect(legacyQueryToken.status).toBe(400);
      const headerToken = await fetch(`${base}/v1/ws`, {
        headers: { authorization: `Bearer ${session.token}` },
      });
      expect(headerToken.status).toBe(400);

      const devices = await fetch(`${base}/v1/devices`, {
        headers: { authorization: `Bearer ${session.token}` },
      });
      expect(devices.status).toBe(200);
      const deviceBody = await devices.json() as { devices: Array<{ id: string; current: boolean }> };
      expect(deviceBody.devices).toHaveLength(2);
      expect(deviceBody.devices.find((device) => device.id === session.deviceId)?.current).toBe(true);

      const revokeOther = await fetch(`${base}/v1/devices/${extraDevice.deviceId}`, {
        method: "DELETE",
        headers: { authorization: `Bearer ${session.token}` },
      });
      expect(revokeOther.status).toBe(200);
      expect((await db`SELECT revoked_at FROM devices WHERE id = ${extraDevice.deviceId}`)[0].revoked_at).not.toBeNull();

      const revoked = await fetch(`${base}/v1/session`, {
        method: "DELETE",
        headers: { authorization: `Bearer ${session.token}` },
      });
      expect(revoked.status).toBe(200);
      expect(await revoked.json()).toEqual({ revoked: true });
      const afterRevoke = await fetch(`${base}/v1/sync/state`, {
        headers: { authorization: `Bearer ${session.token}` },
      });
      expect(afterRevoke.status).toBe(401);
      expect((await db`SELECT revoked_at FROM devices WHERE id = ${session.deviceId}`)[0].revoked_at).not.toBeNull();
    } finally {
      await server.stop(true);
    }
  });

  test("cloud websocket sends a late-join sync hint on open", async () => {
    const server = startCloudServer(0, db, null, null);
    try {
      const session = await makeAccount(testPhone(150), "Hinted");
      const socket = new WebSocket(`ws://127.0.0.1:${server.port}/v1/ws`, {
        headers: { authorization: `Bearer ${session.token}` },
      });
      try {
        const first = await new Promise<string>((resolve, reject) => {
          const timer = setTimeout(() => reject(new Error("no hint within 3s of open")), 3000);
          socket.onmessage = (event) => {
            clearTimeout(timer);
            resolve(String(event.data));
          };
          socket.onerror = () => {
            clearTimeout(timer);
            reject(new Error("socket error"));
          };
        });
        const hint = JSON.parse(first) as { type: string; pts: number; ptsCount: number };
        expect(hint.type).toBe("sync_hint");
        expect(typeof hint.pts).toBe("number");
        expect(hint.pts).toBeGreaterThanOrEqual(0);
      } finally {
        socket.close();
      }
    } finally {
      await server.stop(true);
    }
  });

  test("session reconciliation closes a socket after a missed ban notification", async () => {
    const session = await makeAccount(testPhone(151), "Reconciled");
    const closures: Array<{ code: number; reason: string }> = [];
    const socket = {
      data: { accountId: session.accountId, deviceId: session.deviceId },
      close(code: number, reason: string) { closures.push({ code, reason }); },
    };
    const sockets = new Map([[session.accountId, new Set([socket])]]);
    // Deliberately omit pg_notify to model a listener disconnect or lost notification. The server
    // invokes this same database reconciliation pass every five seconds in production.
    await db`UPDATE accounts SET status = 'banned' WHERE id = ${session.accountId}`;
    await revalidateSocketSessions(db, sockets as any);
    expect(closures).toEqual([{ code: 4002, reason: "account or device disabled" }]);
  });

  test("operations endpoints expose safe readiness, correlation IDs, and protected metrics", async () => {
    const previousMetricsToken = process.env.TOJ_METRICS_TOKEN;
    const previousReturnOTP = process.env.TOJ_RETURN_OTP;
    process.env.TOJ_METRICS_TOKEN = "test-metrics-token";
    delete process.env.TOJ_RETURN_OTP;
    const server = startCloudServer(0, db, null, null);
    const base = `http://127.0.0.1:${server.port}`;
    try {
      const ready = await fetch(`${base}/ready`, { headers: { "x-request-id": "client-request-123" } });
      expect(ready.status).toBe(200);
      expect(ready.headers.get("x-request-id")).toBe("client-request-123");
      expect(await ready.json()).toMatchObject({
        status: "ready", database: "ready", providers: { sms: "disabled", push: "disabled" },
      });

      const unauthorized = await fetch(`${base}/metrics`);
      expect(unauthorized.status).toBe(401);
      expect(await unauthorized.text()).not.toContain("test-metrics-token");

      const metrics = await fetch(`${base}/metrics`, {
        headers: { authorization: "Bearer test-metrics-token" },
      });
      expect(metrics.status).toBe(200);
      const text = await metrics.text();
      expect(text).toContain("toj_http_requests_total");
      expect(text).toContain('route="/ready"');
      expect(text).not.toContain("client-request-123");
    } finally {
      await server.stop(true);
      if (previousMetricsToken === undefined) delete process.env.TOJ_METRICS_TOKEN;
      else process.env.TOJ_METRICS_TOKEN = previousMetricsToken;
      if (previousReturnOTP === undefined) delete process.env.TOJ_RETURN_OTP;
      else process.env.TOJ_RETURN_OTP = previousReturnOTP;
    }
  });

  test("operations sanitize request metadata and cleanup only bounded expired data", async () => {
    const malformed = new Request("https://example.test/v1/devices/private", {
      headers: { "x-request-id": "bad id with spaces" },
    });
    expect(requestIdFrom(malformed)).toMatch(/^[0-9a-f-]{36}$/);
    expect(safeRoute("/v1/devices/00000000-0000-0000-0000-000000000000")).toBe("/v1/devices/:id");
    expect(safeRoute("/private/phone-number")).toBe("unmatched");
    const metrics = new OperationalMetrics();
    metrics.record("GET", "unmatched", 404, 1);
    expect(metrics.render()).not.toContain("phone-number");

    await startVerification(db, testPhone(125));
    await db`UPDATE otp_challenges SET expires_at = now() - interval '25 hours'`;
    const account = await makeAccount(testPhone(126), "Cleanup");
    await startBootstrap(db, account.accountId);
    await db`UPDATE bootstrap_snapshots SET expires_at = now() - interval '1 minute'`;
    await createMediaUpload(db, account.accountId, account.deviceId, {
      kind: "file", contentType: "application/octet-stream", fileName: "expired.bin",
      byteSize: 4, sha256: createHash("sha256").update("test").digest("hex"),
    });
    await db`UPDATE media_objects SET expires_at = now() - interval '1 minute' WHERE status = 'uploading'`;
    const completedPreferenceRequest = crypto.randomUUID();
    const pendingPreferenceRequest = crypto.randomUUID();
    await db`
      INSERT INTO dialog_preference_requests (
        account_id, client_mutation_id, dialog_id, fingerprint, status, created_at
      ) VALUES
        (
          ${account.accountId}, ${completedPreferenceRequest}, ${crypto.randomUUID()},
          ${Buffer.alloc(32)}, 'completed', now() - interval '25 hours'
        ),
        (
          ${account.accountId}, ${pendingPreferenceRequest}, ${crypto.randomUUID()},
          ${Buffer.alloc(32)}, 'pending', now() - interval '25 hours'
        )`;
    await db`
      INSERT INTO dialog_preference_action_budgets (
        account_id, bucket_started, mutation_count, updated_at
      ) VALUES (
        ${account.accountId}, date_trunc('hour', now() - interval '25 hours'),
        7, now() - interval '25 hours'
      )`;

    const deleted = await cleanupExpiredData(db, 1);
    expect(deleted).toMatchObject({
      otp: 1,
      snapshots: 1,
      pushDeliveries: 0,
      mediaUploads: 1,
      dialogPreferenceRequests: 0,
      dialogPreferenceBudgets: 1,
    });
    expect(await db`SELECT id FROM bootstrap_snapshots`).toHaveLength(0);
    expect(await db`SELECT id FROM media_objects WHERE status = 'uploading'`).toHaveLength(0);
    expect(await db`
      SELECT client_mutation_id FROM dialog_preference_requests
      WHERE account_id = ${account.accountId}
      ORDER BY client_mutation_id`)
      .toEqual([
        completedPreferenceRequest,
        pendingPreferenceRequest,
      ].sort().map((client_mutation_id) => expect.objectContaining({ client_mutation_id })));
  });

  test("maintenance drains sustained ingress within explicit row and runtime budgets", async () => {
    const account = await makeAccount(testPhone(127), "Cleanup drain");
    await db`
      INSERT INTO dialog_preference_action_budgets (
        account_id, bucket_started, mutation_count, updated_at
      )
      SELECT ${account.accountId},
             date_trunc('hour', now() - interval '48 hours') + series * interval '1 minute',
             1,
             now() - interval '48 hours'
      FROM generate_series(1, 25) AS series`;
    const first = await drainExpiredData(db, {
      batchSize: 3,
      maxRows: 20,
      maxRuntimeMs: 10_000,
    });
    expect(first.rows).toBe(20);
    expect(first.passes).toBeGreaterThan(1);
    expect(first.exhausted).toBe(true);

    await db`
      INSERT INTO dialog_preference_action_budgets (
        account_id, bucket_started, mutation_count, updated_at
      )
      SELECT ${account.accountId},
             date_trunc('hour', now() - interval '72 hours') + series * interval '1 minute',
             1,
             now() - interval '72 hours'
      FROM generate_series(1, 7) AS series`;
    const second = await drainExpiredData(db, {
      batchSize: 2,
      maxRows: 100,
      maxRuntimeMs: 10_000,
    });
    expect(second.rows).toBe(12);
    expect(await db`
      SELECT account_id FROM dialog_preference_action_budgets
      WHERE updated_at < now() - interval '24 hours'`).toHaveLength(0);
  });

  test("maintenance counts and drains draft and media-group-only backlogs across passes", async () => {
    const { alice, dialogId } = await makePair();
    await db`
      INSERT INTO draft_mutation_requests (
        account_id, operation_id, dialog_id, payload_fingerprint, status, created_at
      )
      SELECT ${alice.accountId}, gen_random_uuid(), ${dialogId}, gen_random_bytes(32),
             'pending', now() - interval '25 hours'
      FROM generate_series(1, 2)`;
    await db`
      INSERT INTO draft_mutation_budgets (
        account_id, device_id, operation_id, accepted_at
      )
      SELECT ${alice.accountId}, ${alice.deviceId}, gen_random_uuid(),
             now() - interval '3 minutes'
      FROM generate_series(1, 2)`;
    await db`
      INSERT INTO media_group_send_requests (
        sender_account_id, client_group_id, dialog_id, payload_fingerprint,
        status, created_at
      )
      SELECT ${alice.accountId}, gen_random_uuid(), ${dialogId}, gen_random_bytes(32),
             'pending', now() - interval '25 hours'
      FROM generate_series(1, 2)`;
    await db`
      INSERT INTO media_group_send_budgets (
        account_id, device_id, item_count, accepted_at
      )
      SELECT ${alice.accountId}, ${alice.deviceId}, 2, now() - interval '3 minutes'
      FROM generate_series(1, 2)`;

    const drained = await drainExpiredData(db, {
      batchSize: 1,
      maxRows: 100,
      maxRuntimeMs: 10_000,
    });

    expect(drained.rows).toBe(8);
    expect(drained.passes).toBe(3);
    expect(drained.exhausted).toBe(false);
    const remaining = (await db`
      SELECT
        (SELECT count(*) FROM draft_mutation_requests)
        + (SELECT count(*) FROM draft_mutation_budgets)
        + (SELECT count(*) FROM media_group_send_requests)
        + (SELECT count(*) FROM media_group_send_budgets) AS count`)[0];
    expect(Number(remaining.count)).toBe(0);
  });

  test("Telegram HTTP login enforces consent and recipient scope, hides OTP, and reports the real channel", async () => {
    const previous = process.env.TOJ_RETURN_OTP;
    process.env.TOJ_RETURN_OTP = "0";
    const phone = testPhone(190);
    let deliveredCode = "";
    let sends = 0;
    const delivery = new TelegramOTPDelivery("synthetic", [phone], async (_url, init) => {
      sends++;
      deliveredCode = JSON.parse(init.body as string).code;
      return Response.json({ ok: true, result: { request_id: "test", phone_number: phone, request_cost: 0 } });
    });
    const server = startCloudServer(0, db, null, registryOf(delivery), { backgroundWorkers: false });
    const base = `http://127.0.0.1:${server.port}`;
    const request = (body: unknown) => fetch(`${base}/v1/auth/start`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
    });
    try {
      expect((await request({ phone })).status).toBe(400);
      expect((await request({ phone: testPhone(191), deliveryChannel: "telegram" })).status).toBe(503);
      expect(await db`SELECT id FROM otp_challenges`).toHaveLength(0);
      expect(sends).toBe(0);
      const response = await request({ phone, deliveryChannel: "telegram" });
      expect(response.status).toBe(200);
      expect(await response.json()).toEqual({ retryAfter: 30 });
      expect(sends).toBe(1);
      expect((await request({ phone, deliveryChannel: "telegram" })).status).toBe(429);
      expect(sends).toBe(1);
      const session = await checkVerification(db, phone, deliveredCode, "ios", "Test", "Telegram Test");
      expect(session.accountId).toBeTruthy();
      const ready = await (await fetch(`${base}/ready`)).json() as any;
      expect(ready.providers).toMatchObject({ sms: "disabled", telegram: "configured" });
      // Accidental operator re-enabling of the old bypass must fail closed, not expose a code.
      process.env.TOJ_RETURN_OTP = "1";
      expect((await request({ phone, deliveryChannel: "telegram" })).status).toBe(503);
      expect(sends).toBe(1);
    } finally {
      await server.stop(true);
      if (previous === undefined) delete process.env.TOJ_RETURN_OTP; else process.env.TOJ_RETURN_OTP = previous;
    }
  });

  test("Telegram daily budget is database-backed and serialized across concurrent recipients", async () => {
    const previous = process.env.TOJ_RETURN_OTP;
    process.env.TOJ_RETURN_OTP = "0";
    let sends = 0;
    const delivery: OTPDelivery = { channel: "telegram", dailyRequestLimit: 1,
      allows: () => true, async send() { sends++; } };
    try {
      const results = await Promise.allSettled([192, 193].map((suffix) => startVerification(db, testPhone(suffix), {
        deliveries: registryOf(delivery), deliveryChannel: "telegram",
      })));
      expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
      expect(results.filter((result) => result.status === "rejected")).toHaveLength(1);
      expect(sends).toBe(1);
      expect(await db`SELECT id FROM otp_challenges`).toHaveLength(1);
      await expect(startVerification(db, testPhone(194),
        { deliveries: registryOf({ ...delivery }), deliveryChannel: "telegram" }))
        .rejects.toMatchObject({ status: 429 });
    } finally {
      if (previous === undefined) delete process.env.TOJ_RETURN_OTP; else process.env.TOJ_RETURN_OTP = previous;
    }
  });

  test("Telegram provider failure consumes challenge without leaking a code or retrying", async () => {
    const previous = process.env.TOJ_RETURN_OTP;
    process.env.TOJ_RETURN_OTP = "0";
    let sends = 0;
    const delivery = new TelegramOTPDelivery("synthetic", [testPhone(195)], async () => {
      sends++;
      return Response.json({ ok: false, error: "provider details must stay private" });
    });
    try {
      await expect(startVerification(db, testPhone(195), { deliveries: registryOf(delivery), deliveryChannel: "telegram" }))
        .rejects.toMatchObject({ status: 503 });
      expect(sends).toBe(1);
      expect((await db`SELECT consumed_at FROM otp_challenges`)[0].consumed_at).not.toBeNull();
    } finally {
      if (previous === undefined) delete process.env.TOJ_RETURN_OTP; else process.env.TOJ_RETURN_OTP = previous;
    }
  });

  test("challenge retention outlives the budget window so maintenance cannot refill it", async () => {
    const previous = process.env.TOJ_RETURN_OTP;
    process.env.TOJ_RETURN_OTP = "0";
    const delivery: OTPDelivery = { channel: "telegram", dailyRequestLimit: 1,
      allows: () => true, async send() {} };
    const backdate = (hours: number) => db`
      UPDATE otp_challenges SET created_at = now() - (${hours} * interval '1 hour'),
        expires_at = now() - (${hours} * interval '1 hour') + interval '5 minutes'`;
    try {
      await startVerification(db, testPhone(196), { deliveries: registryOf(delivery), deliveryChannel: "telegram" });
      await backdate(23);
      await cleanupExpiredData(db);
      expect(await db`SELECT id FROM otp_challenges`).toHaveLength(1);
      await expect(startVerification(db, testPhone(197), { deliveries: registryOf(delivery), deliveryChannel: "telegram" }))
        .rejects.toMatchObject({ status: 429 });

      // Past the window the same maintenance does drop the row and the budget legitimately refills.
      await backdate(25);
      await cleanupExpiredData(db);
      expect(await db`SELECT id FROM otp_challenges`).toHaveLength(0);
      await startVerification(db, testPhone(197), { deliveries: registryOf(delivery), deliveryChannel: "telegram" });
    } finally {
      if (previous === undefined) delete process.env.TOJ_RETURN_OTP; else process.env.TOJ_RETURN_OTP = previous;
    }
  });

  test("Telegram pilot delivers security-change codes but keeps account deletion shut", async () => {
    const previous = process.env.TOJ_RETURN_OTP;
    process.env.TOJ_RETURN_OTP = "0";
    const phone = testPhone(198);
    const account = await makeAccount(phone, "Pilot");
    let sends = 0;
    const delivery = new TelegramOTPDelivery("synthetic", [phone], async () => {
      sends++;
      return Response.json({ ok: true, result: { request_id: "t", phone_number: phone, request_cost: 0 } });
    });
    try {
      await expect(startAccountDeletion(db, account.accountId, { deliveries: registryOf(delivery), deliveryChannel: delivery.channel }))
        .rejects.toMatchObject({ status: 503, code: "capability_unavailable" });
      expect(sends).toBe(0);
      // deleteAccount hard-deletes this phone's challenges, so it would reset the budget. That
      // path stays closed only because no account_deletion challenge can be minted here.
      expect(await db`SELECT id FROM otp_challenges WHERE purpose = 'account_deletion'`).toHaveLength(0);

      // Security-change codes must go through, or two-step enrollment — the only SIM-swap
      // mitigation against phone-number identity — is unreachable for every user.
      await startSecurityChange(db, account.accountId, { deliveries: registryOf(delivery), deliveryChannel: delivery.channel });
      expect(sends).toBe(1);
      expect(await db`SELECT id FROM otp_challenges WHERE purpose = 'security_change'`).toHaveLength(1);
    } finally {
      if (previous === undefined) delete process.env.TOJ_RETURN_OTP; else process.env.TOJ_RETURN_OTP = previous;
    }
  });

  test("Telegram-delivered codes keep the existing expiry and single-use guarantees", async () => {
    const previous = process.env.TOJ_RETURN_OTP;
    process.env.TOJ_RETURN_OTP = "0";
    const phone = testPhone(199);
    let delivered = "";
    const delivery = new TelegramOTPDelivery("synthetic", [phone], async (_url, init) => {
      delivered = JSON.parse(init.body as string).code;
      return Response.json({ ok: true, result: { request_id: "t", phone_number: phone, request_cost: 0 } });
    });
    try {
      await startVerification(db, phone, { deliveries: registryOf(delivery), deliveryChannel: "telegram" });
      expect(delivered).toMatch(/^\d{6}$/);
      expect((await checkVerification(db, phone, delivered, "ios", "Test", "Pilot")).accountId).toBeTruthy();
      await expect(checkVerification(db, phone, delivered, "ios", "Test", "Pilot")).rejects.toThrow();

      // Age the consumed challenge past the resend cooldown, then expire the replacement.
      await db`UPDATE otp_challenges SET created_at = now() - interval '1 hour'`;
      await startVerification(db, phone, { deliveries: registryOf(delivery), deliveryChannel: "telegram" });
      await db`UPDATE otp_challenges SET expires_at = now() - interval '1 second' WHERE consumed_at IS NULL`;
      await expect(checkVerification(db, phone, delivered, "ios", "Test", "Pilot")).rejects.toThrow();
    } finally {
      if (previous === undefined) delete process.env.TOJ_RETURN_OTP; else process.env.TOJ_RETURN_OTP = previous;
    }
  });

  test("provider selection is explicit: a stored Telegram token alone stays inert", () => {
    const keys = ["TOJ_OTP_PROVIDER", "TOJ_TELEGRAM_GATEWAY_TOKEN", "TOJ_TELEGRAM_TEST_ALLOWLIST",
      "TOJ_SMS_WEBHOOK_URL", "TOJ_SMS_WEBHOOK_TOKEN", "NODE_ENV", "TOJ_RETURN_OTP"] as const;
    const saved = Object.fromEntries(keys.map((key) => [key, process.env[key]]));
    try {
      for (const key of keys) delete process.env[key];
      process.env.TOJ_TELEGRAM_GATEWAY_TOKEN = "synthetic";
      process.env.TOJ_TELEGRAM_TEST_ALLOWLIST = testPhone(200);
      expect(otpDeliveryRegistryFromEnvironment().size).toBe(0);

      process.env.TOJ_OTP_PROVIDER = "sms";
      expect(() => otpDeliveryRegistryFromEnvironment()).toThrow();

      // A webhook alone registers only SMS; the stored Telegram token stays inert without its
      // explicit provider switch.
      process.env.TOJ_OTP_PROVIDER = "webhook";
      process.env.TOJ_SMS_WEBHOOK_URL = "https://example.test/hook";
      process.env.TOJ_SMS_WEBHOOK_TOKEN = "synthetic";
      expect([...otpDeliveryRegistryFromEnvironment().keys()]).toEqual(["sms"]);

      // Both configured is now the supported picker shape, not a startup error.
      process.env.TOJ_OTP_PROVIDER = "telegram";
      process.env.NODE_ENV = "staging";
      process.env.TOJ_RETURN_OTP = "0";
      expect([...otpDeliveryRegistryFromEnvironment().keys()].sort()).toEqual(["sms", "telegram"]);

      // And all three at once, which is the shape the picker exists for.
      process.env.TOJ_WHATSAPP_ENABLED = "1";
      process.env.TOJ_WHATSAPP_ACCESS_TOKEN = "synthetic-token-not-a-credential";
      process.env.TOJ_WHATSAPP_PHONE_NUMBER_ID = "123456789012345";
      process.env.TOJ_WHATSAPP_TEMPLATE = "toj_verification";
      process.env.TOJ_WHATSAPP_TEMPLATE_LANGUAGE = "ru";
      process.env.TOJ_WHATSAPP_TEST_ALLOWLIST = testPhone(204);
      expect([...otpDeliveryRegistryFromEnvironment().keys()].sort())
        .toEqual(["sms", "telegram", "whatsapp"]);
    } finally {
      for (const key of keys) {
        if (saved[key] === undefined) delete process.env[key]; else process.env[key] = saved[key]!;
      }
    }
  });

  test("the picker sends only on the chosen channel and never substitutes", async () => {
    const previous = process.env.TOJ_RETURN_OTP;
    process.env.TOJ_RETURN_OTP = "0";
    const phone = testPhone(201);
    const sent: string[] = [];
    const make = (channel: "telegram" | "sms"): OTPDelivery => ({
      channel, allows: () => true, async send() { sent.push(channel); },
    });
    const deliveries = new Map([["telegram", make("telegram")], ["sms", make("sms")]]);
    try {
      // Naming no channel is a 400, not a server-side choice. This is the property the old
      // single-delivery interlock was standing in for.
      await expect(startVerification(db, phone, { deliveries }))
        .rejects.toMatchObject({ status: 400, code: "channel_required" });
      expect(sent).toEqual([]);
      expect(await db`SELECT id FROM otp_challenges`).toHaveLength(0);

      // An unconfigured channel fails rather than falling back to a configured one.
      await expect(startVerification(db, phone, { deliveries, deliveryChannel: "whatsapp" }))
        .rejects.toMatchObject({ status: 400, code: "channel_required" });
      expect(sent).toEqual([]);

      await startVerification(db, phone, { deliveries, deliveryChannel: "sms" });
      expect(sent).toEqual(["sms"]);

      await db`UPDATE otp_challenges SET created_at = created_at - interval '31 seconds'`;
      await startVerification(db, phone, { deliveries, deliveryChannel: "telegram" });
      expect(sent).toEqual(["sms", "telegram"]);
    } finally {
      if (previous === undefined) delete process.env.TOJ_RETURN_OTP; else process.env.TOJ_RETURN_OTP = previous;
    }
  });

  test("advertised channels are global and carry no phone-specific information", async () => {
    const deliveries = new Map<"telegram" | "sms", OTPDelivery>([
      ["telegram", { channel: "telegram", allows: (p) => p === testPhone(202), async send() {} }],
      ["sms", { channel: "sms", async send() {} }],
    ]);
    const server = startCloudServer(0, db, null, deliveries as never, { backgroundWorkers: false });
    try {
      const body = await (await fetch(`http://127.0.0.1:${server.port}/v1/capabilities`)).json() as any;
      expect(body.capabilities).toContain("otp_channel_telegram");
      expect(body.capabilities).toContain("otp_channel_sms");
      expect(body.capabilities).not.toContain("otp_channel_whatsapp");

      // A per-number answer here would reveal allowlist membership on a public endpoint, undoing
      // the single generic 503 that startVerification uses to deny exactly that question.
      const allowed = await (await fetch(
        `http://127.0.0.1:${server.port}/v1/capabilities?phone=${encodeURIComponent(testPhone(202))}`)).json() as any;
      const outsider = await (await fetch(
        `http://127.0.0.1:${server.port}/v1/capabilities?phone=${encodeURIComponent(testPhone(203))}`)).json() as any;
      expect(allowed.capabilities).toEqual(outsider.capabilities);
      expect(JSON.stringify(body)).not.toContain(testPhone(202).slice(-6));
    } finally {
      await server.stop(true);
    }
  });

  test("two transports claiming the sms channel is a loud failure, not a silent winner", () => {
    const keys = ["TOJ_OTP_PROVIDER", "TOJ_TELEGRAM_GATEWAY_TOKEN", "TOJ_TELEGRAM_TEST_ALLOWLIST",
      "TOJ_SMS_WEBHOOK_URL", "TOJ_SMS_WEBHOOK_TOKEN", "NODE_ENV", "TOJ_RETURN_OTP",
      "TOJ_INFOBIP_ENABLED", "TOJ_INFOBIP_BASE_URL", "TOJ_INFOBIP_API_KEY",
      "TOJ_INFOBIP_SENDER", "TOJ_INFOBIP_TEST_ALLOWLIST", "TOJ_WHATSAPP_ENABLED",
      "TOJ_WHATSAPP_ACCESS_TOKEN", "TOJ_WHATSAPP_PHONE_NUMBER_ID", "TOJ_WHATSAPP_TEMPLATE",
      "TOJ_WHATSAPP_TEMPLATE_LANGUAGE", "TOJ_WHATSAPP_TEST_ALLOWLIST"] as const;
    const saved = Object.fromEntries(keys.map((key) => [key, process.env[key]]));
    try {
      for (const key of keys) delete process.env[key];
      process.env.NODE_ENV = "staging";
      process.env.TOJ_RETURN_OTP = "0";
      process.env.TOJ_INFOBIP_ENABLED = "1";
      process.env.TOJ_INFOBIP_BASE_URL = "https://55n4vx.api.infobip.com";
      process.env.TOJ_INFOBIP_API_KEY = "synthetic-key-not-a-credential";
      process.env.TOJ_INFOBIP_SENDER = "ServiceSMS";
      process.env.TOJ_INFOBIP_TEST_ALLOWLIST = testPhone(204);
      expect([...otpDeliveryRegistryFromEnvironment().keys()]).toEqual(["sms"]);

      // Infobip and the generic webhook are both "sms". Letting the later registration win would
      // silently decide which provider bills and sends — the exact class of bug this file exists to
      // keep out. It must refuse to start instead.
      process.env.TOJ_SMS_WEBHOOK_URL = "https://example.test/hook";
      process.env.TOJ_SMS_WEBHOOK_TOKEN = "synthetic";
      expect(() => otpDeliveryRegistryFromEnvironment()).toThrow(/either the SMS webhook or Infobip/);

      // Telegram alongside one SMS transport is the supported picker shape.
      delete process.env.TOJ_SMS_WEBHOOK_URL;
      delete process.env.TOJ_SMS_WEBHOOK_TOKEN;
      process.env.TOJ_OTP_PROVIDER = "telegram";
      process.env.TOJ_TELEGRAM_GATEWAY_TOKEN = "synthetic";
      process.env.TOJ_TELEGRAM_TEST_ALLOWLIST = testPhone(204);
      expect([...otpDeliveryRegistryFromEnvironment().keys()].sort()).toEqual(["sms", "telegram"]);
    } finally {
      for (const key of keys) {
        if (saved[key] === undefined) delete process.env[key]; else process.env[key] = saved[key]!;
      }
    }
  });

  test("a channel switch skips the cooldown, a repeat does not, and the windows ignore both", async () => {
    const previous = process.env.TOJ_RETURN_OTP;
    process.env.TOJ_RETURN_OTP = "0";
    const phone = testPhone(205);
    const sent: string[] = [];
    const make = (channel: "telegram" | "sms"): OTPDelivery => ({
      channel, allows: () => true, async send() { sent.push(channel); },
    });
    const deliveries = new Map([["telegram", make("telegram")], ["sms", make("sms")]]);
    try {
      await startVerification(db, phone, { deliveries, deliveryChannel: "telegram" });

      // Same channel inside the window still waits — the cooldown keeps doing its job.
      await expect(startVerification(db, phone, { deliveries, deliveryChannel: "telegram" }))
        .rejects.toMatchObject({ status: 429 });
      expect(sent).toEqual(["telegram"]);

      // "Didn't get it, send me a text" is the picker's expected flow, not an edge case.
      await startVerification(db, phone, { deliveries, deliveryChannel: "sms" });
      expect(sent).toEqual(["telegram", "sms"]);

      // And the exempted switch still counted: cycling channels must not raise the ceiling.
      // OTP_PHONE_WINDOW_LIMIT is 5 per 15 minutes, so three more attempts exhaust it whichever
      // channel they name.
      for (const channel of ["telegram", "sms", "telegram"]) {
        await db`UPDATE otp_challenges SET created_at = created_at - interval '31 seconds'`;
        await startVerification(db, phone, { deliveries, deliveryChannel: channel });
      }
      await db`UPDATE otp_challenges SET created_at = created_at - interval '31 seconds'`;
      await expect(startVerification(db, phone, { deliveries, deliveryChannel: "sms" }))
        .rejects.toMatchObject({ status: 429 });
      expect(await db`SELECT id FROM otp_challenges`).toHaveLength(5);
    } finally {
      if (previous === undefined) delete process.env.TOJ_RETURN_OTP; else process.env.TOJ_RETURN_OTP = previous;
    }
  });

  test("readiness reports OTP schema drift instead of claiming healthy", async () => {
    const server = startCloudServer(0, db, null, null, { backgroundWorkers: false });
    try {
      const base = `http://127.0.0.1:${server.port}`;
      const healthy = await (await fetch(`${base}/ready`)).json() as any;
      expect(healthy.otpSchema).toBe("ready");
      expect(healthy.otpSchemaMissing).toBeUndefined();

      // `bun run staging` does not migrate, so a deploy carrying a schema change boots clean and
      // fails on the first request touching the new column. That happened for real with #46's
      // `channel` column. Readiness must see it rather than reassure.
      await db`ALTER TABLE otp_challenges DROP COLUMN channel`;
      try {
        const drifted = await (await fetch(`${base}/ready`)).json() as any;
        expect(drifted.otpSchema).toBe("incomplete");
        expect(drifted.otpSchemaMissing).toContain("otp_challenges_channel");
      } finally {
        await db`ALTER TABLE otp_challenges ADD COLUMN IF NOT EXISTS channel TEXT`;
      }
    } finally {
      await server.stop(true);
    }
  });

  test("failed OTP delivery consumes the unusable challenge", async () => {
    let error: unknown;
    const originalConsoleError = console.error;
    const logged: string[] = [];
    console.error = (...parts: unknown[]) => logged.push(parts.map(String).join(" "));
    try {
      const failing = new FailingOTPDelivery();
      await startVerification(db, testPhone(123),
        { deliveries: registryOf(failing), deliveryChannel: failing.channel });
    } catch (value) {
      error = value;
    } finally {
      console.error = originalConsoleError;
    }
    expect(error).toBeInstanceOf(AuthError);
    expect((error as AuthError).status).toBe(503);
    expect((await db`SELECT consumed_at FROM otp_challenges`)[0].consumed_at).not.toBeNull();
    expect(logged.join(" ")).not.toContain("provider unavailable");
    expect(logged.join(" ")).toContain("Error");
  });

  test("APNs token registration encrypts at rest and transfers a reused token", async () => {
    const { alice: first } = await makePair();
    const token = "ab".repeat(32);
    await registerPushToken(db, first.deviceId, token, "sandbox");

    const stored = (await db`
      SELECT push_token_hash, push_token_ciphertext, push_token_nonce, push_token_key_id, push_environment
      FROM devices WHERE id = ${first.deviceId}`)[0];
    expect(stored.push_token_hash).not.toBeNull();
    expect(Buffer.from(stored.push_token_ciphertext).includes(Buffer.from(token))).toBe(false);
    expect((await openForScope(db, { kind: "account", accountId: first.accountId }, {
      keyId: stored.push_token_key_id,
      nonce: Buffer.from(stored.push_token_nonce),
      ciphertext: Buffer.from(stored.push_token_ciphertext),
    }, pushTokenAAD(first.deviceId))).toString("utf8")).toBe(token);

    const second = await addIOSDevice(first.accountId);
    await registerPushToken(db, second.deviceId, token.toUpperCase(), "sandbox");
    const rows = await db`
      SELECT id, push_token_hash FROM devices
      WHERE account_id = ${first.accountId} ORDER BY created_at`;
    expect(rows).toHaveLength(2);
    expect(rows.find((row) => row.id === first.deviceId)?.push_token_hash).toBeNull();
    expect(rows.find((row) => row.id === second.deviceId)?.push_token_hash).not.toBeNull();

    let rejected = false;
    try {
      await registerPushToken(db, second.deviceId, "not-a-device-token", "sandbox");
    } catch {
      rejected = true;
    }
    expect(rejected).toBe(true);
  });

  test("concurrent APNs registrations serialize token ownership without a server error", async () => {
    const { alice: first } = await makePair();
    const second = await addIOSDevice(first.accountId);
    const third = await addIOSDevice(first.accountId);
    const token = "cd".repeat(32);

    await Promise.all([
      registerPushToken(db, first.deviceId, token, "sandbox"),
      registerPushToken(db, second.deviceId, token, "sandbox"),
      registerPushToken(db, third.deviceId, token, "sandbox"),
    ]);

    const owners = await db`
      SELECT id FROM devices
      WHERE account_id = ${first.accountId} AND push_token_hash IS NOT NULL`;
    expect(owners).toHaveLength(1);
  });

  test("APNs payload is a generic sync hint with no message metadata", () => {
    const alert = buildAPNsPayload({ pts: 42, alert: true });
    const silent = buildAPNsPayload({ pts: 43, alert: false });
    expect(alert).toEqual({
      aps: {
        alert: { title: "Toj", body: "New message" },
        sound: "default",
        "content-available": 1,
      },
      toj: { pts: 42 },
    });
    expect(silent).toEqual({ aps: { "content-available": 1 }, toj: { pts: 43 } });
    const serialized = JSON.stringify([alert, silent]);
    expect(serialized).not.toContain("dialog");
    expect(serialized).not.toContain("sender");
    expect(serialized).not.toContain("phone");
  });

  test("message commit queues recipient alerts and silent sender-device catch-up", async () => {
    const { alice, bob, dialogId } = await makePair();
    const aliceSecond = await addIOSDevice(alice.accountId);
    await registerPushToken(db, alice.deviceId, "11".repeat(32), "sandbox");
    await registerPushToken(db, aliceSecond.deviceId, "22".repeat(32), "sandbox");
    await registerPushToken(db, bob.deviceId, "33".repeat(32), "sandbox");

    await sendMessage(db, {
      senderAccountId: alice.accountId,
      senderDeviceId: alice.deviceId,
      dialogId,
      clientMsgId: crypto.randomUUID(),
      body: "push me",
    });

    const deliveries = await db`
      SELECT account_id, device_id, alert, status FROM push_deliveries ORDER BY alert, device_id`;
    expect(deliveries).toHaveLength(2);
    expect(deliveries.find((row) => row.device_id === alice.deviceId)).toBeUndefined();
    expect(deliveries.find((row) => row.device_id === aliceSecond.deviceId)?.alert).toBe(false);
    expect(deliveries.find((row) => row.device_id === bob.deviceId)?.alert).toBe(true);
    expect(deliveries.every((row) => row.status === "pending")).toBe(true);
  });

  test("a revoked device cannot commit a message after sign-out", async () => {
    const { alice, dialogId } = await makePair();
    await registerPushToken(db, alice.deviceId, "77".repeat(32), "sandbox");
    await registerVoIPPushToken(db, alice.deviceId, "66".repeat(32), "sandbox");
    await revokeDevice(db, alice.accountId, alice.deviceId);
    const revoked = (await db`
      SELECT auth_token_key_id, push_token_hash, push_token_hash_key_id,
        voip_push_token_hash, voip_push_token_hash_key_id
      FROM devices WHERE id = ${alice.deviceId}`)[0];
    expect(revoked).toMatchObject({
      auth_token_key_id: "random-deleted",
      push_token_hash: null,
      push_token_hash_key_id: null,
      voip_push_token_hash: null,
      voip_push_token_hash_key_id: null,
    });
    await expect(resolveDevice(db, alice.token)).rejects.toBeInstanceOf(AuthError);
    await expect(sendMessage(db, {
      senderAccountId: alice.accountId, senderDeviceId: alice.deviceId,
      dialogId, clientMsgId: crypto.randomUUID(), body: "must not send",
    })).rejects.toThrow("sending device is no longer active");
    expect(await db`SELECT msg_id FROM messages WHERE dialog_id = ${dialogId}`).toHaveLength(0);
  });

  test("push worker marks success and removes an unregistered device token", async () => {
    const { alice, bob, dialogId } = await makePair();
    await registerPushToken(db, bob.deviceId, "44".repeat(32), "sandbox");

    await sendMessage(db, {
      senderAccountId: alice.accountId,
      senderDeviceId: alice.deviceId,
      dialogId,
      clientMsgId: crypto.randomUUID(),
      body: "first",
    });
    const success = new StubPushSender([{ status: 200, apnsId: "apns-ok" }]);
    expect(await processPushBatch(db, success)).toBe(1);
    expect(success.requests).toEqual([{
      token: "44".repeat(32), environment: "sandbox", pts: expect.any(Number), alert: true,
    }]);
    expect((await db`SELECT status, apns_id FROM push_deliveries`)[0]).toMatchObject({
      status: "sent", apns_id: "apns-ok",
    });

    await sendMessage(db, {
      senderAccountId: alice.accountId,
      senderDeviceId: alice.deviceId,
      dialogId,
      clientMsgId: crypto.randomUUID(),
      body: "second",
    });
    const invalid = new StubPushSender([{ status: 410, reason: "Unregistered" }]);
    expect(await processPushBatch(db, invalid)).toBe(1);
    expect((await db`SELECT push_token_hash FROM devices WHERE id = ${bob.deviceId}`)[0].push_token_hash).toBeNull();
    expect((await db`
      SELECT status, last_error FROM push_deliveries ORDER BY created_at DESC LIMIT 1`)[0]).toMatchObject({
      status: "dead", last_error: "Unregistered",
    });
  });

  test("stale APNs rejection cannot erase a concurrently rotated token or newer delivery", async () => {
    const { alice, bob, dialogId } = await makePair();
    const oldToken = "66".repeat(32);
    const newToken = "77".repeat(32);
    await registerPushToken(db, bob.deviceId, oldToken, "sandbox");

    await sendMessage(db, {
      senderAccountId: alice.accountId,
      senderDeviceId: alice.deviceId,
      dialogId,
      clientMsgId: crypto.randomUUID(),
      body: "old token delivery",
    });

    const sender = new PausedPushSender({ status: 410, reason: "Unregistered" });
    const processing = processPushBatch(db, sender, 1);
    await sender.started;
    let rotationCommitted = false;
    const rotation = (async () => {
      await registerPushToken(db, bob.deviceId, newToken, "sandbox");
      await sendMessage(db, {
        senderAccountId: alice.accountId,
        senderDeviceId: alice.deviceId,
        dialogId,
        clientMsgId: crypto.randomUUID(),
        body: "new token delivery",
      });
      rotationCommitted = true;
    })();

    await Bun.sleep(50);
    expect(rotationCommitted).toBe(false);
    sender.release();
    expect(await processing).toBe(1);
    await rotation;
    const device = (await db`
      SELECT push_token_ciphertext, push_token_nonce, push_token_key_id
      FROM devices WHERE id = ${bob.deviceId}`)[0];
    expect((await openForScope(db, { kind: "account", accountId: bob.accountId }, {
      keyId: device.push_token_key_id,
      nonce: Buffer.from(device.push_token_nonce),
      ciphertext: Buffer.from(device.push_token_ciphertext),
    }, pushTokenAAD(bob.deviceId))).toString("utf8")).toBe(newToken);

    const deliveries = await db`
      SELECT status, last_error FROM push_deliveries ORDER BY created_at`;
    expect(deliveries).toHaveLength(2);
    expect(deliveries[0]).toMatchObject({ status: "dead", last_error: "Unregistered" });
    expect(deliveries[1]).toMatchObject({ status: "pending", last_error: null });
  });

  test("account bans and ordinary APNs sends have a single transaction ordering", async () => {
    const { alice, bob, dialogId } = await makePair();
    await registerPushToken(db, bob.deviceId, "88".repeat(32), "sandbox");
    await sendMessage(db, {
      senderAccountId: alice.accountId,
      senderDeviceId: alice.deviceId,
      dialogId,
      clientMsgId: crypto.randomUUID(),
      body: "ban race",
    });

    const sender = new PausedPushSender({ status: 200, apnsId: "before-ban" });
    const processing = processPushBatch(db, sender, 1);
    await sender.started;
    let banCommitted = false;
    const ban = db.begin(async (tx) => {
      await tx`UPDATE accounts SET status = 'banned' WHERE id = ${bob.accountId}`;
      await tx`UPDATE devices SET revoked_at = now(), push_token_hash = NULL,
        push_token_hash_key_id = NULL, push_token_ciphertext = NULL, push_token_nonce = NULL,
        push_token_key_id = NULL, push_environment = NULL WHERE id = ${bob.deviceId}`;
      await tx`UPDATE push_deliveries SET status = 'dead', last_error = 'account banned',
        claimed_at = NULL WHERE account_id = ${bob.accountId} AND status IN ('pending','sending')`;
    }).then(() => { banCommitted = true; });

    await Bun.sleep(50);
    expect(banCommitted).toBe(false);
    sender.release();
    expect(await processing).toBe(1);
    await ban;
    expect(sender.requests).toHaveLength(1);
    expect((await db`SELECT status FROM accounts WHERE id = ${bob.accountId}`)[0].status)
      .toBe("banned");
    expect((await db`SELECT status, last_error FROM push_deliveries`)[0])
      .toMatchObject({ status: "sent", last_error: null });

    const carol = await makeAccount(testPhone(160), "Carol");
    const dana = await makeAccount(testPhone(161), "Dana");
    const secondDialog = await getOrCreateDirectDialog(db, carol.accountId, dana.accountId);
    await registerPushToken(db, dana.deviceId, "99".repeat(32), "sandbox");
    await sendMessage(db, {
      senderAccountId: carol.accountId,
      senderDeviceId: carol.deviceId,
      dialogId: secondDialog.dialogId,
      clientMsgId: crypto.randomUUID(),
      body: "ban commits first",
    });
    await db.begin(async (tx) => {
      await tx`UPDATE accounts SET status = 'banned' WHERE id = ${dana.accountId}`;
      await tx`UPDATE devices SET revoked_at = now(), push_token_hash = NULL,
        push_token_hash_key_id = NULL, push_token_ciphertext = NULL, push_token_nonce = NULL,
        push_token_key_id = NULL, push_environment = NULL WHERE id = ${dana.deviceId}`;
      await tx`UPDATE push_deliveries SET status = 'dead', last_error = 'account banned',
        claimed_at = NULL WHERE account_id = ${dana.accountId} AND status IN ('pending','sending')`;
    });
    const afterBan = new StubPushSender([{ status: 200 }]);
    expect(await processPushBatch(db, afterBan)).toBe(0);
    expect(afterBan.requests).toHaveLength(0);
  });

  test("push worker retries transient APNs failures without dropping the delivery", async () => {
    const { alice, bob, dialogId } = await makePair();
    await registerPushToken(db, bob.deviceId, "55".repeat(32), "production");
    await sendMessage(db, {
      senderAccountId: alice.accountId,
      senderDeviceId: alice.deviceId,
      dialogId,
      clientMsgId: crypto.randomUUID(),
      body: "retry",
    });

    const throttled = new StubPushSender([{ status: 429, reason: "TooManyRequests" }]);
    expect(await processPushBatch(db, throttled)).toBe(1);
    const row = (await db`SELECT status, attempts, available_at, last_error FROM push_deliveries`)[0];
    expect(row.status).toBe("pending");
    expect(Number(row.attempts)).toBe(1);
    expect(new Date(row.available_at).getTime()).toBeGreaterThan(Date.now());
    expect(row.last_error).toBe("TooManyRequests");

    await db`
      UPDATE push_deliveries
      SET status = 'sending', claimed_at = now() - interval '10 minutes', available_at = now()`;
    const recovered = new StubPushSender([{ status: 200 }]);
    expect(await processPushBatch(db, recovered)).toBe(1);
    expect((await db`SELECT status FROM push_deliveries`)[0].status).toBe("sent");
  });

  test("send retries are idempotent and do not burn message ids", async () => {
    const { alice, dialogId } = await makePair();
    const clientMsgId = crypto.randomUUID();

    const first = await sendMessage(db, {
      senderAccountId: alice.accountId,
      senderDeviceId: alice.deviceId,
      dialogId,
      clientMsgId,
      body: "retry once",
    });
    const second = await sendMessage(db, {
      senderAccountId: alice.accountId,
      senderDeviceId: alice.deviceId,
      dialogId,
      clientMsgId,
      body: "retry once",
    });

    expect(first.duplicate).toBe(false);
    expect(second.duplicate).toBe(true);
    expect(second.msgId).toBe(first.msgId);
    expect(second.senderPts).toBe(first.senderPts);
    expect(second.text).toBe("retry once");

    const counts = (await db`
      SELECT d.last_msg_id, count(m.*)::int AS message_count
      FROM dialogs d
      LEFT JOIN messages m ON m.dialog_id = d.id
      WHERE d.id = ${dialogId}
      GROUP BY d.last_msg_id`)[0];
    expect(Number(counts.last_msg_id)).toBe(1);
    expect(Number(counts.message_count)).toBe(1);
  });

  test("send idempotency survives 24 hours, old receipt cleanup, and canonical recovery", async () => {
    const { alice, dialogId } = await makePair();
    const clientMsgId = crypto.randomUUID();
    const first = await sendMessage(db, {
      senderAccountId: alice.accountId,
      senderDeviceId: alice.deviceId,
      dialogId,
      clientMsgId,
      body: "retry after a long offline period",
    });
    await db`
      UPDATE send_requests
      SET created_at = now() - interval '8 days'
      WHERE sender_account_id = ${alice.accountId} AND client_msg_id = ${clientMsgId}`;

    await cleanupExpiredData(db, 100);
    expect(await db`
      SELECT status FROM send_requests
      WHERE sender_account_id = ${alice.accountId} AND client_msg_id = ${clientMsgId}`)
      .toEqual([expect.objectContaining({ status: "completed" })]);

    // Reproduce a database upgraded from the old 24-hour receipt cleanup behavior.
    await db`
      DELETE FROM send_requests
      WHERE sender_account_id = ${alice.accountId} AND client_msg_id = ${clientMsgId}`;
    const recovered = await sendMessage(db, {
      senderAccountId: alice.accountId,
      senderDeviceId: alice.deviceId,
      dialogId,
      clientMsgId,
      body: "retry after a long offline period",
    });
    expect(recovered).toMatchObject({
      duplicate: true,
      msgId: first.msgId,
      senderPts: first.senderPts,
      text: "retry after a long offline period",
    });
    expect(Number((await db`
      SELECT count(*) AS count FROM messages
      WHERE sender_account_id = ${alice.accountId} AND client_msg_id = ${clientMsgId}`)[0].count))
      .toBe(1);
    expect((await db`
      SELECT status, msg_id, sender_pts FROM send_requests
      WHERE sender_account_id = ${alice.accountId} AND client_msg_id = ${clientMsgId}`)[0])
      .toMatchObject({
        status: "completed",
        msg_id: String(first.msgId),
        sender_pts: String(first.senderPts),
      });
  });

  test("send retries remain idempotent across blind-index key rotation", async () => {
    const { alice, dialogId } = await makePair();
    const clientMsgId = crypto.randomUUID();
    const request = {
      senderAccountId: alice.accountId,
      senderDeviceId: alice.deviceId,
      dialogId,
      clientMsgId,
      body: "retry across blind-index rotation",
    };
    const first = await sendMessage(db, request);
    expect((await db`
      SELECT fingerprint_key_id FROM send_requests
      WHERE sender_account_id = ${alice.accountId} AND client_msg_id = ${clientMsgId}`)[0]
      .fingerprint_key_id).toBe("legacy-v1");
    expect((await db`
      SELECT send_fingerprint_key_id FROM messages
      WHERE sender_account_id = ${alice.accountId} AND client_msg_id = ${clientMsgId}`)[0]
      .send_fingerprint_key_id).toBe("legacy-v1");

    process.env.TOJ_BLIND_INDEX_KEYRING = JSON.stringify({
      "requests-v2": Buffer.alloc(32, 0x72).toString("base64"),
    });
    process.env.TOJ_BLIND_INDEX_ACTIVE_KEY_ID = "requests-v2";

    const receiptRetry = await sendMessage(db, request);
    expect(receiptRetry).toMatchObject({ duplicate: true, msgId: first.msgId });
    expect((await db`
      SELECT fingerprint_key_id FROM send_requests
      WHERE sender_account_id = ${alice.accountId} AND client_msg_id = ${clientMsgId}`)[0]
      .fingerprint_key_id).toBe("requests-v2");

    await db`DELETE FROM send_requests
      WHERE sender_account_id = ${alice.accountId} AND client_msg_id = ${clientMsgId}`;
    const canonicalRetry = await sendMessage(db, request);
    expect(canonicalRetry).toMatchObject({ duplicate: true, msgId: first.msgId });
    expect((await db`
      SELECT fingerprint_key_id FROM send_requests
      WHERE sender_account_id = ${alice.accountId} AND client_msg_id = ${clientMsgId}`)[0]
      .fingerprint_key_id).toBe("requests-v2");
    expect((await db`
      SELECT send_fingerprint_key_id FROM messages
      WHERE sender_account_id = ${alice.accountId} AND client_msg_id = ${clientMsgId}`)[0]
      .send_fingerprint_key_id).toBe("requests-v2");
    expect(Number((await db`
      SELECT count(*) AS count FROM messages
      WHERE sender_account_id = ${alice.accountId} AND client_msg_id = ${clientMsgId}`)[0].count))
      .toBe(1);

    const newClientMsgId = crypto.randomUUID();
    await sendMessage(db, { ...request, clientMsgId: newClientMsgId, body: "new key" });
    expect((await db`
      SELECT send_fingerprint_key_id FROM messages
      WHERE sender_account_id = ${alice.accountId} AND client_msg_id = ${newClientMsgId}`)[0]
      .send_fingerprint_key_id).toBe("requests-v2");
  });

  test("replies survive difference, history, and bootstrap contracts", async () => {
    const { alice, bob, dialogId } = await makePair();
    const original = await sendMessage(db, {
      senderAccountId: bob.accountId,
      senderDeviceId: bob.deviceId,
      dialogId,
      clientMsgId: crypto.randomUUID(),
      body: "original",
    });
    const reply = await sendMessage(db, {
      senderAccountId: alice.accountId,
      senderDeviceId: alice.deviceId,
      dialogId,
      clientMsgId: crypto.randomUUID(),
      body: "reply",
      replyToMsgId: original.msgId,
    });

    const difference = await getDifference(db, bob.accountId, 0);
    const replyUpdate = difference.updates.find((update) => update.message?.msg_id === reply.msgId);
    expect(replyUpdate?.message?.reply_to_msg_id).toBe(original.msgId);

    const history = await getHistory(db, alice.accountId, dialogId);
    expect(history.messages.map((message) => [message.text, message.reply_to_msg_id])).toEqual([
      ["original", null],
      ["reply", original.msgId],
    ]);

    const bootstrap = await startBootstrap(db, bob.accountId);
    const page = await getBootstrapDialogsPage(db, bob.accountId, bootstrap.token, { previewMessages: 10 });
    expect(page.dialogs[0].messages.at(-1)?.reply_to_msg_id).toBe(original.msgId);
  });

  test("reactions are idempotent, replaceable, removable, and sync as full message state", async () => {
    const { alice, bob, dialogId } = await makePair();
    const sent = await sendMessage(db, {
      senderAccountId: alice.accountId,
      senderDeviceId: alice.deviceId,
      dialogId,
      clientMsgId: crypto.randomUUID(),
      body: "react to this",
    });
    const mutationId = crypto.randomUUID();
    const [first, retry] = await Promise.all([
      setReaction(db, {
        actorAccountId: bob.accountId,
        actorDeviceId: bob.deviceId,
        dialogId,
        msgId: sent.msgId,
        clientMutationId: mutationId,
        emoji: "❤️",
      }),
      setReaction(db, {
        actorAccountId: bob.accountId,
        actorDeviceId: bob.deviceId,
        dialogId,
        msgId: sent.msgId,
        clientMutationId: mutationId,
        emoji: "❤️",
      }),
    ]);
    expect([first.duplicate, retry.duplicate].sort()).toEqual([false, true]);
    expect(first.actorPts).toBe(retry.actorPts);
    expect(first.message.reactions).toEqual([{ account_id: bob.accountId, emoji: "❤️" }]);

    const replacement = await setReaction(db, {
      actorAccountId: bob.accountId,
      actorDeviceId: bob.deviceId,
      dialogId,
      msgId: sent.msgId,
      clientMutationId: crypto.randomUUID(),
      emoji: "👍",
    });
    expect(replacement.message.reactions).toEqual([{ account_id: bob.accountId, emoji: "👍" }]);

    const difference = await getDifference(db, alice.accountId, 0);
    const reactionUpdates = difference.updates.filter((update) => update.type === "reaction.updated");
    expect(reactionUpdates).toHaveLength(2);
    expect(reactionUpdates.at(-1)?.message?.reactions).toEqual([{ account_id: bob.accountId, emoji: "👍" }]);

    const history = await getHistory(db, alice.accountId, dialogId);
    expect(history.messages[0].reactions).toEqual([{ account_id: bob.accountId, emoji: "👍" }]);
    const bootstrap = await startBootstrap(db, bob.accountId);
    const page = await getBootstrapDialogsPage(db, bob.accountId, bootstrap.token, { previewMessages: 10 });
    expect(page.dialogs[0].messages[0].reactions).toEqual([{ account_id: bob.accountId, emoji: "👍" }]);

    const removed = await setReaction(db, {
      actorAccountId: bob.accountId,
      actorDeviceId: bob.deviceId,
      dialogId,
      msgId: sent.msgId,
      clientMutationId: crypto.randomUUID(),
      emoji: null,
    });
    expect(removed.message.reactions).toEqual([]);
    await revokeDevice(db, bob.accountId, bob.deviceId);
    await expect(setReaction(db, {
      actorAccountId: bob.accountId,
      actorDeviceId: bob.deviceId,
      dialogId,
      msgId: sent.msgId,
      clientMutationId: crypto.randomUUID(),
      emoji: "🔥",
    })).rejects.toMatchObject({ status: 401 });
  });

  test("reactions require membership and a visible message", async () => {
    const { alice, bob, dialogId } = await makePair();
    const charlie = await makeAccount(testPhone(777), "Charlie");
    const sent = await sendMessage(db, {
      senderAccountId: alice.accountId,
      senderDeviceId: alice.deviceId,
      dialogId,
      clientMsgId: crypto.randomUUID(),
      body: "private message",
    });
    await expect(setReaction(db, {
      actorAccountId: charlie.accountId,
      actorDeviceId: charlie.deviceId,
      dialogId,
      msgId: sent.msgId,
      clientMutationId: crypto.randomUUID(),
      emoji: "👀",
    })).rejects.toThrow("not a member");

    await deleteMessage(db, {
      actorAccountId: alice.accountId,
      actorDeviceId: alice.deviceId,
      dialogId,
      msgId: sent.msgId,
      clientMutationId: crypto.randomUUID(),
    });
    await expect(setReaction(db, {
      actorAccountId: bob.accountId,
      actorDeviceId: bob.deviceId,
      dialogId,
      msgId: sent.msgId,
      clientMutationId: crypto.randomUUID(),
      emoji: "👀",
    })).rejects.toThrow("message not found");
  });

  test("forwarding copies authorized visible text with immutable provenance and idempotency", async () => {
    const { alice, bob, dialogId: sourceDialogId } = await makePair();
    const charlie = await makeAccount(testPhone(778), "Charlie");
    const target = await getOrCreateDirectDialog(db, alice.accountId, charlie.accountId);
    const source = await sendMessage(db, {
      senderAccountId: bob.accountId,
      senderDeviceId: bob.deviceId,
      dialogId: sourceDialogId,
      clientMsgId: crypto.randomUUID(),
      body: "useful source text",
    });
    const clientMsgId = crypto.randomUUID();
    const forwarded = await sendMessage(db, {
      senderAccountId: alice.accountId,
      senderDeviceId: alice.deviceId,
      dialogId: target.dialogId,
      clientMsgId,
      forwardedFrom: { dialogId: sourceDialogId, msgId: source.msgId },
    });
    const retry = await sendMessage(db, {
      senderAccountId: alice.accountId,
      senderDeviceId: alice.deviceId,
      dialogId: target.dialogId,
      clientMsgId,
      forwardedFrom: { dialogId: sourceDialogId, msgId: source.msgId },
    });
    expect(forwarded.text).toBe("useful source text");
    expect(retry.duplicate).toBe(true);
    expect(retry.msgId).toBe(forwarded.msgId);

    await editMessage(db, {
      actorAccountId: bob.accountId,
      actorDeviceId: bob.deviceId,
      dialogId: sourceDialogId,
      msgId: source.msgId,
      clientMutationId: crypto.randomUUID(),
      expectedEditVersion: 0,
      body: "changed later",
    });
    const history = await getHistory(db, charlie.accountId, target.dialogId);
    expect(history.messages[0]).toMatchObject({ text: "useful source text", forwarded: true });
    expect(history.messages[0]).not.toHaveProperty("forwarded_from_account_id");
    expect(history.messages[0]).not.toHaveProperty("forwarded_from_dialog_id");
    const provenance = (await db`
      SELECT forwarded_from_account_id, forwarded_from_dialog_id, forwarded_from_msg_id
      FROM messages WHERE dialog_id = ${target.dialogId} AND msg_id = ${forwarded.msgId}`)[0];
    expect(provenance).toMatchObject({
      forwarded_from_account_id: bob.accountId,
      forwarded_from_dialog_id: sourceDialogId,
    });
    expect(Number(provenance.forwarded_from_msg_id)).toBe(source.msgId);
  });

  test("forwarding rejects inaccessible or deleted source messages", async () => {
    const { alice, bob, dialogId: sourceDialogId } = await makePair();
    const charlie = await makeAccount(testPhone(779), "Charlie");
    const target = await getOrCreateDirectDialog(db, charlie.accountId, bob.accountId);
    const source = await sendMessage(db, {
      senderAccountId: alice.accountId,
      senderDeviceId: alice.deviceId,
      dialogId: sourceDialogId,
      clientMsgId: crypto.randomUUID(),
      body: "not Charlie's message",
    });
    await expect(sendMessage(db, {
      senderAccountId: charlie.accountId,
      senderDeviceId: charlie.deviceId,
      dialogId: target.dialogId,
      clientMsgId: crypto.randomUUID(),
      forwardedFrom: { dialogId: sourceDialogId, msgId: source.msgId },
    })).rejects.toThrow("not a member");

    await deleteMessage(db, {
      actorAccountId: alice.accountId,
      actorDeviceId: alice.deviceId,
      dialogId: sourceDialogId,
      msgId: source.msgId,
      clientMutationId: crypto.randomUUID(),
    });
    await expect(sendMessage(db, {
      senderAccountId: bob.accountId,
      senderDeviceId: bob.deviceId,
      dialogId: target.dialogId,
      clientMsgId: crypto.randomUUID(),
      forwardedFrom: { dialogId: sourceDialogId, msgId: source.msgId },
    })).rejects.toThrow("forward source not found");
  });

  test("edits and deletions are idempotent tombstones that sync to every member", async () => {
    const { alice, bob, dialogId } = await makePair();
    const sent = await sendMessage(db, {
      senderAccountId: alice.accountId,
      senderDeviceId: alice.deviceId,
      dialogId,
      clientMsgId: crypto.randomUUID(),
      body: "sensitive original",
    });
    const mutationId = crypto.randomUUID();
    const [firstEdit, retryEdit] = await Promise.all([
      editMessage(db, {
        actorAccountId: alice.accountId,
        actorDeviceId: alice.deviceId,
        dialogId,
        msgId: sent.msgId,
        clientMutationId: mutationId,
        expectedEditVersion: 0,
        body: "corrected",
      }),
      editMessage(db, {
        actorAccountId: alice.accountId,
        actorDeviceId: alice.deviceId,
        dialogId,
        msgId: sent.msgId,
        clientMutationId: mutationId,
        expectedEditVersion: 0,
        body: "corrected",
      }),
    ]);
    expect(firstEdit.actorPts).toBe(retryEdit.actorPts);
    expect([firstEdit.duplicate, retryEdit.duplicate].sort()).toEqual([false, true]);
    expect(firstEdit.message.text).toBe("corrected");
    expect(firstEdit.message.edit_version).toBe(1);

    const deletion = await deleteMessage(db, {
      actorAccountId: alice.accountId,
      actorDeviceId: alice.deviceId,
      dialogId,
      msgId: sent.msgId,
      clientMutationId: crypto.randomUUID(),
    });
    expect(deletion.message.state).toBe("deleted_for_all");
    expect(deletion.message.text).toBe("");

    const bobDifference = await getDifference(db, bob.accountId, 0);
    expect(bobDifference.updates.map((update) => update.type)).toContain("message.edited");
    const tombstone = bobDifference.updates.find((update) => update.type === "message.deleted");
    expect(tombstone?.message?.state).toBe("deleted_for_all");
    expect(tombstone?.message?.text).toBe("");

    const row = (await db`
      SELECT body_key_id, body_nonce, body_ciphertext, sender_account_id
      FROM messages WHERE dialog_id = ${dialogId} AND msg_id = ${sent.msgId}`)[0];
    const liveBody = (await openForScope(db, { kind: "account", accountId: row.sender_account_id }, {
      keyId: row.body_key_id,
      nonce: Buffer.from(row.body_nonce),
      ciphertext: Buffer.from(row.body_ciphertext),
    }, bodyAAD(dialogId, sent.msgId, row.sender_account_id))).toString("utf8");
    expect(liveBody).toBe("");
  });

  test("only a message sender can edit or delete and stale edits are rejected", async () => {
    const { alice, bob, dialogId } = await makePair();
    const sent = await sendMessage(db, {
      senderAccountId: alice.accountId,
      senderDeviceId: alice.deviceId,
      dialogId,
      clientMsgId: crypto.randomUUID(),
      body: "owned by Alice",
    });

    await expect(editMessage(db, {
      actorAccountId: bob.accountId,
      actorDeviceId: bob.deviceId,
      dialogId,
      msgId: sent.msgId,
      clientMutationId: crypto.randomUUID(),
      expectedEditVersion: 0,
      body: "hijacked",
    })).rejects.toThrow("only the sender");

    await editMessage(db, {
      actorAccountId: alice.accountId,
      actorDeviceId: alice.deviceId,
      dialogId,
      msgId: sent.msgId,
      clientMutationId: crypto.randomUUID(),
      expectedEditVersion: 0,
      body: "version one",
    });
    await expect(editMessage(db, {
      actorAccountId: alice.accountId,
      actorDeviceId: alice.deviceId,
      dialogId,
      msgId: sent.msgId,
      clientMutationId: crypto.randomUUID(),
      expectedEditVersion: 0,
      body: "stale overwrite",
    })).rejects.toThrow("another device");
    await expect(deleteMessage(db, {
      actorAccountId: bob.accountId,
      actorDeviceId: bob.deviceId,
      dialogId,
      msgId: sent.msgId,
      clientMutationId: crypto.randomUUID(),
    })).rejects.toThrow("only the sender");
  });

  test("get_difference catches up in pts order and respects byte slicing", async () => {
    const { alice, bob, dialogId } = await makePair();
    for (let i = 0; i < 4; i++) {
      await sendMessage(db, {
        senderAccountId: alice.accountId,
        senderDeviceId: alice.deviceId,
        dialogId,
        clientMsgId: crypto.randomUUID(),
        body: `message ${i} ${"x".repeat(600)}`,
      });
    }

    const firstSlice = await getDifference(db, bob.accountId, 1, { maxEvents: 20, maxBytes: 900 });
    expect(firstSlice.kind).toBe("difference_slice");
    expect(firstSlice.updates.length).toBeGreaterThanOrEqual(1);

    const rest = await getDifference(db, bob.accountId, firstSlice.state.pts, { maxEvents: 20, maxBytes: 4096 });
    expect(rest.kind).toBe("difference");
    expect(rest.state.pts).toBeGreaterThan(firstSlice.state.pts);
    expect(firstSlice.updates[0].pts).toBeLessThan(rest.updates.at(-1).pts);
  });

  test("a 200-event difference page uses at most four SQL calls", async () => {
    const { alice, bob, dialogId } = await makePair();
    for (let i = 0; i < 200; i++) {
      await sendMessage(db, {
        senderAccountId: alice.accountId,
        senderDeviceId: alice.deviceId,
        dialogId,
        clientMsgId: crypto.randomUUID(),
        body: `bulk message ${i}`,
      });
    }

    let calls = 0;
    const countedDB = new Proxy(db, {
      apply(target, _thisArg, argumentsList) {
        calls += 1;
        return Reflect.apply(target, target, argumentsList);
      },
    });
    const difference = await getDifference(
      countedDB,
      bob.accountId,
      1,
      { maxEvents: 200, maxBytes: 512 * 1024 },
    );

    expect(difference.updates).toHaveLength(200);
    expect(calls).toBeLessThanOrEqual(4);
  });

  test("pruned event floor returns difference_too_long instead of a fake partial catch-up", async () => {
    const { alice, bob, dialogId } = await makePair();
    await sendMessage(db, {
      senderAccountId: alice.accountId,
      senderDeviceId: alice.deviceId,
      dialogId,
      clientMsgId: crypto.randomUUID(),
      body: "old event",
    });
    await db`UPDATE account_sync_states SET pruned_through_pts = 2 WHERE account_id = ${bob.accountId}`;

    const diff = await getDifference(db, bob.accountId, 1);
    expect(diff.kind).toBe("difference_too_long");
  });

  test("dialog preference patches are account-only, field-safe, and exactly idempotent", async () => {
    const { alice, bob, dialogId } = await makePair();
    const outsider = await makeAccount(testPhone(3_901), "Outsider");
    const aliceSecond = await addIOSDevice(alice.accountId);
    await registerPushToken(db, aliceSecond.deviceId, "91".repeat(32), "sandbox");
    const aliceBefore = Number((await db`
      SELECT pts FROM account_sync_states WHERE account_id = ${alice.accountId}`)[0].pts);
    const bobBefore = Number((await db`
      SELECT pts FROM account_sync_states WHERE account_id = ${bob.accountId}`)[0].pts);
    const pinMutationId = crypto.randomUUID();
    const muteMutationId = crypto.randomUUID();

    const [pinResult, muteResult] = await Promise.all([
      updateDialogPreferences(db, {
        accountId: alice.accountId,
        deviceId: alice.deviceId,
        dialogId,
        clientMutationId: pinMutationId,
        patch: { pinned: true, archived: true },
      }),
      updateDialogPreferences(db, {
        accountId: alice.accountId,
        deviceId: aliceSecond.deviceId,
        dialogId,
        clientMutationId: muteMutationId,
        patch: { muted: true },
      }),
    ]);

    expect([pinResult.pts, muteResult.pts].sort((a, b) => a - b))
      .toEqual([aliceBefore + 1, aliceBefore + 2]);
    const canonical = (await db`
      SELECT is_pinned, pinned_at, is_muted, is_archived
      FROM dialog_preferences
      WHERE dialog_id = ${dialogId} AND account_id = ${alice.accountId}`)[0];
    expect(canonical).toMatchObject({
      is_pinned: true,
      is_muted: true,
      is_archived: true,
    });
    expect(canonical.pinned_at).not.toBeNull();
    expect((await db`
      SELECT notification_mode FROM dialog_members
      WHERE dialog_id = ${dialogId} AND account_id = ${alice.accountId}`)[0].notification_mode)
      .toBe("muted");
    expect(Number((await db`
      SELECT pts FROM account_sync_states WHERE account_id = ${bob.accountId}`)[0].pts))
      .toBe(bobBefore);

    const difference = await getDifference(db, alice.accountId, aliceBefore);
    if (difference.kind === "difference_too_long") throw new Error("unexpected rebuild");
    expect(difference.updates.map((update) => update.pts))
      .toEqual([aliceBefore + 1, aliceBefore + 2]);
    expect(difference.updates.every((update) => update.type === "dialog.preferences_updated"))
      .toBe(true);
    expect(difference.updates.map((update) => update.changed_fields).sort())
      .toEqual([["archived", "pinned"], ["muted"]].sort());
    expect(difference.updates.at(-1)?.preferences).toMatchObject({
      dialogId,
      pinned: true,
      muted: true,
      archived: true,
    });

    const retry = await updateDialogPreferences(db, {
      accountId: alice.accountId,
      deviceId: alice.deviceId,
      dialogId,
      clientMutationId: pinMutationId,
      patch: { pinned: true, archived: true },
    });
    expect(retry.duplicate).toBe(true);
    expect(retry.pts).toBe(pinResult.pts);
    expect(Number((await db`
      SELECT pts FROM account_sync_states WHERE account_id = ${alice.accountId}`)[0].pts))
      .toBe(aliceBefore + 2);
    await expect(updateDialogPreferences(db, {
      accountId: alice.accountId,
      deviceId: alice.deviceId,
      dialogId,
      clientMutationId: pinMutationId,
      patch: { pinned: false },
    })).rejects.toMatchObject({ code: "idempotency_conflict", status: 409 });

    const deliveries = await db`
      SELECT device_id, alert
      FROM push_deliveries
      WHERE account_id = ${alice.accountId}
      ORDER BY pts, device_id`;
    expect(deliveries.length).toBeGreaterThanOrEqual(1);
    expect(deliveries.every((delivery) => delivery.alert === false)).toBe(true);
    expect(deliveries.every((delivery) =>
      delivery.device_id === alice.deviceId || delivery.device_id === aliceSecond.deviceId
    )).toBe(true);

    await expect(updateDialogPreferences(db, {
      accountId: outsider.accountId,
      deviceId: outsider.deviceId,
      dialogId,
      clientMutationId: crypto.randomUUID(),
      patch: { pinned: true },
    })).rejects.toMatchObject({ status: 403 });
    await expect(updateDialogPreferences(db, {
      accountId: alice.accountId,
      deviceId: alice.deviceId,
      dialogId,
      clientMutationId: crypto.randomUUID(),
      patch: { muted: "true" },
    })).rejects.toMatchObject({ code: "invalid_request", status: 400 });
    await expect(updateDialogPreferences(db, {
      accountId: alice.accountId,
      deviceId: alice.deviceId,
      dialogId,
      clientMutationId: crypto.randomUUID(),
      patch: { pinned: true, keepArchived: true },
    })).rejects.toMatchObject({ code: "invalid_request", status: 400 });

    const firstPinnedAt = canonical.pinned_at.toISOString();
    const beforeRedundant = (await db`
      SELECT
        (SELECT pts FROM account_sync_states WHERE account_id = ${alice.accountId}) AS pts,
        (SELECT count(*) FROM account_events
         WHERE account_id = ${alice.accountId}) AS event_count,
        (SELECT count(*) FROM push_deliveries
         WHERE account_id = ${alice.accountId}) AS push_count`)[0];
    const redundantPin = await updateDialogPreferences(db, {
      accountId: alice.accountId,
      deviceId: alice.deviceId,
      dialogId,
      clientMutationId: crypto.randomUUID(),
      patch: { pinned: true },
    });
    expect(redundantPin.preferences.pinnedAt).toBe(firstPinnedAt);
    expect(redundantPin.changedFields).toEqual([]);
    expect(redundantPin.pushes).toEqual([]);
    const afterRedundant = (await db`
      SELECT
        (SELECT pts FROM account_sync_states WHERE account_id = ${alice.accountId}) AS pts,
        (SELECT count(*) FROM account_events
         WHERE account_id = ${alice.accountId}) AS event_count,
        (SELECT count(*) FROM push_deliveries
         WHERE account_id = ${alice.accountId}) AS push_count`)[0];
    expect(afterRedundant).toEqual(beforeRedundant);
    const unpinned = await updateDialogPreferences(db, {
      accountId: alice.accountId,
      deviceId: alice.deviceId,
      dialogId,
      clientMutationId: crypto.randomUUID(),
      patch: { pinned: false },
    });
    expect(unpinned.preferences.pinnedAt).toBeNull();
    const repinned = await updateDialogPreferences(db, {
      accountId: alice.accountId,
      deviceId: alice.deviceId,
      dialogId,
      clientMutationId: crypto.randomUUID(),
      patch: { pinned: true },
    });
    expect(repinned.preferences.pinnedAt).not.toBe(firstPinnedAt);

    const secondPeer = await makeAccount(testPhone(3_902), "Second pin");
    const secondDialog = await getOrCreateDirectDialog(
      db,
      alice.accountId,
      secondPeer.accountId,
    );
    await updateDialogPreferences(db, {
      accountId: alice.accountId,
      deviceId: alice.deviceId,
      dialogId,
      clientMutationId: crypto.randomUUID(),
      patch: { pinned: false },
    });
    const concurrentPins = await Promise.all([
      updateDialogPreferences(db, {
        accountId: alice.accountId,
        deviceId: alice.deviceId,
        dialogId,
        clientMutationId: crypto.randomUUID(),
        patch: { pinned: true },
      }),
      updateDialogPreferences(db, {
        accountId: alice.accountId,
        deviceId: aliceSecond.deviceId,
        dialogId: secondDialog.dialogId,
        clientMutationId: crypto.randomUUID(),
        patch: { pinned: true },
      }),
    ]);
    const pinsByCommitOrder = concurrentPins.sort((left, right) => left.pts - right.pts);
    expect(pinsByCommitOrder[1].preferences.pinnedAt! >
      pinsByCommitOrder[0].preferences.pinnedAt!).toBe(true);
  });

  test("dialog preference mutation budgets are persisted and return Retry-After", async () => {
    const { alice, dialogId } = await makePair();
    await db`
      INSERT INTO dialog_preference_action_budgets (
        account_id, bucket_started, mutation_count
      ) VALUES (
        ${alice.accountId}, date_trunc('hour', now()), 240
      )
      ON CONFLICT (account_id, bucket_started) DO UPDATE
      SET mutation_count = 240, updated_at = now()`;
    const before = (await db`
      SELECT pts FROM account_sync_states WHERE account_id = ${alice.accountId}`)[0].pts;

    await expect(updateDialogPreferences(db, {
      accountId: alice.accountId,
      deviceId: alice.deviceId,
      dialogId,
      clientMutationId: crypto.randomUUID(),
      patch: { pinned: true },
    })).rejects.toMatchObject({
      code: "rate_limited",
      status: 429,
      retryAfter: 3600,
    });
    expect((await db`
      SELECT pts FROM account_sync_states WHERE account_id = ${alice.accountId}`)[0].pts)
      .toBe(before);
  });

  test("lost preference responses remain idempotent after retention and a newer device change", async () => {
    const { alice, dialogId } = await makePair();
    const secondDevice = await addIOSDevice(alice.accountId);
    const firstMutationId = crypto.randomUUID();
    const first = await updateDialogPreferences(db, {
      accountId: alice.accountId,
      deviceId: alice.deviceId,
      dialogId,
      clientMutationId: firstMutationId,
      patch: { muted: true },
    });
    const second = await updateDialogPreferences(db, {
      accountId: alice.accountId,
      deviceId: secondDevice.deviceId,
      dialogId,
      clientMutationId: crypto.randomUUID(),
      patch: { muted: false },
    });
    await db`
      UPDATE dialog_preference_requests
      SET created_at = now() - interval '90 days'
      WHERE account_id = ${alice.accountId}
        AND client_mutation_id = ${firstMutationId}`;
    await cleanupExpiredData(db, 1_000);
    expect(await db`
      SELECT client_mutation_id
      FROM dialog_preference_requests
      WHERE account_id = ${alice.accountId}
        AND client_mutation_id = ${firstMutationId}`).toHaveLength(1);

    const ptsBeforeRetry = Number((await db`
      SELECT pts FROM account_sync_states WHERE account_id = ${alice.accountId}`)[0].pts);
    const retry = await updateDialogPreferences(db, {
      accountId: alice.accountId,
      deviceId: alice.deviceId,
      dialogId,
      clientMutationId: firstMutationId,
      patch: { muted: true },
    });
    expect(retry.duplicate).toBe(true);
    expect(retry.pts).toBe(first.pts);
    expect(second.pts).toBeGreaterThan(first.pts);
    expect(Number((await db`
      SELECT pts FROM account_sync_states WHERE account_id = ${alice.accountId}`)[0].pts))
      .toBe(ptsBeforeRetry);
    expect((await db`
      SELECT is_muted
      FROM dialog_preferences
      WHERE account_id = ${alice.accountId} AND dialog_id = ${dialogId}`)[0].is_muted)
      .toBe(false);
  });

  test("muted messages stay silent and only unmuted incoming messages auto-unarchive", async () => {
    const { alice, bob, dialogId } = await makePair();
    await registerPushToken(db, bob.deviceId, "92".repeat(32), "sandbox");
    await updateDialogPreferences(db, {
      accountId: bob.accountId,
      deviceId: bob.deviceId,
      dialogId,
      clientMutationId: crypto.randomUUID(),
      patch: { muted: true, archived: true },
    });
    await db`DELETE FROM push_deliveries`;
    const mutedSince = Number((await db`
      SELECT pts FROM account_sync_states WHERE account_id = ${bob.accountId}`)[0].pts);

    await sendMessage(db, {
      senderAccountId: alice.accountId,
      senderDeviceId: alice.deviceId,
      dialogId,
      clientMsgId: crypto.randomUUID(),
      body: "silent but synchronized",
    });
    expect((await db`
      SELECT is_archived FROM dialog_preferences
      WHERE dialog_id = ${dialogId} AND account_id = ${bob.accountId}`)[0].is_archived)
      .toBe(true);
    expect((await db`
      SELECT alert FROM push_deliveries
      WHERE account_id = ${bob.accountId}`)[0].alert).toBe(false);
    const mutedDifference = await getDifference(db, bob.accountId, mutedSince);
    if (mutedDifference.kind === "difference_too_long") throw new Error("unexpected rebuild");
    expect(mutedDifference.updates).toHaveLength(1);
    expect(mutedDifference.updates[0].message.text).toBe("silent but synchronized");
    expect(mutedDifference.updates[0].preferences).toBeUndefined();

    await updateDialogPreferences(db, {
      accountId: bob.accountId,
      deviceId: bob.deviceId,
      dialogId,
      clientMutationId: crypto.randomUUID(),
      patch: { muted: false },
    });
    await db`DELETE FROM push_deliveries`;
    const unmutedSince = Number((await db`
      SELECT pts FROM account_sync_states WHERE account_id = ${bob.accountId}`)[0].pts);
    await sendMessage(db, {
      senderAccountId: alice.accountId,
      senderDeviceId: alice.deviceId,
      dialogId,
      clientMsgId: crypto.randomUUID(),
      body: "returns to chats",
    });

    expect((await db`
      SELECT is_archived FROM dialog_preferences
      WHERE dialog_id = ${dialogId} AND account_id = ${bob.accountId}`)[0].is_archived)
      .toBe(false);
    expect((await db`
      SELECT alert FROM push_deliveries
      WHERE account_id = ${bob.accountId}`)[0].alert).toBe(true);
    const unmutedDifference = await getDifference(db, bob.accountId, unmutedSince);
    if (unmutedDifference.kind === "difference_too_long") throw new Error("unexpected rebuild");
    expect(unmutedDifference.updates).toHaveLength(1);
    expect(unmutedDifference.updates[0]).toMatchObject({
      type: "message.new",
      preferences: {
        dialogId,
        muted: false,
        archived: false,
      },
    });
  });

  test("the behavior switch applies to every fanout event path", async () => {
    const { alice, bob, dialogId } = await makePair();
    await registerPushToken(db, bob.deviceId, "9f".repeat(32), "sandbox");
    await db`
      UPDATE dialog_preferences
      SET is_muted = TRUE
      WHERE dialog_id = ${dialogId} AND account_id = ${bob.accountId}`;
    expect((await db`
      SELECT notification_mode
      FROM dialog_members
      WHERE dialog_id = ${dialogId} AND account_id = ${bob.accountId}`)[0].notification_mode)
      .toBe("all");

    const previous = process.env.TOJ_DIALOG_PREFERENCES_BEHAVIOR_ENABLED;
    process.env.TOJ_DIALOG_PREFERENCES_BEHAVIOR_ENABLED = "0";
    try {
      for (const type of [
        "dialog.profile_updated",
        "member.added",
        "message.edited",
        "reaction.updated",
        "read.updated",
      ]) {
        await fanoutDialogEvent(db, {
          dialogId,
          type,
          actorAccountId: alice.accountId,
          sourceDeviceId: alice.deviceId,
          recipientAccountIds: [bob.accountId],
        });
      }
      const deliveries = await db`
        SELECT alert
        FROM push_deliveries
        WHERE account_id = ${bob.accountId}
        ORDER BY pts`;
      expect(deliveries).toHaveLength(5);
      expect(deliveries.every((delivery: any) => delivery.alert === true)).toBe(true);
    } finally {
      if (previous === undefined) {
        delete process.env.TOJ_DIALOG_PREFERENCES_BEHAVIOR_ENABLED;
      } else {
        process.env.TOJ_DIALOG_PREFERENCES_BEHAVIOR_ENABLED = previous;
      }
    }
  });

  test("mute and incoming-message races follow commit order without losing archive intent", async () => {
    const { alice, bob, dialogId } = await makePair();
    await registerPushToken(db, bob.deviceId, "93".repeat(32), "sandbox");
    await updateDialogPreferences(db, {
      accountId: bob.accountId,
      deviceId: bob.deviceId,
      dialogId,
      clientMutationId: crypto.randomUUID(),
      patch: { muted: true, archived: true },
    });
    await db`DELETE FROM push_deliveries`;
    const since = Number((await db`
      SELECT pts FROM account_sync_states WHERE account_id = ${bob.accountId}`)[0].pts);

    const [messageResult, preferenceResult] = await Promise.all([
      sendMessage(db, {
        senderAccountId: alice.accountId,
        senderDeviceId: alice.deviceId,
        dialogId,
        clientMsgId: crypto.randomUUID(),
        body: "racing mute",
      }),
      updateDialogPreferences(db, {
        accountId: bob.accountId,
        deviceId: bob.deviceId,
        dialogId,
        clientMutationId: crypto.randomUUID(),
        patch: { muted: false },
      }),
    ]);
    const messagePts = messageResult.pushes.find(
      (push) => push.accountId === bob.accountId,
    )!.pts;
    const final = (await db`
      SELECT is_muted, is_archived
      FROM dialog_preferences
      WHERE dialog_id = ${dialogId} AND account_id = ${bob.accountId}`)[0];
    expect(final.is_muted).toBe(false);

    const difference = await getDifference(db, bob.accountId, since);
    if (difference.kind === "difference_too_long") throw new Error("unexpected rebuild");
    expect(difference.updates).toHaveLength(2);
    expect(difference.updates.map((update) => update.pts))
      .toEqual([since + 1, since + 2]);
    const messageUpdate = difference.updates.find((update) => update.type === "message.new")!;
    const messageDelivery = (await db`
      SELECT alert FROM push_deliveries
      WHERE account_id = ${bob.accountId} AND pts = ${messagePts}`)[0];

    if (preferenceResult.pts < messagePts) {
      expect(final.is_archived).toBe(false);
      expect(messageUpdate.preferences).toMatchObject({ muted: false, archived: false });
      expect(messageDelivery.alert).toBe(true);
    } else {
      expect(final.is_archived).toBe(true);
      expect(messageUpdate.preferences).toBeUndefined();
      expect(messageDelivery.alert).toBe(false);
    }
  });

  test("bootstrap captures preference values at its pts and replays later mutations", async () => {
    const { bob, dialogId } = await makePair();
    await updateDialogPreferences(db, {
      accountId: bob.accountId,
      deviceId: bob.deviceId,
      dialogId,
      clientMutationId: crypto.randomUUID(),
      patch: { pinned: true, archived: true },
    });
    const bootstrap = await startBootstrap(db, bob.accountId);
    await updateDialogPreferences(db, {
      accountId: bob.accountId,
      deviceId: bob.deviceId,
      dialogId,
      clientMutationId: crypto.randomUUID(),
      patch: { muted: true, archived: false },
    });

    const page = await getBootstrapDialogsPage(db, bob.accountId, bootstrap.token);
    expect(page.dialogs[0].preferences).toMatchObject({
      dialogId,
      pinned: true,
      muted: false,
      archived: true,
    });
    const difference = await getDifference(db, bob.accountId, bootstrap.state.pts);
    if (difference.kind === "difference_too_long") throw new Error("unexpected rebuild");
    expect(difference.updates).toHaveLength(1);
    expect(difference.updates[0]).toMatchObject({
      type: "dialog.preferences_updated",
      preferences: {
        dialogId,
        pinned: true,
        muted: true,
        archived: false,
      },
    });
  });

  test("bootstrap snapshot does not duplicate or swallow messages sent during onboarding", async () => {
    const { alice, bob, dialogId } = await makePair();
    const aliceCreation = await getDifference(db, alice.accountId, 0);
    const bobCreation = await getDifference(db, bob.accountId, 0);
    expect(aliceCreation.updates.find((u) => u.type === "dialog.created")?.dialog_title).toBe("Bob");
    expect(bobCreation.updates.find((u) => u.type === "dialog.created")?.dialog_title).toBe("Alice");
    await sendMessage(db, {
      senderAccountId: alice.accountId,
      senderDeviceId: alice.deviceId,
      dialogId,
      clientMsgId: crypto.randomUUID(),
      body: "before snapshot",
    });

    const bootstrap = await startBootstrap(db, bob.accountId);

    await sendMessage(db, {
      senderAccountId: alice.accountId,
      senderDeviceId: alice.deviceId,
      dialogId,
      clientMsgId: crypto.randomUUID(),
      body: "after snapshot",
    });

    const page = await getBootstrapDialogsPage(db, bob.accountId, bootstrap.token, { previewMessages: 10 });
    expect(page.state.pts).toBe(bootstrap.state.pts);
    expect(page.dialogs).toHaveLength(1);
    expect(page.dialogs[0].title).toBe("Alice");
    expect(page.dialogs[0].messages.map((m) => m.text)).toEqual(["before snapshot"]);
    expect(page.dialogs[0].unread_count).toBe(1);

    const diff = await getDifference(db, bob.accountId, bootstrap.state.pts);
    expect(diff.kind).toBe("difference");
    expect(diff.updates.map((u) => u.message?.text).filter(Boolean)).toEqual(["after snapshot"]);
  });

  test("history pages load locally decryptable message bodies", async () => {
    const { alice, bob, dialogId } = await makePair();
    await sendMessage(db, {
      senderAccountId: alice.accountId,
      senderDeviceId: alice.deviceId,
      dialogId,
      clientMsgId: crypto.randomUUID(),
      body: "one",
    });
    await sendMessage(db, {
      senderAccountId: bob.accountId,
      senderDeviceId: bob.deviceId,
      dialogId,
      clientMsgId: crypto.randomUUID(),
      body: "two",
    });

    const page = await getHistory(db, alice.accountId, dialogId, { limit: 50 });
    expect(page.messages.map((m) => m.text)).toEqual(["one", "two"]);

    const forwardPage = await getHistory(db, alice.accountId, dialogId, {
      afterMsgId: page.messages[0].msg_id,
      limit: 1,
    });
    expect(forwardPage.messages.map((m) => m.text)).toEqual(["two"]);
    expect(forwardPage.nextBeforeMsgId).toBeUndefined();
  });

  test("read receipts advance member state and emit sync updates", async () => {
    const { alice, bob, dialogId } = await makePair();
    const sent = await sendMessage(db, {
      senderAccountId: alice.accountId,
      senderDeviceId: alice.deviceId,
      dialogId,
      clientMsgId: crypto.randomUUID(),
      body: "read me",
    });

    const read = await readHistory(db, { accountId: bob.accountId, dialogId, maxReadMsgId: sent.msgId });
    expect(read.maxReadMsgId).toBe(sent.msgId);
    expect(read.unreadCount).toBe(0);

    const diff = await getDifference(db, alice.accountId, sent.senderPts);
    expect(diff.kind).toBe("difference");
    expect(diff.updates.some((u) => u.type === "read.updated"
      && u.max_read_msg_id === sent.msgId && u.unread_count === 0)).toBe(true);

    const repeat = await readHistory(db, { accountId: bob.accountId, dialogId, maxReadMsgId: sent.msgId });
    expect(repeat.pushes).toHaveLength(0);
    expect(repeat.unreadCount).toBe(0);
    const afterRepeat = await getDifference(db, alice.accountId, diff.state.pts);
    expect(afterRepeat.kind).toBe("difference");
    expect(afterRepeat.updates).toEqual([]);
  });

  test("message plaintext is not stored on disk", async () => {
    const { alice, dialogId } = await makePair();
    const body = "plaintext must not appear here";
    await sendMessage(db, {
      senderAccountId: alice.accountId,
      senderDeviceId: alice.deviceId,
      dialogId,
      clientMsgId: crypto.randomUUID(),
      body,
    });

    const row = (await db`SELECT encode(body_ciphertext, 'escape') AS ciphertext FROM messages LIMIT 1`)[0];
    expect(String(row.ciphertext)).not.toContain(body);
  });

  test("resumable media is encrypted at rest, idempotent, and downloadable only by members", async () => {
    const { alice, bob, dialogId } = await makePair();
    const outsider = await makeAccount(testPhone(901), "Outsider");
    const bytes = Buffer.from("private-media-payload-that-must-not-be-visible-on-disk");
    const created = await createMediaUpload(db, alice.accountId, alice.deviceId, {
      kind: "file", contentType: "application/octet-stream", fileName: "safe.bin",
      byteSize: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex"),
    });
    const first = bytes.subarray(0, 20);
    const second = bytes.subarray(20);
    expect((await uploadMediaChunk(db, alice.accountId, alice.deviceId, created.mediaId, 0, first)).uploadOffset).toBe(20);
    const retry = await uploadMediaChunk(db, alice.accountId, alice.deviceId, created.mediaId, 0, first);
    expect(retry).toMatchObject({ uploadOffset: 20, duplicate: true });
    await uploadMediaChunk(db, alice.accountId, alice.deviceId, created.mediaId, 20, second);
    await expect(uploadMediaThumbnail(
      db, alice.accountId, alice.deviceId, created.mediaId, "image/jpeg", tinyJpeg(3_000, 3_000),
    )).rejects.toMatchObject({ status: 413 });
    await uploadMediaThumbnail(db, alice.accountId, alice.deviceId, created.mediaId, "image/jpeg", tinyJpeg());

    const stored = await db`SELECT ciphertext, plain_sha256 FROM media_chunks WHERE media_id = ${created.mediaId}`;
    expect(Buffer.concat(stored.map((row) => Buffer.from(row.ciphertext))).includes(bytes)).toBe(false);
    expect(Buffer.from(stored[0].plain_sha256).equals(createHash("sha256").update(first).digest())).toBe(false);
    const fingerprint = (await db`SELECT expected_sha256 FROM media_objects WHERE id = ${created.mediaId}`)[0];
    expect(Buffer.from(fingerprint.expected_sha256).equals(createHash("sha256").update(bytes).digest())).toBe(false);
    expect(await completeMediaUpload(db, alice.accountId, alice.deviceId, created.mediaId)).toMatchObject({ ready: true, duplicate: false });
    expect(await completeMediaUpload(db, alice.accountId, alice.deviceId, created.mediaId)).toMatchObject({ ready: true, duplicate: true });

    const sent = await sendMessage(db, {
      senderAccountId: alice.accountId, senderDeviceId: alice.deviceId, dialogId,
      clientMsgId: crypto.randomUUID(), body: "attached", mediaId: created.mediaId,
    });
    const history = await getHistory(db, bob.accountId, dialogId);
    expect(history.messages[0].media).toMatchObject({
      id: created.mediaId, kind: "file", byte_size: bytes.length, has_thumbnail: true,
    });
    const downloaded = await downloadMediaChunk(db, bob.accountId, created.mediaId, 0);
    const [parallelA, parallelB] = await Promise.all([
      downloadMediaChunk(db, bob.accountId, created.mediaId, 0),
      downloadMediaChunk(db, bob.accountId, created.mediaId, 0),
    ]);
    expect(parallelA.bytes).toEqual(first);
    expect(parallelB.bytes).toEqual(first);
    const downloadedSecond = await downloadMediaChunk(db, bob.accountId, created.mediaId, downloaded.nextOffset);
    expect(Buffer.concat([downloaded.bytes, downloadedSecond.bytes])).toEqual(bytes);
    await expect(downloadMediaChunk(db, outsider.accountId, created.mediaId, 0))
      .rejects.toMatchObject({ status: 404 });

    await deleteMessage(db, {
      actorAccountId: alice.accountId, actorDeviceId: alice.deviceId, dialogId,
      msgId: sent.msgId, clientMutationId: crypto.randomUUID(),
    });
    await expect(downloadMediaChunk(db, bob.accountId, created.mediaId, 0))
      .rejects.toMatchObject({ status: 404 });
    expect(await db`SELECT id FROM media_objects WHERE id = ${created.mediaId}`).toHaveLength(0);
  });

  test("multipart v2 accepts encrypted out-of-order parts and resumes only missing parts", async () => {
    const { alice } = await makePair();
    const bytes = Buffer.alloc(MEDIA_PART_SIZE * 2 + 31);
    bytes.fill(0x41, 0, MEDIA_PART_SIZE);
    bytes.fill(0x42, MEDIA_PART_SIZE, MEDIA_PART_SIZE * 2);
    bytes.fill(0x43, MEDIA_PART_SIZE * 2);
    const created = await createMediaUpload(db, alice.accountId, alice.deviceId, {
      kind: "file", contentType: "application/octet-stream", fileName: "multipart.bin",
      byteSize: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex"),
      uploadProtocol: "parts_v2",
    });
    expect(created).toMatchObject({
      uploadProtocol: "parts_v2", partSize: MEDIA_PART_SIZE, totalParts: 3, receivedParts: [],
    });

    const part0 = bytes.subarray(0, MEDIA_PART_SIZE);
    const part1 = bytes.subarray(MEDIA_PART_SIZE, MEDIA_PART_SIZE * 2);
    const part2 = bytes.subarray(MEDIA_PART_SIZE * 2);
    await expect(uploadMediaChunk(db, alice.accountId, alice.deviceId, created.mediaId, 0, part0))
      .rejects.toMatchObject({ status: 409, code: "media_protocol_mismatch" });
    await uploadMediaPart(db, alice.accountId, alice.deviceId, created.mediaId, 2, part2);
    await uploadMediaPart(db, alice.accountId, alice.deviceId, created.mediaId, 0, part0);
    expect(await uploadMediaPart(db, alice.accountId, alice.deviceId, created.mediaId, 0, part0))
      .toMatchObject({ duplicate: true, partIndex: 0 });
    const conflicting = Buffer.from(part0);
    conflicting[0] ^= 0xff;
    await expect(uploadMediaPart(db, alice.accountId, alice.deviceId, created.mediaId, 0, conflicting))
      .rejects.toMatchObject({ status: 409, code: "media_part_conflict" });

    expect(await getMediaUpload(db, alice.accountId, created.mediaId)).toMatchObject({
      uploadProtocol: "parts_v2", receivedParts: [0, 2], uploadOffset: MEDIA_PART_SIZE + 31,
    });
    await expect(completeMediaUpload(db, alice.accountId, alice.deviceId, created.mediaId))
      .rejects.toMatchObject({ status: 409 });
    await uploadMediaPart(db, alice.accountId, alice.deviceId, created.mediaId, 1, part1);
    expect(await completeMediaUpload(db, alice.accountId, alice.deviceId, created.mediaId))
      .toMatchObject({ ready: true, duplicate: false });

    const stored = await db`
      SELECT ciphertext FROM media_chunks WHERE media_id = ${created.mediaId} ORDER BY chunk_offset`;
    expect(Buffer.concat(stored.map((row) => Buffer.from(row.ciphertext))).includes(part0)).toBe(false);
  });

  test("media HTTP routes bound binary bodies and round-trip authorized chunks", async () => {
    const { alice, bob, dialogId } = await makePair();
    const server = startCloudServer(0, db, null, null);
    try {
      const base = `http://127.0.0.1:${server.port}`;
      const bytes = Buffer.from("http-media-round-trip");
      const createdResponse = await fetch(`${base}/v1/media/uploads`, {
        method: "POST",
        headers: { authorization: `Bearer ${alice.token}`, "content-type": "application/json" },
        body: JSON.stringify({
          kind: "file", contentType: "application/octet-stream", fileName: "round-trip.bin",
          byteSize: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex"),
        }),
      });
      expect(createdResponse.status).toBe(201);
      const created = await createdResponse.json() as { mediaId: string };

      const missingOffset = await fetch(`${base}/v1/media/uploads/${created.mediaId}/chunks`, {
        method: "PUT",
        headers: { authorization: `Bearer ${alice.token}` },
        body: bytes,
      });
      expect(missingOffset.status).toBe(400);

      const oversized = await fetch(`${base}/v1/media/uploads/${created.mediaId}/chunks`, {
        method: "PUT",
        headers: { authorization: `Bearer ${alice.token}`, "upload-offset": "0" },
        body: Buffer.alloc(mediaLimits().chunkBytes + 1),
      });
      expect(oversized.status).toBe(413);
      expect(Number((await db`SELECT uploaded_bytes FROM media_objects WHERE id = ${created.mediaId}`)[0].uploaded_bytes))
        .toBe(0);

      const chunk = await fetch(`${base}/v1/media/uploads/${created.mediaId}/chunks`, {
        method: "PUT",
        headers: { authorization: `Bearer ${alice.token}`, "upload-offset": "0" },
        body: bytes,
      });
      expect(chunk.status).toBe(200);
      expect(chunk.headers.get("upload-offset")).toBe(String(bytes.length));
      const completed = await fetch(`${base}/v1/media/uploads/${created.mediaId}/complete`, {
        method: "POST", headers: { authorization: `Bearer ${alice.token}` },
      });
      expect(completed.status).toBe(200);
      await sendMessage(db, {
        senderAccountId: alice.accountId, senderDeviceId: alice.deviceId, dialogId,
        clientMsgId: crypto.randomUUID(), mediaId: created.mediaId, body: "",
      });

      const downloaded = await fetch(`${base}/v1/media/${created.mediaId}/chunks?offset=0`, {
        headers: { authorization: `Bearer ${bob.token}` },
      });
      expect(downloaded.status).toBe(200);
      expect(Buffer.from(await downloaded.arrayBuffer())).toEqual(bytes);
      expect(downloaded.headers.get("x-media-next-offset")).toBe(String(bytes.length));

      const abandonedBytes = Buffer.from("abandoned route upload");
      const abandonedResponse = await fetch(`${base}/v1/media/uploads`, {
        method: "POST",
        headers: { authorization: `Bearer ${alice.token}`, "content-type": "application/json" },
        body: JSON.stringify({
          kind: "file", contentType: "application/octet-stream", fileName: "cancel.bin",
          byteSize: abandonedBytes.length,
          sha256: createHash("sha256").update(abandonedBytes).digest("hex"),
        }),
      });
      expect(abandonedResponse.status).toBe(201);
      const abandoned = await abandonedResponse.json() as { mediaId: string };
      const cancelled = await fetch(`${base}/v1/media/uploads/${abandoned.mediaId}`, {
        method: "DELETE", headers: { authorization: `Bearer ${alice.token}` },
      });
      expect(cancelled.status).toBe(200);
      expect(await cancelled.json()).toEqual({ mediaId: abandoned.mediaId, cancelled: true });
      const cancelledState = await fetch(`${base}/v1/media/uploads/${abandoned.mediaId}`, {
        headers: { authorization: `Bearer ${alice.token}` },
      });
      expect(cancelledState.status).toBe(404);
    } finally {
      server.stop(true);
    }
  });

  test("multipart v2 HTTP route reports capabilities, acknowledgements, and stable errors", async () => {
    const { alice } = await makePair();
    const server = startCloudServer(0, db, null, null);
    try {
      const base = `http://127.0.0.1:${server.port}`;
      const bytes = tinyJpeg(7, 9);
      const createdResponse = await fetch(`${base}/v1/media/uploads`, {
        method: "POST",
        headers: { authorization: `Bearer ${alice.token}`, "content-type": "application/json" },
        body: JSON.stringify({
          kind: "photo", contentType: "image/jpeg", fileName: "photo.jpg",
          byteSize: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex"),
          width: 7, height: 9, uploadProtocol: "parts_v2",
        }),
      });
      expect(createdResponse.status).toBe(201);
      const created = await createdResponse.json() as {
        mediaId: string; uploadProtocol: string; partSize: number; totalParts: number;
      };
      expect(created).toMatchObject({ uploadProtocol: "parts_v2", partSize: MEDIA_PART_SIZE, totalParts: 1 });

      const part = await fetch(`${base}/v1/media/uploads/${created.mediaId}/parts/0`, {
        method: "PUT", headers: { authorization: `Bearer ${alice.token}` }, body: bytes,
      });
      expect(part.status).toBe(200);
      expect(await part.json()).toMatchObject({ partIndex: 0, complete: true, duplicate: false });
      expect(safeRoute(`/v1/media/uploads/${created.mediaId}/parts/0`))
        .toBe("/v1/media/uploads/:id/parts/:part");

      const completed = await fetch(`${base}/v1/media/uploads/${created.mediaId}/complete`, {
        method: "POST", headers: { authorization: `Bearer ${alice.token}` },
      });
      expect(completed.status).toBe(200);

      const invalid = await fetch(`${base}/v1/media/uploads`, {
        method: "POST",
        headers: { authorization: `Bearer ${alice.token}`, "content-type": "application/json" },
        body: JSON.stringify({
          kind: "file", contentType: "application/octet-stream", byteSize: 1,
          sha256: createHash("sha256").update(Buffer.from([1])).digest("hex"),
          uploadProtocol: "unknown",
        }),
      });
      expect(invalid.status).toBe(400);
      expect(await invalid.json()).toMatchObject({ code: "unsupported_upload_protocol" });
    } finally {
      server.stop(true);
    }
  });

  test("media completion rejects gaps and checksum mismatches without publishing a message", async () => {
    const { alice, dialogId } = await makePair();
    const bytes = Buffer.from("checksum-test");
    const created = await createMediaUpload(db, alice.accountId, alice.deviceId, {
      kind: "voice", contentType: "audio/mp4", byteSize: bytes.length,
      sha256: "00".repeat(32), durationMs: 850,
    });
    await expect(uploadMediaChunk(db, alice.accountId, alice.deviceId, created.mediaId, 4, bytes))
      .rejects.toMatchObject({ status: 409 });
    await uploadMediaChunk(db, alice.accountId, alice.deviceId, created.mediaId, 0, bytes);
    await expect(completeMediaUpload(db, alice.accountId, alice.deviceId, created.mediaId))
      .rejects.toThrow("checksum mismatch");
    await expect(completeMediaUpload(db, alice.accountId, alice.deviceId, created.mediaId))
      .rejects.toThrow("upload unavailable");
    expect(await db`SELECT media_id FROM media_chunks WHERE media_id = ${created.mediaId}`).toHaveLength(0);
    expect((await db`SELECT status FROM media_objects WHERE id = ${created.mediaId}`)[0].status).toBe("rejected");
    await expect(sendMessage(db, {
      senderAccountId: alice.accountId, senderDeviceId: alice.deviceId, dialogId,
      clientMsgId: crypto.randomUUID(), body: "", mediaId: created.mediaId,
    })).rejects.toThrow("media upload is incomplete");

    const expired = await createMediaUpload(db, alice.accountId, alice.deviceId, {
      kind: "file", contentType: "application/octet-stream", byteSize: bytes.length,
      sha256: createHash("sha256").update(bytes).digest("hex"),
    });
    await uploadMediaChunk(db, alice.accountId, alice.deviceId, expired.mediaId, 0, bytes);
    await db`UPDATE media_objects SET expires_at = now() - interval '1 second' WHERE id = ${expired.mediaId}`;
    await expect(completeMediaUpload(db, alice.accountId, alice.deviceId, expired.mediaId))
      .rejects.toMatchObject({ status: 410 });
  });

  test("media completion rejects content that does not match its declared type", async () => {
    const { alice } = await makePair();
    const bytes = Buffer.from("this is not an image");
    const created = await createMediaUpload(db, alice.accountId, alice.deviceId, {
      kind: "photo", contentType: "image/jpeg", fileName: "fake.jpg",
      byteSize: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex"), width: 1, height: 1,
    });
    await uploadMediaChunk(db, alice.accountId, alice.deviceId, created.mediaId, 0, bytes);
    await expect(completeMediaUpload(db, alice.accountId, alice.deviceId, created.mediaId))
      .rejects.toMatchObject({ status: 415 });
  });

  test.each([
    ["image/jpeg", tinyJpeg(1_284, 2_778)],
    ["image/png", tinyPng(1_284, 2_778)],
  ])("media completion accepts a valid %s photo with matching dimensions", async (contentType, bytes) => {
    const { alice } = await makePair();
    const created = await createMediaUpload(db, alice.accountId, alice.deviceId, {
      kind: "photo", contentType, fileName: "valid-photo",
      byteSize: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex"),
      width: 1_284, height: 2_778,
    });
    await uploadMediaChunk(db, alice.accountId, alice.deviceId, created.mediaId, 0, bytes);
    await expect(completeMediaUpload(db, alice.accountId, alice.deviceId, created.mediaId))
      .resolves.toMatchObject({ ready: true, duplicate: false });
  });

  test("owners can cancel abandoned uploads but cannot cancel delivered media", async () => {
    const { alice, bob, dialogId } = await makePair();
    const bytes = Buffer.from("abandoned encrypted upload");
    const abandoned = await createMediaUpload(db, alice.accountId, alice.deviceId, {
      kind: "file", contentType: "application/octet-stream", fileName: "private.txt",
      byteSize: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex"),
    });
    await uploadMediaChunk(db, alice.accountId, alice.deviceId, abandoned.mediaId, 0, bytes);
    await expect(cancelMediaUpload(db, bob.accountId, bob.deviceId, abandoned.mediaId)).rejects.toMatchObject({ status: 404 });
    expect(await cancelMediaUpload(db, alice.accountId, alice.deviceId, abandoned.mediaId)).toEqual({
      mediaId: abandoned.mediaId, cancelled: true,
    });

    const delivered = await createMediaUpload(db, alice.accountId, alice.deviceId, {
      kind: "file", contentType: "application/octet-stream", fileName: "delivered.txt",
      byteSize: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex"),
    });
    await uploadMediaChunk(db, alice.accountId, alice.deviceId, delivered.mediaId, 0, bytes);
    await completeMediaUpload(db, alice.accountId, alice.deviceId, delivered.mediaId);
    await sendMessage(db, {
      senderAccountId: alice.accountId, senderDeviceId: alice.deviceId, dialogId,
      clientMsgId: crypto.randomUUID(), body: "", mediaId: delivered.mediaId,
    });
    await expect(cancelMediaUpload(db, alice.accountId, alice.deviceId, delivered.mediaId)).rejects.toMatchObject({ status: 409 });
  });

  test("deleting a source keeps forwarded media until the final visible copy is deleted", async () => {
    const { alice, bob, dialogId: sourceDialogId } = await makePair();
    const charlie = await makeAccount(testPhone(902), "Charlie");
    const destination = await getOrCreateDirectDialog(db, bob.accountId, charlie.accountId);
    const bytes = Buffer.from("forwarded encrypted media");
    const created = await createMediaUpload(db, alice.accountId, alice.deviceId, {
      kind: "file", contentType: "application/octet-stream", fileName: "forward.bin",
      byteSize: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex"),
    });
    await uploadMediaChunk(db, alice.accountId, alice.deviceId, created.mediaId, 0, bytes);
    await completeMediaUpload(db, alice.accountId, alice.deviceId, created.mediaId);
    const source = await sendMessage(db, {
      senderAccountId: alice.accountId, senderDeviceId: alice.deviceId,
      dialogId: sourceDialogId, clientMsgId: crypto.randomUUID(), body: "", mediaId: created.mediaId,
    });
    const forwarded = await sendMessage(db, {
      senderAccountId: bob.accountId, senderDeviceId: bob.deviceId,
      dialogId: destination.dialogId, clientMsgId: crypto.randomUUID(),
      forwardedFrom: { dialogId: sourceDialogId, msgId: source.msgId },
    });
    await deleteMessage(db, {
      actorAccountId: alice.accountId, actorDeviceId: alice.deviceId,
      dialogId: sourceDialogId, msgId: source.msgId, clientMutationId: crypto.randomUUID(),
    });
    expect((await downloadMediaChunk(db, charlie.accountId, created.mediaId, 0)).bytes).toEqual(bytes);
    await deleteMessage(db, {
      actorAccountId: bob.accountId, actorDeviceId: bob.deviceId,
      dialogId: destination.dialogId, msgId: forwarded.msgId, clientMutationId: crypto.randomUUID(),
    });
    await expect(downloadMediaChunk(db, charlie.accountId, created.mediaId, 0))
      .rejects.toMatchObject({ status: 404 });
    expect(await db`SELECT id FROM media_objects WHERE id = ${created.mediaId}`).toHaveLength(0);
  });

  test("media creation reserves quota atomically and sanitizes file names", async () => {
    const { alice } = await makePair();
    await expect(createMediaUpload(db, alice.accountId, alice.deviceId, {
      kind: "voice", contentType: "image/jpeg", byteSize: 4, sha256: "11".repeat(32),
    })).rejects.toThrow("audio content type required");
    await expect(createMediaUpload(db, alice.accountId, alice.deviceId, {
      kind: "photo", contentType: "image/jpeg", byteSize: 4, sha256: "11".repeat(32), width: 0,
    })).rejects.toThrow("invalid media dimensions");
    const oldQuota = process.env.TOJ_MEDIA_ACCOUNT_QUOTA_BYTES;
    process.env.TOJ_MEDIA_ACCOUNT_QUOTA_BYTES = "1024";
    try {
      const bytes = Buffer.alloc(700, 1);
      const first = await createMediaUpload(db, alice.accountId, alice.deviceId, {
        kind: "file", contentType: "application/pdf", fileName: "folder/statement.pdf",
        byteSize: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex"),
      });
      const metadata = (await db`
        SELECT file_name, file_name_key_id, file_name_nonce, file_name_ciphertext
        FROM media_objects WHERE id = ${first.mediaId}`)[0];
      expect(metadata.file_name).toBeNull();
      expect(Buffer.from(metadata.file_name_ciphertext).includes(Buffer.from("statement.pdf"))).toBe(false);
      expect((await openForScope(db, { kind: "account", accountId: alice.accountId }, {
        keyId: metadata.file_name_key_id,
        nonce: Buffer.from(metadata.file_name_nonce),
        ciphertext: Buffer.from(metadata.file_name_ciphertext),
      }, mediaFileNameAAD(first.mediaId))).toString("utf8")).toBe("statement.pdf");
      await expect(createMediaUpload(db, alice.accountId, alice.deviceId, {
        kind: "file", contentType: "application/pdf", byteSize: 400, sha256: "11".repeat(32),
      })).rejects.toEqual(expect.objectContaining<Partial<MediaError>>({ status: 413 }));
    } finally {
      if (oldQuota == null) delete process.env.TOJ_MEDIA_ACCOUNT_QUOTA_BYTES;
      else process.env.TOJ_MEDIA_ACCOUNT_QUOTA_BYTES = oldQuota;
    }
  });

  test("media mutations revalidate the device and cap active upload rows", async () => {
    const { alice } = await makePair();
    const oldActiveLimit = process.env.TOJ_MEDIA_MAX_ACTIVE_UPLOADS;
    process.env.TOJ_MEDIA_MAX_ACTIVE_UPLOADS = "2";
    try {
      for (let index = 0; index < 2; index += 1) {
        await createMediaUpload(db, alice.accountId, alice.deviceId, {
          kind: "file", contentType: "application/octet-stream", byteSize: 1,
          sha256: createHash("sha256").update(Buffer.from([index])).digest("hex"),
        });
      }
      await expect(createMediaUpload(db, alice.accountId, alice.deviceId, {
        kind: "file", contentType: "application/octet-stream", byteSize: 1,
        sha256: createHash("sha256").update(Buffer.from([2])).digest("hex"),
      })).rejects.toMatchObject({ status: 429 });
      await revokeDevice(db, alice.accountId, alice.deviceId);
      await expect(createMediaUpload(db, alice.accountId, alice.deviceId, {
        kind: "file", contentType: "application/octet-stream", byteSize: 1,
        sha256: createHash("sha256").update(Buffer.from([3])).digest("hex"),
      })).rejects.toMatchObject({ status: 401 });
    } finally {
      if (oldActiveLimit == null) delete process.env.TOJ_MEDIA_MAX_ACTIVE_UPLOADS;
      else process.env.TOJ_MEDIA_MAX_ACTIVE_UPLOADS = oldActiveLimit;
    }
  });

  test("concurrent sends with the same client_msg_id collapse to one message (B2 race)", async () => {
    const { alice, dialogId } = await makePair();
    const params = {
      senderAccountId: alice.accountId, senderDeviceId: alice.deviceId,
      dialogId, clientMsgId: crypto.randomUUID(), body: "race",
    };
    const [a, b] = await Promise.all([sendMessage(db, params), sendMessage(db, params)]);
    expect(a.msgId).toBe(b.msgId);
    expect(a.senderPts).toBe(b.senderPts);
    expect([a.duplicate, b.duplicate].sort()).toEqual([false, true]);
    const count = (await db`SELECT count(*)::int AS c FROM messages WHERE dialog_id = ${dialogId}`)[0];
    expect(Number(count.c)).toBe(1);
  });

  test("contact lookup resolves a phone to an account and null for unknown", async () => {
    const { code } = await startVerification(db, "+16505550140");
    const session = await checkVerification(db, "+16505550140", code, "ios", "iPhone", "Muhammad");
    const requester = await makeAccount(testPhone(141), "Requester");
    const found = await lookupAccountByPhone(db, requester.accountId, "+16505550140");
    expect(found?.accountId).toBe(session.accountId);
    expect(found?.displayName).toBe("Muhammad");
    expect(await lookupAccountByPhone(db, requester.accountId, "+16505559999")).toBeNull();
  });

  test("profile updates persist and sync to every active chat partner", async () => {
    const owner = await makeAccount(testPhone(145), "Old Name");
    const requester = await makeAccount(testPhone(146), "Requester");
    const direct = await getOrCreateDirectDialog(db, owner.accountId, requester.accountId);
    const requesterPts = Number((await db`
      SELECT pts FROM account_sync_states WHERE account_id = ${requester.accountId}`)[0].pts);
    const result = await updateProfile(db, owner.accountId, owner.deviceId, {
      username: "new_name",
      firstName: "New", lastName: "Name", bio: "Building Toj",
      birthday: "1995-04-18", colorIndex: 4,
    });
    expect(result.profile).toMatchObject({
      accountId: owner.accountId, username: "new_name", firstName: "New", lastName: "Name",
      displayName: "New Name", bio: "Building Toj", birthday: "1995-04-18", colorIndex: 4,
    });
    expect(await getProfile(db, owner.accountId)).toEqual(result.profile);
    expect((await lookupAccountByPhone(db, requester.accountId, testPhone(145)))?.displayName)
      .toBe("New Name");
    expect((await lookupAccountByUsername(db, requester.accountId, "@NEW_NAME"))?.accountId)
      .toBe(owner.accountId);
    const publicLookup = await lookupAccountByUsername(db, requester.accountId, "@NEW_NAME");
    expect(Object.keys(publicLookup!).sort()).toEqual([
      "accountId", "colorIndex", "displayName", "firstName", "lastName", "updatedAt", "username",
    ]);

    const difference = await getDifference(db, requester.accountId, requesterPts);
    expect(difference.kind).toBe("difference");
    if (difference.kind === "difference") {
      expect(difference.updates).toContainEqual(expect.objectContaining({
        type: "profile.updated", subject_account_id: owner.accountId,
        username: "new_name", display_name: "New Name", bio: "Building Toj",
        birthday: "1995-04-18", color_index: 4,
        shared_dialog_ids: [direct.dialogId],
      }));
    }
    const snapshot = await startBootstrap(db, requester.accountId);
    const page = await getBootstrapDialogsPage(db, requester.accountId, snapshot.token);
    expect(page.dialogs[0].profiles).toContainEqual(expect.objectContaining({
      accountId: owner.accountId, displayName: "New Name", colorIndex: 4,
    }));

    await revokeDevice(db, owner.accountId, owner.deviceId);
    await expect(updateProfile(db, owner.accountId, owner.deviceId, {
      firstName: "Another", lastName: "Name", bio: "", birthday: null, colorIndex: 0,
    }))
      .rejects.toMatchObject({ status: 401 });
  });

  test("legacy profile updates preserve omitted usernames while explicit clears remain supported", async () => {
    const owner = await makeAccount(testPhone(149), "Legacy Owner");
    const base = {
      firstName: "Legacy", lastName: "Owner", bio: "", birthday: null, colorIndex: 2,
    };
    await updateProfile(db, owner.accountId, owner.deviceId, {
      ...base,
      username: "legacy_owner",
    });

    const beforeOmitted = Number((await db`
      SELECT pts FROM account_sync_states WHERE account_id = ${owner.accountId}`)[0].pts);
    const omitted = await updateProfile(db, owner.accountId, owner.deviceId, {
      ...base,
      firstName: "Updated",
    });
    expect(omitted.profile.username).toBe("legacy_owner");
    expect((await getProfile(db, owner.accountId)).username).toBe("legacy_owner");
    const omittedDifference = await getDifference(db, owner.accountId, beforeOmitted);
    expect(omittedDifference.kind).toBe("difference");
    if (omittedDifference.kind === "difference") {
      expect(omittedDifference.updates).toContainEqual(expect.objectContaining({
        type: "profile.updated",
        subject_account_id: owner.accountId,
        username: "legacy_owner",
      }));
    }

    await expect(updateProfile(db, owner.accountId, owner.deviceId, {
      ...base,
      username: 42,
    })).rejects.toMatchObject({ status: 400 });

    const beforeClear = Number((await db`
      SELECT pts FROM account_sync_states WHERE account_id = ${owner.accountId}`)[0].pts);
    const cleared = await updateProfile(db, owner.accountId, owner.deviceId, {
      ...base,
      username: null,
    });
    expect(cleared.profile.username).toBeNull();
    const clearedDifference = await getDifference(db, owner.accountId, beforeClear);
    expect(clearedDifference.kind).toBe("difference");
    if (clearedDifference.kind === "difference") {
      expect(clearedDifference.updates).toContainEqual(expect.objectContaining({
        type: "profile.updated",
        subject_account_id: owner.accountId,
        username: null,
      }));
    }

    await updateProfile(db, owner.accountId, owner.deviceId, {
      ...base,
      username: "legacy_owner",
    });
    expect((await updateProfile(db, owner.accountId, owner.deviceId, {
      ...base,
      username: "",
    })).profile.username).toBeNull();
  });

  test("usernames are normalized, unique under concurrency, and invalid lookups are non-oracular", async () => {
    const first = await makeAccount(testPhone(147), "First");
    const second = await makeAccount(testPhone(148), "Second");
    const profile = { username: "unique_name", firstName: "Name", lastName: "", bio: "", birthday: null, colorIndex: 0 };
    const attempts = await Promise.allSettled([
      updateProfile(db, first.accountId, first.deviceId, profile),
      updateProfile(db, second.accountId, second.deviceId, profile),
    ]);
    expect(attempts.filter((item) => item.status === "fulfilled")).toHaveLength(1);
    expect(attempts.filter((item) => item.status === "rejected")[0])
      .toMatchObject({ reason: expect.objectContaining({ status: 409 }) });
    expect(await lookupAccountByUsername(db, first.accountId, "@UNIQUE_NAME")).not.toBeNull();
    process.env.TOJ_BLIND_INDEX_KEYRING = JSON.stringify({
      "username-v2": Buffer.alloc(32, 0x6b).toString("base64"),
    });
    process.env.TOJ_BLIND_INDEX_ACTIVE_KEY_ID = "username-v2";
    expect(await lookupAccountByUsername(db, first.accountId, "unique_name")).not.toBeNull();
    expect(Number((await db`SELECT count(*) AS count FROM contact_lookup_attempts
      WHERE requester_account_id = ${first.accountId}`)[0].count)).toBe(1);
    expect(await lookupAccountByUsername(db, first.accountId, "not_valid!")).toBeNull();
    await expect(updateProfile(db, first.accountId, first.deviceId, { ...profile, username: "admin" }))
      .rejects.toMatchObject({ status: 400 });
  });

  test("profile photos sync idempotently to devices and chat partners without contact discovery leakage", async () => {
    const { alice, bob } = await makePair();
    const outsider = await makeAccount(testPhone(147), "Outsider");
    await db`UPDATE accounts SET username = 'alice_photo' WHERE id = ${alice.accountId}`;
    expect(await profilePhotosSchemaReadiness(db)).toEqual({ ready: true });
    const bobPtsBeforePhoto = Number((await db`
      SELECT pts FROM account_sync_states WHERE account_id = ${bob.accountId}`)[0].pts);
    const bytes = tinyJpeg(96, 96);
    const upload = await createMediaUpload(db, alice.accountId, alice.deviceId, {
      kind: "photo", contentType: "image/jpeg", fileName: "avatar.jpg",
      byteSize: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex"),
      width: 96, height: 96, purpose: "profile_photo",
    });
    await uploadMediaChunk(db, alice.accountId, alice.deviceId, upload.mediaId, 0, bytes);
    await uploadMediaThumbnail(
      db, alice.accountId, alice.deviceId, upload.mediaId, "image/jpeg", bytes,
    );
    await completeMediaUpload(db, alice.accountId, alice.deviceId, upload.mediaId);

    const mutationId = crypto.randomUUID();
    const committed = await updateProfilePhoto(db, {
      accountId: alice.accountId,
      deviceId: alice.deviceId,
      mediaId: upload.mediaId,
      clientMutationId: mutationId,
      basePhotoRevision: 0,
    });
    expect(committed).toMatchObject({
      duplicate: false,
      committedPhotoRevision: 1,
      profile: {
        accountId: alice.accountId,
        username: "alice_photo",
        photoRevision: 1,
        photo: { id: upload.mediaId },
      },
    });
    expect(committed.pushes.map((push) => push.accountId).sort())
      .toEqual([alice.accountId, bob.accountId].sort());

    const previousProfilePhotoFlag = process.env.TOJ_PROFILE_PHOTOS_V1_ENABLED;
    const requestBody = JSON.stringify({
      mediaId: upload.mediaId,
      clientMutationId: mutationId,
      basePhotoRevision: 0,
    });
    process.env.TOJ_PROFILE_PHOTOS_V1_ENABLED = "0";
    const hiddenServer = startCloudServer(0, db, null, null, { backgroundWorkers: false });
    try {
      const hiddenResponse = await fetch(
        `http://127.0.0.1:${hiddenServer.port}/v1/profile/photo`,
        {
          method: "PUT",
          headers: {
            authorization: `Bearer ${alice.token}`,
            "content-type": "application/json",
          },
          body: requestBody,
        },
      );
      expect(hiddenResponse.status).toBe(404);
      expect(await hiddenResponse.json()).toMatchObject({ code: "capability_unavailable" });
    } finally {
      hiddenServer.stop(true);
    }

    process.env.TOJ_PROFILE_PHOTOS_V1_ENABLED = "1";
    const routeServer = startCloudServer(0, db, null, null, { backgroundWorkers: false });
    try {
      const endpoint = `http://127.0.0.1:${routeServer.port}/v1/profile/photo`;
      const unauthorized = await fetch(endpoint, {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: requestBody,
      });
      expect(unauthorized.status).toBe(401);

      const inaccessible = await fetch(endpoint, {
        method: "PUT",
        headers: {
          authorization: `Bearer ${outsider.token}`,
          "content-type": "application/json",
        },
        body: requestBody,
      });
      expect(inaccessible.status).toBe(404);

      const duplicate = await fetch(endpoint, {
        method: "PUT",
        headers: {
          authorization: `Bearer ${alice.token}`,
          "content-type": "application/json",
        },
        body: requestBody,
      });
      expect(duplicate.status).toBe(200);
      expect(await duplicate.json()).toMatchObject({
        duplicate: true,
        committedPhotoRevision: 1,
        profile: {
          accountId: alice.accountId,
          photoRevision: 1,
          photo: { id: upload.mediaId, file_name: "avatar.jpg" },
        },
      });
    } finally {
      routeServer.stop(true);
      if (previousProfilePhotoFlag === undefined) {
        delete process.env.TOJ_PROFILE_PHOTOS_V1_ENABLED;
      } else {
        process.env.TOJ_PROFILE_PHOTOS_V1_ENABLED = previousProfilePhotoFlag;
      }
    }

    expect(await loadProfiles(db, [alice.accountId])).toContainEqual(expect.objectContaining({
      accountId: alice.accountId,
      photoRevision: 1,
      photo: expect.objectContaining({ id: upload.mediaId, file_name: "avatar.jpg" }),
    }));
    expect((await lookupAccountByPhone(db, outsider.accountId, "+16505550100"))?.photo).toBeNull();
    expect((await downloadMediaChunk(db, bob.accountId, upload.mediaId, 0)).bytes).toEqual(bytes);
    await expect(downloadMediaChunk(db, outsider.accountId, upload.mediaId, 0))
      .rejects.toMatchObject({ status: 404 });

    const photoDifference = await getDifference(db, bob.accountId, bobPtsBeforePhoto);
    expect(photoDifference.kind).toBe("difference");
    if (photoDifference.kind === "difference") {
      expect(photoDifference.updates).toContainEqual(expect.objectContaining({
        type: "profile.updated",
        subject_account_id: alice.accountId,
        photo_revision: 1,
        photo: expect.objectContaining({ id: upload.mediaId }),
      }));
    }
    const photoSnapshot = await startBootstrap(db, bob.accountId);
    const photoPage = await getBootstrapDialogsPage(db, bob.accountId, photoSnapshot.token);
    expect(photoPage.dialogs.flatMap((dialog) => dialog.profiles)).toContainEqual(
      expect.objectContaining({
        accountId: alice.accountId,
        photoRevision: 1,
        photo: expect.objectContaining({ id: upload.mediaId, file_name: "avatar.jpg" }),
      }),
    );

    const retry = await updateProfilePhoto(db, {
      accountId: alice.accountId,
      deviceId: alice.deviceId,
      mediaId: upload.mediaId,
      clientMutationId: mutationId,
      basePhotoRevision: 0,
    });
    expect(retry).toMatchObject({ duplicate: true, committedPhotoRevision: 1 });
    await expect(updateProfilePhoto(db, {
      accountId: alice.accountId,
      deviceId: alice.deviceId,
      mediaId: null,
      clientMutationId: mutationId,
      basePhotoRevision: 0,
    })).rejects.toMatchObject({ status: 409, code: "idempotency_conflict" });
    await expect(updateProfilePhoto(db, {
      accountId: alice.accountId,
      deviceId: alice.deviceId,
      mediaId: upload.mediaId,
      clientMutationId: crypto.randomUUID(),
      basePhotoRevision: 0,
    })).rejects.toMatchObject({ status: 409, code: "stale_profile_photo" });

    const removed = await updateProfilePhoto(db, {
      accountId: alice.accountId,
      deviceId: alice.deviceId,
      mediaId: null,
      clientMutationId: crypto.randomUUID(),
      basePhotoRevision: 1,
    });
    expect(removed).toMatchObject({
      committedPhotoRevision: 2,
      profile: { photo: null, photoRevision: 2 },
    });
    await expect(downloadMediaChunk(db, bob.accountId, upload.mediaId, 0))
      .rejects.toMatchObject({ status: 404 });
    await db`DELETE FROM media_objects WHERE id = ${upload.mediaId}`;
    const durableRetry = await updateProfilePhoto(db, {
      accountId: alice.accountId,
      deviceId: alice.deviceId,
      mediaId: upload.mediaId,
      clientMutationId: mutationId,
      basePhotoRevision: 0,
    });
    expect(durableRetry).toMatchObject({
      duplicate: true,
      committedPhotoRevision: 1,
      profile: { username: "alice_photo", photo: null, photoRevision: 2 },
    });
  });

  test("profile photo uploads enforce their narrow image contract", async () => {
    const owner = await makeAccount(testPhone(148), "Owner");
    const bytes = tinyPng(32, 32);
    await expect(createMediaUpload(db, owner.accountId, owner.deviceId, {
      kind: "photo", contentType: "image/png", fileName: "avatar.png",
      byteSize: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex"),
      width: 32, height: 32, purpose: "profile_photo",
    })).rejects.toMatchObject({ status: 415, code: "invalid_profile_photo_type" });
    await expect(createMediaUpload(db, owner.accountId, owner.deviceId, {
      kind: "photo", contentType: "image/jpeg", fileName: "avatar.jpg",
      byteSize: 3 * 1024 * 1024 + 1, sha256: "11".repeat(32),
      width: 1, height: 1, purpose: "profile_photo",
    })).rejects.toMatchObject({ status: 413, code: "profile_photo_too_large" });
    await expect(createMediaUpload(db, owner.accountId, owner.deviceId, {
      kind: "photo", contentType: "image/jpeg", fileName: "avatar.jpg",
      byteSize: 64, sha256: "11".repeat(32),
      width: 1_025, height: 1, purpose: "profile_photo",
    })).rejects.toMatchObject({ status: 413, code: "profile_photo_dimensions_too_large" });

    const wrongPurposeBytes = tinyJpeg(16, 16);
    const wrongPurpose = await createMediaUpload(db, owner.accountId, owner.deviceId, {
      kind: "photo", contentType: "image/jpeg", fileName: "message.jpg",
      byteSize: wrongPurposeBytes.length,
      sha256: createHash("sha256").update(wrongPurposeBytes).digest("hex"),
      width: 16, height: 16, purpose: "message",
    });
    await uploadMediaChunk(
      db, owner.accountId, owner.deviceId, wrongPurpose.mediaId, 0, wrongPurposeBytes,
    );
    await completeMediaUpload(db, owner.accountId, owner.deviceId, wrongPurpose.mediaId);
    await expect(updateProfilePhoto(db, {
      accountId: owner.accountId,
      deviceId: owner.deviceId,
      mediaId: wrongPurpose.mediaId,
      clientMutationId: crypto.randomUUID(),
      basePhotoRevision: 0,
    })).rejects.toMatchObject({ status: 404, code: "profile_photo_unavailable" });

    const actualDimensions = tinyJpeg(16, 16);
    const declaredDimensions = await createMediaUpload(db, owner.accountId, owner.deviceId, {
      kind: "photo", contentType: "image/jpeg", fileName: "avatar.jpg",
      byteSize: actualDimensions.length,
      sha256: createHash("sha256").update(actualDimensions).digest("hex"),
      width: 32, height: 32, purpose: "profile_photo",
    });
    await uploadMediaChunk(
      db, owner.accountId, owner.deviceId, declaredDimensions.mediaId, 0, actualDimensions,
    );
    await expect(completeMediaUpload(
      db, owner.accountId, owner.deviceId, declaredDimensions.mediaId,
    )).rejects.toMatchObject({ status: 415, code: "photo_dimensions_mismatch" });
  });

  test("profile photo mutation receipts have a replay-safe daily action budget", async () => {
    const owner = await makeAccount(testPhone(149), "Budgeted photos");
    const firstMutationId = crypto.randomUUID();
    for (let index = 0; index < 120; index += 1) {
      const result = await updateProfilePhoto(db, {
        accountId: owner.accountId,
        deviceId: owner.deviceId,
        mediaId: null,
        clientMutationId: index === 0 ? firstMutationId : crypto.randomUUID(),
        basePhotoRevision: 0,
      });
      expect(result.committedPhotoRevision).toBe(0);
    }
    await expect(updateProfilePhoto(db, {
      accountId: owner.accountId,
      deviceId: owner.deviceId,
      mediaId: null,
      clientMutationId: crypto.randomUUID(),
      basePhotoRevision: 0,
    })).rejects.toMatchObject({ status: 429, code: "profile_photo_rate_limited" });
    await expect(updateProfilePhoto(db, {
      accountId: owner.accountId,
      deviceId: owner.deviceId,
      mediaId: null,
      clientMutationId: firstMutationId,
      basePhotoRevision: 0,
    })).resolves.toMatchObject({ duplicate: true, committedPhotoRevision: 0 });
    expect(Number((await db`
      SELECT mutation_count FROM profile_photo_action_budgets
      WHERE account_id = ${owner.accountId}`)[0].mutation_count)).toBe(120);
  }, 10_000);

  test("status-only mixed-version deletion clears and erases a private profile photo", async () => {
    const owner = await makeAccount(testPhone(150), "Legacy deletion");
    const bytes = tinyJpeg(64, 64);
    const upload = await createMediaUpload(db, owner.accountId, owner.deviceId, {
      kind: "photo", contentType: "image/jpeg", fileName: "legacy.jpg",
      byteSize: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex"),
      width: 64, height: 64, purpose: "profile_photo",
    });
    await uploadMediaChunk(db, owner.accountId, owner.deviceId, upload.mediaId, 0, bytes);
    await uploadMediaThumbnail(
      db, owner.accountId, owner.deviceId, upload.mediaId, "image/jpeg", bytes,
    );
    await completeMediaUpload(db, owner.accountId, owner.deviceId, upload.mediaId);
    await db`
      UPDATE accounts SET profile_photo_media_id = ${upload.mediaId}
      WHERE id = ${owner.accountId}`;

    // This is the only write an older binary knew how to perform.
    await db`UPDATE accounts SET status = 'deleted' WHERE id = ${owner.accountId}`;
    expect((await db`
      SELECT status, profile_photo_media_id FROM accounts WHERE id = ${owner.accountId}`)[0])
      .toMatchObject({ status: "deleted", profile_photo_media_id: null });
    expect(await db`SELECT id FROM media_objects WHERE id = ${upload.mediaId}`).toHaveLength(0);
  });

  test("contact discovery is persistently bounded per authenticated account", async () => {
    const requester = await makeAccount(testPhone(142), "Requester");
    for (let index = 0; index < 20; index += 1) {
      expect(await lookupAccountByPhone(db, requester.accountId, testPhone(2_000 + index))).toBeNull();
    }
    await expect(lookupAccountByPhone(db, requester.accountId, testPhone(2_100)))
      .rejects.toMatchObject({ status: 429 });
    // A retry for an already-budgeted number remains usable and does not consume another slot.
    expect(await lookupAccountByPhone(db, requester.accountId, testPhone(2_000))).toBeNull();
  });
});
  test("capability contract is public, cache-safe, and advertises shipped messaging features", async () => {
    const server = startCloudServer(0, db, null, null);
    try {
      const response = await fetch(`http://127.0.0.1:${server.port}/v1/capabilities`);
      expect(response.status).toBe(200);
      expect(response.headers.get("cache-control")).toBe("no-store");
      expect(await response.json()).toEqual(CLOUD_CAPABILITIES);
      expect(safeRoute("/v1/capabilities")).toBe("/v1/capabilities");
    } finally {
      server.stop(true);
    }
  });
  test("dialog preference capability and route family are hard-gated by the rollout flag", async () => {
    await resetDb();
    const { alice, dialogId } = await makePair();
    const previous = process.env.TOJ_DIALOG_PREFERENCES_V1_ENABLED;
    const previousBehavior = process.env.TOJ_DIALOG_PREFERENCES_BEHAVIOR_ENABLED;
    let server: ReturnType<typeof startCloudServer> | undefined;
    try {
      delete process.env.TOJ_DIALOG_PREFERENCES_V1_ENABLED;
      server = startCloudServer(0, db, null, null);
      let base = `http://127.0.0.1:${server.port}`;
      let capabilities = await (await fetch(`${base}/v1/capabilities`)).json() as {
        api_version: number;
        capabilities: string[];
      };
      expect(capabilities.api_version).toBe(6);
      expect(capabilities.capabilities).not.toContain("dialog_preferences_v1");
      expect((await fetch(
        `${base}/v1/dialogs/${crypto.randomUUID()}/preferences`,
        { method: "PUT" },
      )).status).toBe(404);
      await server.stop(true);
      server = undefined;

      process.env.TOJ_DIALOG_PREFERENCES_V1_ENABLED = "1";
      process.env.TOJ_DIALOG_PREFERENCES_BEHAVIOR_ENABLED = "0";
      server = startCloudServer(0, db, null, null);
      base = `http://127.0.0.1:${server.port}`;
      capabilities = await (await fetch(`${base}/v1/capabilities`)).json() as {
        api_version: number;
        capabilities: string[];
      };
      expect(capabilities.capabilities).not.toContain("dialog_preferences_v1");
      expect((await fetch(
        `${base}/v1/dialogs/${crypto.randomUUID()}/preferences`,
        { method: "PUT" },
      )).status).toBe(404);
      await server.stop(true);
      server = undefined;

      delete process.env.TOJ_DIALOG_PREFERENCES_BEHAVIOR_ENABLED;
      server = startCloudServer(0, db, null, null);
      base = `http://127.0.0.1:${server.port}`;
      capabilities = await (await fetch(`${base}/v1/capabilities`)).json() as {
        api_version: number;
        capabilities: string[];
      };
      expect(capabilities.capabilities).toContain("dialog_preferences_v1");
      expect((await fetch(
        `${base}/v1/dialogs/${crypto.randomUUID()}/preferences`,
        { method: "PUT" },
      )).status).toBe(401);
      const clientMutationId = crypto.randomUUID();
      const updated = await fetch(`${base}/v1/dialogs/${dialogId}/preferences`, {
        method: "PUT",
        headers: {
          authorization: `Bearer ${alice.token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ clientMutationId, pinned: true, archived: true }),
      });
      expect(updated.status).toBe(200);
      expect(await updated.json()).toMatchObject({
        preferences: {
          dialogId,
          pinned: true,
          muted: false,
          archived: true,
        },
        duplicate: false,
      });
      const duplicate = await fetch(`${base}/v1/dialogs/${dialogId}/preferences`, {
        method: "PUT",
        headers: {
          authorization: `Bearer ${alice.token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ clientMutationId, pinned: true, archived: true }),
      });
      expect(duplicate.status).toBe(200);
      expect(await duplicate.json()).toMatchObject({ duplicate: true });
    } finally {
      if (server) await server.stop(true);
      if (previous === undefined) delete process.env.TOJ_DIALOG_PREFERENCES_V1_ENABLED;
      else process.env.TOJ_DIALOG_PREFERENCES_V1_ENABLED = previous;
      if (previousBehavior === undefined) {
        delete process.env.TOJ_DIALOG_PREFERENCES_BEHAVIOR_ENABLED;
      } else {
        process.env.TOJ_DIALOG_PREFERENCES_BEHAVIOR_ENABLED = previousBehavior;
      }
    }
  });
