import type { SQL } from "bun";
import { randomBytes, randomInt } from "node:crypto";
import {
  PHONE_AAD, phoneLookupCandidates, phoneLookupIndex,
  codeHashIndex, tokenHashCandidates, tokenHashIndex,
  normalizePhone, constantTimeEqual,
} from "./crypto";
import { loadMediaDTO, type MediaDTO } from "./media";
import { CryptoUnavailableError, openForScope, sealForScope } from "./envelope-crypto";
import { enqueuePushDeliveries, revokePushBindingsForDevice } from "./push";
import { notifySyncWakeups } from "./sync-wakeup";
import { COMMON_PASSWORDS_V1 } from "./common-passwords-v1";
import { AuthError } from "./auth-error";
import { telegramOTPFromEnvironment } from "./telegram-otp";
import { infobipOTPFromEnvironment } from "./infobip-otp";
import { whatsappOTPFromEnvironment } from "./whatsapp-otp";
export { AuthError } from "./auth-error";
import {
  isV2AccessToken,
  issueV2Session,
  notifySessionRevocation,
  resolveV2Access,
  type AuthV2Session,
} from "./session-security";

const OTP_TTL_MS = 5 * 60_000;
const OTP_RESEND_COOLDOWN_SECONDS = 30;
const OTP_PHONE_WINDOW_LIMIT = 5;
const OTP_NETWORK_WINDOW_LIMIT = 20;
const OTP_WINDOW_MINUTES = 15;
const OTP_MAX_ATTEMPTS = 5;
const CONTACT_LOOKUP_WINDOW_MINUTES = 15;
const CONTACT_LOOKUP_WINDOW_LIMIT = 20;
const CONTACT_LOOKUP_DAILY_LIMIT = 100;
const ALLOWED_PLATFORMS = new Set(["ios", "android", "web", "desktop"]);
type OTPPurpose = "login" | "account_deletion" | "security_change";
export type SecurityChangeEvent =
  | "two_factor_enabled"
  | "two_factor_changed"
  | "two_factor_disabled"
  | "device_revoked";

/**
 * The channels a user can pick between on the verification screen. The user chooses; the server
 * never substitutes. That is what makes the picker safe where a server-side fallback ladder was
 * not: a tap is the consent, so there is no silent routing and no probing a number on a provider
 * the user did not select.
 */
export const OTP_CHANNELS = ["telegram", "sms", "whatsapp"] as const;
export type OTPChannel = (typeof OTP_CHANNELS)[number];

export function isOTPChannel(value: unknown): value is OTPChannel {
  return typeof value === "string" && (OTP_CHANNELS as readonly string[]).includes(value);
}

export interface OTPDelivery {
  readonly channel: OTPChannel;
  readonly dailyRequestLimit?: number;
  allows?(phone: string): boolean;
  send(phone: string, code: string, purpose: OTPPurpose): Promise<void>;
  sendSecurityAlert?(phone: string, event: SecurityChangeEvent): Promise<void>;
}

/** Every channel configured on this deployment, keyed by the value the client names in its pick. */
export type OTPDeliveryRegistry = ReadonlyMap<OTPChannel, OTPDelivery>;

class WebhookOTPDelivery implements OTPDelivery {
  readonly channel = "sms" as const;
  constructor(private readonly url: URL, private readonly bearerToken: string) {}

  async send(phone: string, code: string, purpose: OTPPurpose): Promise<void> {
    const response = await fetch(this.url, {
      method: "POST",
      headers: {
        "authorization": `Bearer ${this.bearerToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ phone, code, purpose, service: "Toj" }),
      signal: AbortSignal.timeout(10_000),
    });
    if (!response.ok) throw new Error(`SMS delivery returned HTTP ${response.status}`);
  }

  async sendSecurityAlert(phone: string, event: SecurityChangeEvent): Promise<void> {
    const response = await fetch(this.url, {
      method: "POST",
      headers: {
        "authorization": `Bearer ${this.bearerToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ phone, event, kind: "security_alert", service: "Toj" }),
      signal: AbortSignal.timeout(10_000),
    });
    if (!response.ok) throw new Error(`SMS delivery returned HTTP ${response.status}`);
  }
}

function hostedAuthentication(): boolean {
  return process.env.NODE_ENV === "production" || process.env.NODE_ENV === "staging";
}

/**
 * Every configured channel, not one. The server used to hold a single delivery object and
 * telegram-otp.ts threw on startup if an SMS webhook was also configured — a pilot-era interlock
 * that guaranteed only one unproven provider could send. It also made the Telegram+SMS picker
 * unbootable in any configuration, which is the feature it was protecting.
 *
 * Removing that interlock is only safe together with per-channel consent in startVerification: the
 * gap between "more than one channel can be configured" and "the caller must name which one" is
 * precisely the silent substitution the interlock prevented. They ship as one change, never two.
 */
/**
 * Whether the OTP tables match what this build writes.
 *
 * `bun run staging` does not run migrations — they are a separate, deliberate `bun run migrate`.
 * So a deploy carrying a schema change starts cleanly, answers /ready 200, and then fails on the
 * first request that touches the new column. That happened with the `channel` column in #46: the
 * service looked healthy and every OTP request would have failed.
 *
 * Nine other subsystems already report schema readiness here; OTP simply was not among them. A
 * green /ready must mean the schema matches the code, or it is a signal that reassures without
 * checking — which is worse than no signal at all.
 */
export async function otpSchemaReadiness(sql: SQL): Promise<{ ready: boolean; missing: string[] }> {
  const missing: string[] = [];
  const row = (await sql`
    SELECT
      to_regclass('public.otp_challenges') IS NOT NULL AS otp_challenges,
      EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'otp_challenges' AND column_name = 'channel'
      ) AS otp_challenges_channel,
      to_regclass('public.security_step_up_tickets') IS NOT NULL AS security_step_up_tickets,
      to_regclass('public.account_two_factor') IS NOT NULL AS account_two_factor`)[0];
  for (const [name, present] of Object.entries(row ?? {})) {
    if (!present) missing.push(name);
  }
  return { ready: missing.length === 0, missing };
}

export function otpDeliveryRegistryFromEnvironment(): OTPDeliveryRegistry {
  const registry = new Map<OTPChannel, OTPDelivery>();

  const telegram = telegramOTPFromEnvironment();
  if (telegram) registry.set(telegram.channel, telegram);

  const rawUrl = process.env.TOJ_SMS_WEBHOOK_URL;
  const token = process.env.TOJ_SMS_WEBHOOK_TOKEN;
  if (rawUrl || token) {
    if (!rawUrl || !token) {
      throw new Error("TOJ_SMS_WEBHOOK_URL and TOJ_SMS_WEBHOOK_TOKEN must be set together");
    }
    const url = new URL(rawUrl);
    if (hostedAuthentication() && url.protocol !== "https:") {
      throw new Error("TOJ_SMS_WEBHOOK_URL must use HTTPS in production or staging");
    }
    const webhook = new WebhookOTPDelivery(url, token);
    registry.set(webhook.channel, webhook);
  }

  // Infobip and the generic webhook are both "sms". Two transports claiming one channel is
  // ambiguous, and letting the later registration silently win is the class of bug this file has
  // spent its history removing. Fail loudly and make the operator choose.
  const infobip = infobipOTPFromEnvironment();
  if (infobip) {
    if (registry.has(infobip.channel)) {
      throw new Error("Configure either the SMS webhook or Infobip as the sms channel, not both");
    }
    registry.set(infobip.channel, infobip);
  }

  const whatsapp = whatsappOTPFromEnvironment();
  if (whatsapp) registry.set(whatsapp.channel, whatsapp);

  // TOJ_OTP_PROVIDER survives as a deliberate activation switch for Telegram (telegram-otp.ts reads
  // it), not as a selector between mutually exclusive providers.
  const provider = process.env.TOJ_OTP_PROVIDER;
  if (provider && provider !== "telegram" && provider !== "webhook") {
    throw new Error("TOJ_OTP_PROVIDER must be telegram or webhook when set");
  }
  return registry;
}

type StartVerificationOptions = {
  networkKey?: string | null;
  /** Every channel this deployment can send on. The caller picks one; the server never picks. */
  deliveries?: OTPDeliveryRegistry | null;
  purpose?: OTPPurpose;
  /** The channel the user tapped. Required whenever any channel is configured. */
  deliveryChannel?: unknown;
};

function privateBetaOTPAllowed(normalizedPhone: string): boolean {
  if (process.env.TOJ_RETURN_OTP !== "1") return false;
  if (!hostedAuthentication()) return true;
  return (process.env.TOJ_DEV_OTP_ALLOWLIST ?? "")
    .split(",")
    .map((value) => value.trim())
    .filter((value) => /^\+[1-9]\d{7,14}$/.test(value))
    .includes(normalizedPhone);
}

/** Used only for provider-readiness reporting; it never exposes the allowlisted values. */
export function privateBetaOTPConfigured(): boolean {
  if (process.env.TOJ_RETURN_OTP !== "1") return false;
  if (!hostedAuthentication()) return true;
  return (process.env.TOJ_DEV_OTP_ALLOWLIST ?? "")
    .split(",")
    .some((value) => /^\+[1-9]\d{7,14}$/.test(value.trim()));
}

function validPhone(phone: string): string {
  if (/[A-Za-z]/.test(phone)) {
    throw new AuthError("enter a valid international phone number", 400);
  }
  const normalized = normalizePhone(phone.trim());
  if (!/^\+[1-9]\d{7,14}$/.test(normalized)) {
    throw new AuthError("enter a valid international phone number", 400);
  }
  return normalized;
}

function cleanLabel(value: string | undefined, maxLength: number): string | null {
  const trimmed = value?.trim() ?? "";
  if (!trimmed) return null;
  return trimmed.slice(0, maxLength);
}

/** Issues a short-lived OTP. Production returns codes only for explicitly allowlisted beta phones. */
export async function startVerification(
  sql: SQL,
  phone: string,
  options: StartVerificationOptions = {},
): Promise<{ code?: string; retryAfter?: number }> {
  const normalizedPhone = validPhone(phone);
  const purpose = options.purpose ?? "login";
  const lookupIndex = phoneLookupIndex(normalizedPhone);
  const lookup = lookupIndex.digest;
  const lookupCandidates = phoneLookupCandidates(normalizedPhone).map((candidate) => candidate.digest);
  const networkInput = options.networkKey ? `otp-network|${options.networkKey}` : null;
  const networkIndex = networkInput ? tokenHashIndex(networkInput) : null;
  const networkHash = networkIndex?.digest ?? null;
  const networkCandidates = networkInput
    ? tokenHashCandidates(networkInput).map((candidate) => candidate.digest)
    : [];
  const hosted = hostedAuthentication();
  const registry = options.deliveries ?? null;
  const configured = registry && registry.size > 0 ? registry : null;
  let delivery: OTPDelivery | null = null;

  if (configured) {
    // The user picks the channel and the server sends on exactly that one, or fails honestly. There
    // is no fallback ladder and no server-side routing: a tap is the consent, which is what makes a
    // picker safe where substitution was not. It also means no channel is ever probed for a number
    // whose owner did not choose it, so the disclosure a preflight would leak cannot happen here.
    if (!isOTPChannel(options.deliveryChannel) || !configured.has(options.deliveryChannel)) {
      throw new AuthError("choose how to receive your code", 400, undefined, "channel_required");
    }
    delivery = configured.get(options.deliveryChannel)!;

    // Account deletion stays unavailable on Telegram, deliberately rather than for tidiness:
    // deleteAccount hard-deletes this phone's otp_challenges, the very rows the Telegram request
    // budget counts, so minting a deletion code would reopen that budget as a resettable one.
    if (delivery.channel === "telegram" && purpose === "account_deletion") {
      throw new AuthError("this verification step is unavailable in the Telegram pilot", 503,
        undefined, "capability_unavailable");
    }
    // Recipient scope and the OTP-return interlock share one generic message on purpose: a
    // distinct reply would turn this endpoint into an allowlist-membership oracle.
    if (delivery.channel === "telegram" && process.env.TOJ_RETURN_OTP !== "0") {
      throw new AuthError("verification service temporarily unavailable", 503);
    }
    if (delivery.allows && !delivery.allows(normalizedPhone)) {
      throw new AuthError("verification service temporarily unavailable", 503);
    }
  } else if (options.deliveryChannel !== undefined) {
    // Nothing is configured, so a named channel cannot be honoured. Never fall back to returning a
    // synthetic code to a caller who asked for a real one.
    throw new AuthError("requested verification channel unavailable", 503);
  }

  const returnOTP = !delivery && (!hosted || privateBetaOTPAllowed(normalizedPhone));
  if (hosted && !delivery && !returnOTP) {
    throw new AuthError("verification service temporarily unavailable", 503);
  }

  const code = randomInt(0, 1_000_000).toString().padStart(6, "0");
  const salt = randomBytes(16);
  const expires = new Date(Date.now() + OTP_TTL_MS);
  const phoneLocks = lookupCandidates.map((candidate) => candidate.readBigInt64BE(0));
  const networkLocks = networkCandidates.map((candidate) => candidate.readBigInt64BE(0));

  const challengeId: string = await sql.begin(async (tx) => {
    if (delivery?.dailyRequestLimit) {
      // Taken before the phone/network locks below so every caller acquires the same ordering.
      // The window is only meaningful while cleanupExpiredData retains challenges for longer than
      // 24 hours; ops.ts carries the matching note and m3.test.ts pins the pair.
      await tx`SELECT pg_advisory_xact_lock(hashtextextended('toj-otp-daily-budget-v1', 0))`;
      const count = Number((await tx`SELECT count(*) AS count FROM otp_challenges
        WHERE created_at > now() - interval '24 hours'`)[0].count);
      if (count >= delivery.dailyRequestLimit) {
        throw new AuthError("verification request budget reached; try again later", 429, 86400);
      }
    }
    const locks = [...phoneLocks, ...networkLocks]
      .sort((a, b) => a < b ? -1 : a > b ? 1 : 0);
    for (const lock of locks) await tx`SELECT pg_advisory_xact_lock(${lock})`;

    const latest = (await tx`
      SELECT created_at, channel FROM otp_challenges
      WHERE phone_lookup_hash IN (
        SELECT decode(value, 'hex') FROM unnest(
          ${tx.array(lookupCandidates.map((hash) => hash.toString("hex")), "text")}::text[]
        ) AS candidate(value)
      )
        AND purpose = ${purpose}
      ORDER BY created_at DESC LIMIT 1`)[0];
    if (latest) {
      const ageSeconds = Math.floor((Date.now() - new Date(latest.created_at).getTime()) / 1000);
      // "I didn't get the WhatsApp one, send me a text" is the flow the picker exists for, so a
      // genuine channel change skips the cooldown. The cooldown is anti-annoyance and
      // anti-double-billing; the abuse control is the window limits below, which this never
      // touches — an exempted switch still counts toward them, so cycling channels cannot raise
      // the ceiling. Repeats on the same channel still wait.
      const switchedChannel = delivery !== null
        && latest.channel !== null
        && String(latest.channel) !== delivery.channel;
      if (ageSeconds < OTP_RESEND_COOLDOWN_SECONDS && !switchedChannel) {
        throw new AuthError(
          "please wait before requesting another code",
          429,
          OTP_RESEND_COOLDOWN_SECONDS - ageSeconds,
        );
      }
    }

    const phoneCount = Number((await tx`
      SELECT count(*) AS count FROM otp_challenges
      WHERE phone_lookup_hash IN (
        SELECT decode(value, 'hex') FROM unnest(
          ${tx.array(lookupCandidates.map((hash) => hash.toString("hex")), "text")}::text[]
        ) AS candidate(value)
      )
        AND created_at > now() - (${OTP_WINDOW_MINUTES} * interval '1 minute')`)[0].count);
    if (phoneCount >= OTP_PHONE_WINDOW_LIMIT) {
      throw new AuthError("too many verification requests; try again later", 429, OTP_WINDOW_MINUTES * 60);
    }

    if (networkHash) {
      const networkCount = Number((await tx`
        SELECT count(*) AS count FROM otp_challenges
        WHERE network_hash IN (
          SELECT decode(value, 'hex') FROM unnest(
            ${tx.array(networkCandidates.map((hash) => hash.toString("hex")), "text")}::text[]
          ) AS candidate(value)
        )
          AND created_at > now() - (${OTP_WINDOW_MINUTES} * interval '1 minute')`)[0].count);
      if (networkCount >= OTP_NETWORK_WINDOW_LIMIT) {
        throw new AuthError("too many verification requests; try again later", 429, OTP_WINDOW_MINUTES * 60);
      }
    }

    await tx`
      UPDATE otp_challenges SET consumed_at = now()
      WHERE phone_lookup_hash IN (
        SELECT decode(value, 'hex') FROM unnest(
          ${tx.array(lookupCandidates.map((hash) => hash.toString("hex")), "text")}::text[]
        ) AS candidate(value)
      )
        AND consumed_at IS NULL`;
    const codeIndex = codeHashIndex(code, salt);
    return (await tx`
      INSERT INTO otp_challenges
        (phone_lookup_hash, phone_lookup_key_id, code_hash, code_key_id, code_salt,
         network_hash, network_key_id, purpose, expires_at, channel)
      VALUES (${lookup}, ${lookupIndex.keyId}, ${codeIndex.digest}, ${codeIndex.keyId}, ${salt},
              ${networkHash}, ${networkIndex?.keyId ?? null}, ${purpose}, ${expires},
              ${delivery?.channel ?? null})
      RETURNING id`)[0].id;
  });

  if (delivery) {
    try {
      await delivery.send(normalizedPhone, code, purpose);
    } catch (error) {
      await sql`UPDATE otp_challenges SET consumed_at = now() WHERE id = ${challengeId}`;
      console.error(new Date().toISOString(), "auth.otp.delivery_failed",
        error instanceof Error ? error.name : "UnknownError");
      throw new AuthError("verification service temporarily unavailable", 503);
    }
  }

  return returnOTP ? { code, retryAfter: OTP_RESEND_COOLDOWN_SECONDS }
    : { retryAfter: OTP_RESEND_COOLDOWN_SECONDS };
}

export type Session = { accountId: string; deviceId: string; token: string };

export type ProfileDTO = {
  accountId: string;
  username: string | null;
  firstName: string;
  lastName: string;
  displayName: string;
  bio: string;
  birthday: string | null;
  colorIndex: number;
  photo: MediaDTO | null;
  photoRevision: number;
  updatedAt: string;
};

export type UsernameLookupDTO = {
  accountId: string;
  username: string;
  firstName: string;
  lastName: string;
  displayName: string;
  colorIndex: number;
  updatedAt: string;
};

export type ProfilePush = { accountId: string; pts: number; ptsCount: number };

const profileDate = (value: unknown): string | null => {
  if (value == null || value === "") return null;
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value)) {
    throw new AuthError("invalid birthday", 400);
  }
  const parsed = new Date(`${value}T00:00:00.000Z`);
  if (Number.isNaN(parsed.getTime()) || parsed.toISOString().slice(0, 10) !== value) {
    throw new AuthError("invalid birthday", 400);
  }
  const today = new Date().toISOString().slice(0, 10);
  const oldest = new Date();
  oldest.setUTCFullYear(oldest.getUTCFullYear() - 120);
  if (value > today || value < oldest.toISOString().slice(0, 10)) {
    throw new AuthError("invalid birthday", 400);
  }
  return value;
};

export function profileDTO(row: any, photo: MediaDTO | null = null): ProfileDTO {
  const birthday = birthdayString(row.birthday);
  return {
    accountId: row.id,
    username: row.username ?? null,
    firstName: row.first_name,
    lastName: row.last_name,
    displayName: row.display_name,
    bio: row.bio,
    birthday,
    colorIndex: Number(row.profile_color),
    photo,
    photoRevision: Number(row.profile_photo_revision ?? 0),
    updatedAt: row.updated_at instanceof Date ? row.updated_at.toISOString() : String(row.updated_at),
  };
}

function birthdayString(value: unknown): string | null {
  if (value == null) return null;
  return value instanceof Date ? value.toISOString().slice(0, 10) : String(value).slice(0, 10);
}

export async function checkVerification(
  sql: SQL, phone: string, code: string, platform = "ios", deviceName?: string, displayName?: string,
): Promise<Session> {
  const token = randomBytes(32).toString("base64url");
  return await completePhoneVerification(sql, phone, code, displayName, async (tx, accountId) => {
    const factor = await tx`SELECT account_id FROM account_two_factor WHERE account_id = ${accountId}`;
    if (factor.length) {
      throw new AuthError(
        "update Toj to sign in with two-step verification", 426, undefined, "two_factor_client_required",
      );
    }
    const authToken = tokenHashIndex(token);
    const device = await tx`
      INSERT INTO devices (
        account_id, platform, device_name, auth_token_hash, auth_token_key_id, last_seen_at
      )
      VALUES (${accountId}, ${platform}, ${cleanLabel(deviceName, 120)},
              ${authToken.digest}, ${authToken.keyId}, now())
      RETURNING id`;
    return { accountId, deviceId: String(device[0].id), token };
  }, platform);
}

export type AuthV2CheckResponse =
  | { state: "authenticated"; session: AuthV2Session }
  | { state: "two_factor_required"; challengeId: string; expiresAt: string };

export async function checkVerificationV2(
  sql: SQL,
  phone: string,
  code: string,
  platform = "ios",
  deviceName?: string,
  displayName?: string,
): Promise<AuthV2CheckResponse> {
  return await completePhoneVerification(sql, phone, code, displayName, async (tx, accountId) => {
    const factor = await tx`SELECT account_id FROM account_two_factor WHERE account_id = ${accountId}`;
    if (factor.length) {
      const expiresAt = new Date(Date.now() + 5 * 60_000);
      const challenge = (await tx`
        INSERT INTO two_factor_login_challenges
          (account_id, platform, device_name, display_name, expires_at)
        VALUES (
          ${accountId}, ${platform}, ${cleanLabel(deviceName, 120)},
          ${cleanLabel(displayName, 80)}, ${expiresAt}
        ) RETURNING id`)[0];
      return {
        state: "two_factor_required" as const,
        challengeId: String(challenge.id),
        expiresAt: expiresAt.toISOString(),
      };
    }
    const session = await issueV2Session(tx, {
      accountId,
      platform,
      deviceName: cleanLabel(deviceName, 120),
    });
    return { state: "authenticated" as const, session };
  }, platform);
}

async function completePhoneVerification<T>(
  sql: SQL,
  phone: string,
  code: string,
  displayName: string | undefined,
  finish: (tx: SQL, accountId: string) => Promise<T>,
  platform: string,
): Promise<T> {
  const normalizedPhone = validPhone(phone);
  if (!/^\d{6}$/.test(code)) throw new AuthError("enter the 6-digit code", 400);
  if (!ALLOWED_PLATFORMS.has(platform)) throw new AuthError("unsupported device platform", 400);
  const lookupIndex = phoneLookupIndex(normalizedPhone);
  const lookup = lookupIndex.digest;
  const lookupCandidates = phoneLookupCandidates(normalizedPhone).map((candidate) => candidate.digest);
  const result: T | AuthError = await sql.begin(async (tx) => {
    const rows = await tx`
      SELECT id, code_hash, code_key_id, code_salt, attempts FROM otp_challenges
      WHERE phone_lookup_hash IN (
        SELECT decode(value, 'hex') FROM unnest(
          ${tx.array(lookupCandidates.map((hash) => hash.toString("hex")), "text")}::text[]
        ) AS candidate(value)
      )
        AND purpose = 'login'
        AND consumed_at IS NULL AND expires_at > now()
      ORDER BY created_at DESC LIMIT 1
      FOR UPDATE`;
    if (rows.length === 0) throw new AuthError("no active verification code");
    const challenge = rows[0];
    if (challenge.attempts >= OTP_MAX_ATTEMPTS) throw new AuthError("too many attempts; request a new code", 429);
    const expected = codeHashIndex(
      code,
      challenge.code_salt ? Buffer.from(challenge.code_salt) : undefined,
      challenge.code_key_id ?? "legacy-v1",
    ).digest;
    if (!constantTimeEqual(Buffer.from(challenge.code_hash), expected)) {
      await tx`UPDATE otp_challenges SET attempts = attempts + 1 WHERE id = ${challenge.id}`;
      return new AuthError("incorrect code");
    }
    const claimed = await tx`
      UPDATE otp_challenges SET consumed_at = now()
      WHERE id = ${challenge.id} AND consumed_at IS NULL
      RETURNING id`;
    if (claimed.length === 0) throw new AuthError("verification code already used");

    const name = cleanLabel(displayName, 80) ?? "";
    let accountId: string;
    const existing = (await tx`
      SELECT id, status FROM accounts
      WHERE phone_lookup_hash IN (
        SELECT decode(value, 'hex') FROM unnest(
          ${tx.array(lookupCandidates.map((hash) => hash.toString("hex")), "text")}::text[]
        ) AS candidate(value)
      )
      FOR UPDATE`)[0];
    if (!existing) {
      accountId = crypto.randomUUID();
      // Establish the account row before creating its FK-bound DEK. Envelope modes use a
      // service-scoped bootstrap key; the value is replaced in this transaction and never visible.
      const temporary = await sealForScope(
        tx,
        { kind: "service", serviceName: "account-bootstrap" },
        normalizedPhone,
        PHONE_AAD,
      );
      await tx`
        INSERT INTO accounts (
          id, phone_lookup_hash, phone_lookup_key_id,
          phone_e164_ciphertext, phone_nonce, phone_key_id,
          first_name, display_name
        ) VALUES (
          ${accountId}, ${lookup}, ${lookupIndex.keyId},
          ${temporary.ciphertext}, ${temporary.nonce}, ${temporary.keyId},
          ${name}, ${name}
        )`;
      const sealed = await sealForScope(
        tx,
        { kind: "account", accountId },
        normalizedPhone,
        PHONE_AAD,
      );
      await tx`
        UPDATE accounts SET phone_e164_ciphertext = ${sealed.ciphertext},
          phone_nonce = ${sealed.nonce}, phone_key_id = ${sealed.keyId}
        WHERE id = ${accountId}`;
      await tx`INSERT INTO account_sync_states (account_id) VALUES (${accountId}) ON CONFLICT DO NOTHING`;
    } else {
      if (existing.status === "banned" || existing.status === "deleted") {
        return new AuthError("account unavailable", 403);
      }
      accountId = existing.id;
      await tx`
        UPDATE accounts
        SET phone_lookup_hash = ${lookup}, phone_lookup_key_id = ${lookupIndex.keyId},
            first_name = CASE WHEN ${name} <> '' AND first_name = '' AND last_name = ''
              THEN ${name} ELSE first_name END,
            display_name = CASE WHEN ${name} <> '' AND first_name = '' AND last_name = ''
              THEN ${name} ELSE display_name END,
            updated_at = now()
        WHERE id = ${accountId}`;
    }

    return await finish(tx, String(accountId));
  });
  if (result instanceof AuthError) throw result;
  return result;
}

const TWO_FACTOR_MAX_ATTEMPTS = 5;
const TWO_FACTOR_ACCOUNT_WINDOW_LIMIT = 20;
const TWO_FACTOR_NETWORK_WINDOW_LIMIT = 50;
const RECOVERY_ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";

export type TwoFactorLoginResponse = {
  session: AuthV2Session;
  recoveryCodes?: string[];
};

function validateTwoFactorPassword(password: unknown): string {
  if (typeof password !== "string") throw new AuthError("password required", 400);
  const length = Array.from(password).length;
  if (length < 8 || length > 128) {
    throw new AuthError("password must contain 8 to 128 characters", 400);
  }
  if (COMMON_PASSWORDS_V1.has(password.toLocaleLowerCase("en-US"))) {
    throw new AuthError("choose a less common password", 400);
  }
  return password;
}

async function passwordHash(password: string): Promise<string> {
  return await Bun.password.hash(password, {
    algorithm: "argon2id",
    memoryCost: 19_456,
    timeCost: 2,
  });
}

function recoveryCode(): string {
  const bytes = randomBytes(10);
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += RECOVERY_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  return output.match(/.{1,4}/g)!.join("-");
}

function normalizedRecoveryCode(value: unknown): string {
  if (typeof value !== "string") return "";
  return value.toUpperCase().replace(/[^2-9A-HJ-NP-Z]/g, "");
}

function recoveryCodeInput(accountId: string, value: string): string {
  return `toj/recovery/v1|${accountId}|${value}`;
}

async function replaceRecoveryCodes(sql: SQL, accountId: string): Promise<string[]> {
  const codes = Array.from({ length: 10 }, recoveryCode);
  await sql`DELETE FROM two_factor_recovery_codes WHERE account_id = ${accountId}`;
  for (const code of codes) {
    const index = tokenHashIndex(recoveryCodeInput(accountId, normalizedRecoveryCode(code)));
    await sql`
      INSERT INTO two_factor_recovery_codes (account_id, code_hash, code_key_id)
      VALUES (${accountId}, ${index.digest}, ${index.keyId})`;
  }
  return codes;
}

async function revokeOtherAccountDevices(sql: SQL, accountId: string, keepDeviceId?: string): Promise<string[]> {
  await sql`SELECT id FROM accounts WHERE id = ${accountId} FOR UPDATE`;
  const rows = await sql`
    UPDATE devices SET
      revoked_at = COALESCE(revoked_at, now()),
      push_token_hash = NULL, push_token_hash_key_id = NULL,
      push_token_ciphertext = NULL, push_token_nonce = NULL,
      push_token_key_id = NULL, push_environment = NULL, push_updated_at = now(),
      voip_push_token_hash = NULL, voip_push_token_hash_key_id = NULL,
      voip_push_token_ciphertext = NULL,
      voip_push_token_nonce = NULL, voip_push_token_key_id = NULL,
      voip_push_environment = NULL, voip_push_updated_at = now()
    WHERE account_id = ${accountId} AND revoked_at IS NULL
      AND (${keepDeviceId ?? null}::uuid IS NULL OR id <> ${keepDeviceId ?? null}::uuid)
    RETURNING id`;
  if (rows.length) await sql`
    UPDATE device_sessions SET revoked_at = COALESCE(revoked_at, now()), revocation_reason = 'security_change'
    WHERE device_id IN ${sql(rows.map((row) => String(row.id)))}`;
  for (const row of rows) {
    await revokePushBindingsForDevice(sql, String(row.id));
    await notifySessionRevocation(sql, accountId, String(row.id), "security_change");
  }
  return rows.map((row) => String(row.id));
}

export async function completeTwoFactorLogin(
  sql: SQL,
  input: {
    challengeId: string;
    password?: string;
    recoveryCode?: string;
    newPassword?: string;
    networkKey?: string | null;
  },
): Promise<TwoFactorLoginResponse> {
  const result = await sql.begin(async (tx) => {
    const challenge = (await tx`
      SELECT * FROM two_factor_login_challenges
      WHERE id = ${input.challengeId} AND consumed_at IS NULL AND expires_at > now()
      FOR UPDATE`)[0];
    if (!challenge) return new AuthError("two-step challenge expired", 401, undefined, "challenge_expired");
    if (Number(challenge.attempts) >= TWO_FACTOR_MAX_ATTEMPTS) {
      return new AuthError("too many attempts; request a new SMS code", 429, undefined, "challenge_locked");
    }
    const accountId = String(challenge.account_id);
    const accountBudgetLocks = tokenHashCandidates(`two-factor-account|${accountId}`)
      .map((candidate) => candidate.digest.readBigInt64BE(0))
      .sort((left, right) => left < right ? -1 : left > right ? 1 : 0);
    for (const lock of accountBudgetLocks) await tx`SELECT pg_advisory_xact_lock(${lock})`;
    const networkInput = input.networkKey ? `two-factor-network|${input.networkKey}` : null;
    const networkCandidates = networkInput ? tokenHashCandidates(networkInput) : [];
    const networkIndex = networkInput ? tokenHashIndex(networkInput) : null;
    const networkLocks = networkCandidates
      .map((candidate) => candidate.digest.readBigInt64BE(0))
      .sort((left, right) => left < right ? -1 : left > right ? 1 : 0);
    for (const lock of networkLocks) await tx`SELECT pg_advisory_xact_lock(${lock})`;
    const accountAttempts = Number((await tx`
      SELECT count(*) AS count FROM two_factor_attempt_budgets
      WHERE account_id = ${accountId} AND accepted_at > now() - interval '15 minutes'`)[0].count);
    if (accountAttempts >= TWO_FACTOR_ACCOUNT_WINDOW_LIMIT) {
      return new AuthError("too many two-step attempts; try again later", 429, 900, "challenge_locked");
    }
    if (networkCandidates.length) {
      const networkAttempts = Number((await tx`
        SELECT count(*) AS count FROM two_factor_attempt_budgets
        WHERE network_hash IN (
          SELECT decode(value, 'hex') FROM unnest(
            ${tx.array(networkCandidates.map((candidate) => candidate.digest.toString("hex")), "text")}::text[]
          ) AS candidate(value)
        ) AND accepted_at > now() - interval '15 minutes'`)[0].count);
      if (networkAttempts >= TWO_FACTOR_NETWORK_WINDOW_LIMIT) {
        return new AuthError("too many two-step attempts; try again later", 429, 900, "challenge_locked");
      }
    }
    await tx`
      INSERT INTO two_factor_attempt_budgets (account_id, network_hash, network_key_id)
      VALUES (${accountId}, ${networkIndex?.digest ?? null}, ${networkIndex?.keyId ?? null})`;
    const factor = (await tx`
      SELECT password_hash FROM account_two_factor WHERE account_id = ${accountId} FOR UPDATE`)[0];
    if (!factor) return new AuthError("two-step verification is no longer enabled", 409, undefined, "factor_changed");

    let recoveryCodes: string[] | undefined;
    let accepted = false;
    if (input.password !== undefined) {
      accepted = await Bun.password.verify(input.password, String(factor.password_hash));
    } else {
      const normalized = normalizedRecoveryCode(input.recoveryCode);
      const recoveryCandidates = normalized.length === 16
        ? tokenHashCandidates(recoveryCodeInput(accountId, normalized))
        : [];
      const recovery = normalized.length === 16 ? (await tx`
        SELECT id FROM two_factor_recovery_codes
        WHERE account_id = ${accountId}
          AND code_hash IN (
            SELECT decode(value, 'hex') FROM unnest(
              ${tx.array(recoveryCandidates.map((candidate) => candidate.digest.toString("hex")), "text")}::text[]
            ) AS candidate(value)
          )
          AND consumed_at IS NULL
        FOR UPDATE`)[0] : null;
      if (recovery) {
        const replacement = validateTwoFactorPassword(input.newPassword);
        const nextHash = await passwordHash(replacement);
        await tx`UPDATE two_factor_recovery_codes SET consumed_at = now() WHERE id = ${recovery.id}`;
        await tx`
          UPDATE account_two_factor SET password_hash = ${nextHash}, updated_at = now()
          WHERE account_id = ${accountId}`;
        recoveryCodes = await replaceRecoveryCodes(tx, accountId);
        await revokeOtherAccountDevices(tx, accountId);
        accepted = true;
      }
    }
    if (!accepted) {
      await tx`
        UPDATE two_factor_login_challenges SET attempts = attempts + 1
        WHERE id = ${challenge.id}`;
      if (Number(challenge.attempts) + 1 >= TWO_FACTOR_MAX_ATTEMPTS) {
        return new AuthError("too many attempts; request a new SMS code", 429, undefined, "challenge_locked");
      }
      return new AuthError("incorrect password or recovery code", 401, undefined, "incorrect_second_factor");
    }
    const claimed = await tx`
      UPDATE two_factor_login_challenges SET consumed_at = now()
      WHERE id = ${challenge.id} AND consumed_at IS NULL RETURNING id`;
    if (!claimed.length) return new AuthError("two-step challenge already used", 401, undefined, "challenge_used");
    const session = await issueV2Session(tx, {
      accountId,
      platform: String(challenge.platform),
      deviceName: challenge.device_name ? String(challenge.device_name) : null,
    });
    return { session, ...(recoveryCodes ? { recoveryCodes } : {}) };
  });
  if (result instanceof AuthError) throw result;
  return result;
}

export async function twoFactorStatus(sql: SQL, accountId: string): Promise<{ enabled: boolean; recoveryCodesRemaining: number }> {
  const row = (await sql`
    SELECT factor.account_id,
           count(code.id) FILTER (WHERE code.consumed_at IS NULL) AS remaining
    FROM account_two_factor factor
    LEFT JOIN two_factor_recovery_codes code ON code.account_id = factor.account_id
    WHERE factor.account_id = ${accountId}
    GROUP BY factor.account_id`)[0];
  return { enabled: Boolean(row), recoveryCodesRemaining: row ? Number(row.remaining) : 0 };
}

export async function startSecurityChange(
  sql: SQL,
  accountId: string,
  options: StartVerificationOptions = {},
): Promise<{ code?: string; retryAfter?: number }> {
  const account = (await sql`
    SELECT phone_e164_ciphertext, phone_nonce, phone_key_id, status
    FROM accounts WHERE id = ${accountId}`)[0];
  if (!account || !["active", "limited"].includes(String(account.status))) {
    throw new AuthError("account unavailable", 403);
  }
  const phone = (await openForScope(sql, { kind: "account", accountId }, {
    ciphertext: Buffer.from(account.phone_e164_ciphertext),
    nonce: Buffer.from(account.phone_nonce),
    keyId: String(account.phone_key_id),
  }, PHONE_AAD)).toString("utf8");
  return await startVerification(sql, phone, { ...options, purpose: "security_change" });
}

export async function completeSecurityStepUp(
  sql: SQL,
  accountId: string,
  code: string,
): Promise<{ stepUpToken: string; expiresAt: string }> {
  if (!/^\d{6}$/.test(code)) throw new AuthError("enter the 6-digit code", 400);
  const account = (await sql`
    SELECT phone_e164_ciphertext, phone_nonce, phone_key_id
    FROM accounts WHERE id = ${accountId}`)[0];
  if (!account) throw new AuthError("account unavailable", 403);
  const phone = (await openForScope(sql, { kind: "account", accountId }, {
    ciphertext: Buffer.from(account.phone_e164_ciphertext), nonce: Buffer.from(account.phone_nonce),
    keyId: String(account.phone_key_id),
  }, PHONE_AAD)).toString("utf8");
  const lookupCandidates = phoneLookupCandidates(phone).map((candidate) => candidate.digest);
  const ticket = randomBytes(32).toString("base64url");
  const expiresAt = new Date(Date.now() + 10 * 60_000);
  const result = await sql.begin(async (tx) => {
    const challenge = (await tx`
      SELECT id, code_hash, code_key_id, code_salt, attempts FROM otp_challenges
      WHERE phone_lookup_hash IN (
        SELECT decode(value, 'hex') FROM unnest(
          ${tx.array(lookupCandidates.map((hash) => hash.toString("hex")), "text")}::text[]
        ) AS candidate(value)
      )
        AND purpose = 'security_change'
        AND consumed_at IS NULL AND expires_at > now()
      ORDER BY created_at DESC LIMIT 1 FOR UPDATE`)[0];
    if (!challenge) return new AuthError("no active security code", 401);
    if (Number(challenge.attempts) >= TWO_FACTOR_MAX_ATTEMPTS) {
      return new AuthError(
        "too many attempts; request a new security code",
        429,
        undefined,
        "challenge_locked",
      );
    }
    const expected = codeHashIndex(
      code,
      challenge.code_salt ? Buffer.from(challenge.code_salt) : undefined,
      challenge.code_key_id ?? "legacy-v1",
    ).digest;
    if (!constantTimeEqual(Buffer.from(challenge.code_hash), expected)) {
      await tx`UPDATE otp_challenges SET attempts = attempts + 1 WHERE id = ${challenge.id}`;
      if (Number(challenge.attempts) + 1 >= TWO_FACTOR_MAX_ATTEMPTS) {
        return new AuthError(
          "too many attempts; request a new security code",
          429,
          undefined,
          "challenge_locked",
        );
      }
      return new AuthError("incorrect code", 401);
    }
    await tx`UPDATE otp_challenges SET consumed_at = now() WHERE id = ${challenge.id}`;
    const ticketIndex = tokenHashIndex(ticket);
    await tx`
      INSERT INTO security_step_up_tickets (account_id, token_hash, token_key_id, expires_at)
      VALUES (${accountId}, ${ticketIndex.digest}, ${ticketIndex.keyId}, ${expiresAt})`;
    return { stepUpToken: ticket, expiresAt: expiresAt.toISOString() };
  });
  if (result instanceof AuthError) throw result;
  return result;
}

async function requireStepUp(
  sql: SQL,
  accountId: string,
  tokenValue: unknown,
): Promise<{ id: string } | AuthError> {
  if (typeof tokenValue !== "string") {
    return new AuthError("security verification required", 401, undefined, "step_up_expired");
  }
  const candidates = tokenHashCandidates(tokenValue);
  const ticket = (await sql`
    SELECT id, attempts FROM security_step_up_tickets
    WHERE account_id = ${accountId} AND token_hash IN (
      SELECT decode(value, 'hex') FROM unnest(
        ${sql.array(candidates.map((candidate) => candidate.digest.toString("hex")), "text")}::text[]
      ) AS candidate(value)
    )
      AND consumed_at IS NULL AND expires_at > now()
    FOR UPDATE`)[0];
  if (!ticket) return new AuthError("security verification expired", 401, undefined, "step_up_expired");
  if (Number(ticket.attempts) >= TWO_FACTOR_MAX_ATTEMPTS) {
    return new AuthError("too many attempts; request a new security code", 429, undefined, "challenge_locked");
  }
  return { id: String(ticket.id) };
}

/**
 * Revoking another device is destructive and, until now, needed nothing but a bearer token: the
 * bulk revoke is two-factor gated, but iterating `DELETE /v1/devices/{id}` reached the same end
 * state ungated. Whenever an aggregate operation is security-gated, check whether iterating its
 * single-item equivalent gets there too.
 *
 * The gate is a step-up ticket, demanded only when the account actually has a second factor —
 * without one there is nothing to ask for, and requiring a phone code instead would put a paid
 * OTP in front of an ordinary action. That is the argument for enrolling two-step, not for
 * inventing a weaker gate here.
 *
 * The ticket is validated but deliberately **not** consumed. Cleaning up several stale devices is
 * one intent, and its own TTL already bounds the window; spending a ticket per device would make
 * an honest user re-verify for each one.
 */
export async function requireDeviceRevocationStepUp(
  sql: SQL,
  accountId: string,
  stepUpToken: unknown,
): Promise<void> {
  const result = await sql.begin(async (tx) => {
    const factor = (await tx`
      SELECT account_id FROM account_two_factor WHERE account_id = ${accountId}`)[0];
    if (!factor) return null;
    const ticket = await requireStepUp(tx, accountId, stepUpToken);
    return ticket instanceof AuthError ? ticket : null;
  });
  if (result instanceof AuthError) throw result;
}

async function verifyCurrentFactor(
  sql: SQL,
  accountId: string,
  credential: unknown,
): Promise<boolean> {
  const factor = (await sql`
    SELECT password_hash FROM account_two_factor WHERE account_id = ${accountId} FOR UPDATE`)[0];
  if (!factor) return true;
  if (typeof credential === "string" && await Bun.password.verify(credential, String(factor.password_hash))) {
    return true;
  }
  const normalized = normalizedRecoveryCode(credential);
  const recoveryCandidates = normalized.length === 16
    ? tokenHashCandidates(recoveryCodeInput(accountId, normalized))
    : [];
  const recovered = normalized.length === 16 ? await sql`
    UPDATE two_factor_recovery_codes SET consumed_at = now()
    WHERE account_id = ${accountId} AND code_hash IN (
      SELECT decode(value, 'hex') FROM unnest(
        ${sql.array(recoveryCandidates.map((candidate) => candidate.digest.toString("hex")), "text")}::text[]
      ) AS candidate(value)
    )
      AND consumed_at IS NULL RETURNING id` : [];
  return recovered.length > 0;
}

export async function configureTwoFactor(
  sql: SQL,
  input: {
    accountId: string;
    currentDeviceId: string;
    stepUpToken: string;
    password: string;
    currentCredential?: string;
  },
): Promise<{ enabled: true; recoveryCodes: string[]; session: AuthV2Session; revokedDeviceIds: string[] }> {
  const nextPassword = validateTwoFactorPassword(input.password);
  const result = await sql.begin(async (tx) => {
    const ticket = await requireStepUp(tx, input.accountId, input.stepUpToken);
    if (ticket instanceof AuthError) return ticket;
    if (!await verifyCurrentFactor(tx, input.accountId, input.currentCredential)) {
      await tx`UPDATE security_step_up_tickets SET attempts = attempts + 1 WHERE id = ${ticket.id}`;
      return new AuthError(
        "current password or recovery code is incorrect",
        401,
        undefined,
        "incorrect_second_factor",
      );
    }
    const nextHash = await passwordHash(nextPassword);
    await tx`UPDATE security_step_up_tickets SET consumed_at = now() WHERE id = ${ticket.id}`;
    await tx`
      INSERT INTO account_two_factor (account_id, password_hash)
      VALUES (${input.accountId}, ${nextHash})
      ON CONFLICT (account_id) DO UPDATE SET password_hash = EXCLUDED.password_hash, updated_at = now()`;
    const recoveryCodes = await replaceRecoveryCodes(tx, input.accountId);
    const revokedDeviceIds = await revokeOtherAccountDevices(tx, input.accountId, input.currentDeviceId);
    const session = await issueV2Session(tx, {
      accountId: input.accountId, platform: "ios", existingDeviceId: input.currentDeviceId,
    });
    return { enabled: true as const, recoveryCodes, session, revokedDeviceIds };
  });
  if (result instanceof AuthError) throw result;
  return result;
}

export async function regenerateTwoFactorRecoveryCodes(
  sql: SQL,
  input: {
    accountId: string;
    currentDeviceId: string;
    stepUpToken: string;
    currentCredential: string;
  },
): Promise<{ enabled: true; recoveryCodes: string[]; session: AuthV2Session; revokedDeviceIds: string[] }> {
  const result = await sql.begin(async (tx) => {
    const ticket = await requireStepUp(tx, input.accountId, input.stepUpToken);
    if (ticket instanceof AuthError) return ticket;
    const factor = await tx`
      SELECT account_id FROM account_two_factor WHERE account_id = ${input.accountId} FOR UPDATE`;
    if (!factor.length) {
      return new AuthError("two-step verification is not enabled", 409, undefined, "factor_changed");
    }
    if (!await verifyCurrentFactor(tx, input.accountId, input.currentCredential)) {
      await tx`UPDATE security_step_up_tickets SET attempts = attempts + 1 WHERE id = ${ticket.id}`;
      return new AuthError(
        "current password or recovery code is incorrect",
        401,
        undefined,
        "incorrect_second_factor",
      );
    }
    await tx`UPDATE security_step_up_tickets SET consumed_at = now() WHERE id = ${ticket.id}`;
    const recoveryCodes = await replaceRecoveryCodes(tx, input.accountId);
    const revokedDeviceIds = await revokeOtherAccountDevices(tx, input.accountId, input.currentDeviceId);
    const session = await issueV2Session(tx, {
      accountId: input.accountId, platform: "ios", existingDeviceId: input.currentDeviceId,
    });
    return { enabled: true as const, recoveryCodes, session, revokedDeviceIds };
  });
  if (result instanceof AuthError) throw result;
  return result;
}

export async function disableTwoFactor(
  sql: SQL,
  input: { accountId: string; currentDeviceId: string; stepUpToken: string; currentCredential: string },
): Promise<{ enabled: false; session: AuthV2Session; revokedDeviceIds: string[] }> {
  const result = await sql.begin(async (tx) => {
    const ticket = await requireStepUp(tx, input.accountId, input.stepUpToken);
    if (ticket instanceof AuthError) return ticket;
    if (!await verifyCurrentFactor(tx, input.accountId, input.currentCredential)) {
      await tx`UPDATE security_step_up_tickets SET attempts = attempts + 1 WHERE id = ${ticket.id}`;
      return new AuthError(
        "current password or recovery code is incorrect",
        401,
        undefined,
        "incorrect_second_factor",
      );
    }
    await tx`UPDATE security_step_up_tickets SET consumed_at = now() WHERE id = ${ticket.id}`;
    await tx`DELETE FROM two_factor_recovery_codes WHERE account_id = ${input.accountId}`;
    await tx`DELETE FROM account_two_factor WHERE account_id = ${input.accountId}`;
    const revokedDeviceIds = await revokeOtherAccountDevices(tx, input.accountId, input.currentDeviceId);
    const session = await issueV2Session(tx, {
      accountId: input.accountId, platform: "ios", existingDeviceId: input.currentDeviceId,
    });
    return { enabled: false as const, session, revokedDeviceIds };
  });
  if (result instanceof AuthError) throw result;
  return result;
}

/** Best-effort non-secret alert. Provider failure never rolls back the committed security change. */
export async function sendSecurityChangeAlert(
  sql: SQL,
  accountId: string,
  event: SecurityChangeEvent,
  delivery: OTPDelivery | null,
): Promise<void> {
  try {
    await sql.begin(async (tx) => {
      const state = (await tx`
        UPDATE account_sync_states SET pts = pts + 1, updated_at = now()
        WHERE account_id = ${accountId}
        RETURNING pts`)[0];
      if (!state) return;
      const pts = Number(state.pts);
      await tx`
        INSERT INTO account_events (account_id, pts, type, actor_account_id, data)
        VALUES (
          ${accountId}, ${pts}, 'security.changed', ${accountId},
          ${JSON.stringify({ event })}::text::jsonb
        )`;
      await enqueuePushDeliveries(tx, {
        accountId,
        pts,
        senderAccountId: accountId,
        forceAlert: true,
      });
      await notifySyncWakeups(tx, [{ accountId, pts, ptsCount: 1 }]);
    });
  } catch (error) {
    console.error(new Date().toISOString(), "auth.security_alert.push_failed",
      error instanceof Error ? error.name : "UnknownError");
  }

  if (!delivery?.sendSecurityAlert) return;
  try {
    const account = (await sql`
      SELECT phone_e164_ciphertext, phone_nonce, phone_key_id
      FROM accounts WHERE id = ${accountId}`)[0];
    if (!account) return;
    const phone = (await openForScope(sql, { kind: "account", accountId }, {
      ciphertext: Buffer.from(account.phone_e164_ciphertext),
      nonce: Buffer.from(account.phone_nonce),
      keyId: String(account.phone_key_id),
    }, PHONE_AAD)).toString("utf8");
    await delivery.sendSecurityAlert(phone, event);
  } catch (error) {
    console.error(new Date().toISOString(), "auth.security_alert.sms_failed",
      error instanceof Error ? error.name : "UnknownError");
  }
}

/** Contact discovery: resolve a phone number to an account so the client can open a direct dialog. */
export async function lookupAccountByPhone(
  sql: SQL, requesterAccountId: string, phone: string,
): Promise<ProfileDTO | null> {
  const normalizedPhone = validPhone(phone);
  const targetIndex = phoneLookupIndex(normalizedPhone);
  const targetHash = targetIndex.digest;
  const targetHashes = phoneLookupCandidates(normalizedPhone).map((candidate) => candidate.digest);
  return await sql.begin(async (tx) => {
    await tx`SELECT pg_advisory_xact_lock(hashtextextended(${`contact-lookup:${requesterAccountId}`}, 0))`;
    const requester = await tx`
      SELECT id FROM accounts WHERE id = ${requesterAccountId} AND status IN ('active','limited')`;
    if (!requester.length) throw new AuthError("account unavailable", 403);

    // Network retries and reopening the same contact do not burn more discovery budget.
    const repeated = await tx`
      SELECT 1 FROM contact_lookup_attempts
      WHERE requester_account_id = ${requesterAccountId}
        AND target_phone_hash IN (
          SELECT decode(value, 'hex') FROM unnest(
            ${tx.array(targetHashes.map((hash) => hash.toString("hex")), "text")}::text[]
          ) AS candidate(value)
        )
        AND created_at > now() - (${CONTACT_LOOKUP_WINDOW_MINUTES} * interval '1 minute')
      LIMIT 1`;
    if (!repeated.length) {
      const counts = (await tx`
        SELECT
          count(*) FILTER (WHERE created_at > now() - (${CONTACT_LOOKUP_WINDOW_MINUTES} * interval '1 minute')) AS recent,
          count(*) FILTER (WHERE created_at > now() - interval '24 hours') AS daily
        FROM contact_lookup_attempts WHERE requester_account_id = ${requesterAccountId}`)[0];
      if (Number(counts.recent) >= CONTACT_LOOKUP_WINDOW_LIMIT || Number(counts.daily) >= CONTACT_LOOKUP_DAILY_LIMIT) {
        throw new AuthError("contact discovery limit reached; try again later", 429, CONTACT_LOOKUP_WINDOW_MINUTES * 60);
      }
    }

    const row = (await tx`
      SELECT id, username, first_name, last_name, display_name, bio, birthday, profile_color, updated_at FROM accounts
      WHERE phone_lookup_hash IN (
        SELECT decode(value, 'hex') FROM unnest(
          ${tx.array(targetHashes.map((hash) => hash.toString("hex")), "text")}::text[]
        ) AS candidate(value)
      )
        AND status IN ('active','limited')`)[0];
    if (!repeated.length) {
      await tx`
        INSERT INTO contact_lookup_attempts (
          requester_account_id, target_phone_hash, target_phone_key_id
        ) VALUES (${requesterAccountId}, ${targetHash}, ${targetIndex.keyId})`;
    }
    return row ? profileDTO(row) : null;
  });
}

/** Return the canonical account profile for this authenticated account. */
export async function getProfile(sql: SQL, accountId: string): Promise<ProfileDTO> {
  const row = (await sql`
    SELECT id, username, first_name, last_name, display_name, bio, birthday, profile_color,
           profile_photo_media_id, profile_photo_revision, updated_at
    FROM accounts WHERE id = ${accountId} AND status IN ('active','limited')`)[0];
  if (!row) throw new AuthError("account unavailable", 403);
  return profileDTO(row, await loadMediaDTO(sql, row.profile_photo_media_id));
}

export async function fanoutProfileUpdate(
  tx: SQL,
  accountId: string,
  deviceId: string,
  profile: ProfileDTO,
): Promise<ProfilePush[]> {
  const recipientRows = await tx`
    WITH recipients AS (
      SELECT DISTINCT peer.account_id
      FROM dialog_members mine
      JOIN dialog_members peer ON peer.dialog_id = mine.dialog_id AND peer.left_at IS NULL
      JOIN dialogs dialog ON dialog.id = mine.dialog_id AND dialog.closed_at IS NULL
      WHERE mine.account_id = ${accountId} AND mine.left_at IS NULL
      UNION SELECT ${accountId}::uuid AS account_id
    ), shared_direct_dialogs AS (
      SELECT peer.account_id,
             jsonb_agg(DISTINCT mine.dialog_id ORDER BY mine.dialog_id) AS dialog_ids
      FROM dialog_members mine
      JOIN dialog_members peer
        ON peer.dialog_id = mine.dialog_id
       AND peer.account_id <> ${accountId}
       AND peer.left_at IS NULL
      JOIN dialogs dialog
        ON dialog.id = mine.dialog_id
       AND dialog.type = 'direct'
       AND dialog.closed_at IS NULL
      WHERE mine.account_id = ${accountId} AND mine.left_at IS NULL
      GROUP BY peer.account_id
    )
    SELECT recipient.account_id,
           COALESCE(shared.dialog_ids, '[]'::jsonb) AS shared_dialog_ids
    FROM recipients recipient
    LEFT JOIN shared_direct_dialogs shared ON shared.account_id = recipient.account_id
    ORDER BY recipient.account_id`;
  const recipients = recipientRows.map((row) => String(row.account_id));
  const baseData = {
    subject_account_id: profile.accountId,
    username: profile.username,
    first_name: profile.firstName,
    last_name: profile.lastName,
    display_name: profile.displayName,
    bio: profile.bio,
    birthday: profile.birthday,
    color_index: profile.colorIndex,
    photo: profile.photo,
    photo_revision: profile.photoRevision,
    updated_at: profile.updatedAt,
  };
  // Keep lock acquisition deterministic while advancing every recipient in one set-based write.
  await tx`
    SELECT account_id FROM account_sync_states
    WHERE account_id = ANY(${tx.array(recipients, "uuid")}::uuid[])
    ORDER BY account_id FOR UPDATE`;
  const stateRows = await tx`
    UPDATE account_sync_states
    SET pts = pts + 1, updated_at = now()
    WHERE account_id = ANY(${tx.array(recipients, "uuid")}::uuid[])
    RETURNING account_id, pts`;
  if (stateRows.length !== recipients.length) {
    throw new AuthError("profile recipient state unavailable", 503);
  }
  const sharedByAccount = new Map(recipientRows.map((row) => [
    String(row.account_id),
    (row.shared_dialog_ids ?? []).map(String),
  ]));
  const eventRows = stateRows.map((state) => ({
    account_id: String(state.account_id),
    pts: Number(state.pts),
    data: {
      ...baseData,
      shared_dialog_ids: sharedByAccount.get(String(state.account_id)) ?? [],
    },
  })).sort((left, right) => left.account_id.localeCompare(right.account_id));
  const encodedRows = JSON.stringify(eventRows);
  await tx`
    INSERT INTO account_events (account_id, pts, type, actor_account_id, data)
    SELECT event.account_id, event.pts, 'profile.updated', ${accountId}, event.data
    FROM jsonb_to_recordset(${encodedRows}::text::jsonb)
      AS event(account_id uuid, pts bigint, data jsonb)`;
  await tx`
    INSERT INTO push_deliveries (account_id, pts, device_id, alert)
    SELECT event.account_id, event.pts, device.id, false
    FROM jsonb_to_recordset(${encodedRows}::text::jsonb)
      AS event(account_id uuid, pts bigint, data jsonb)
    JOIN devices device ON device.account_id = event.account_id
    WHERE device.platform = 'ios'
      AND device.revoked_at IS NULL
      AND device.push_token_hash IS NOT NULL
      AND device.push_token_ciphertext IS NOT NULL
      AND device.id <> ${deviceId}
    ON CONFLICT (account_id, pts, device_id) DO NOTHING`;
  return eventRows.map((event) => ({
    accountId: event.account_id,
    pts: event.pts,
    ptsCount: 1,
  }));
}

/** Persist a profile and fan a silent sync event out to every device and active chat partner. */
export async function updateProfile(
  sql: SQL,
  accountId: string,
  deviceId: string,
  input: { username?: unknown; firstName?: unknown; lastName?: unknown; bio?: unknown; birthday?: unknown; colorIndex?: unknown },
): Promise<{ profile: ProfileDTO; pushes: ProfilePush[] }> {
  const hasUsername = Object.prototype.hasOwnProperty.call(input, "username");
  if (hasUsername && input.username !== null && typeof input.username !== "string") {
    throw new AuthError("username must be a string or null", 400);
  }
  const requestedUsername = hasUsername
    ? (typeof input.username === "string" ? input.username.trim().toLowerCase() : "") || null
    : undefined;
  if (requestedUsername && (!/^[a-z][a-z0-9_]{4,31}$/.test(requestedUsername)
    || new Set(["admin", "support", "settings", "login", "tojapp"]).has(requestedUsername))) {
    throw new AuthError("username must start with a letter and contain 5-32 letters, numbers, or underscores", 400);
  }
  const firstName = typeof input.firstName === "string" ? input.firstName.trim().slice(0, 48) : "";
  const lastName = typeof input.lastName === "string" ? input.lastName.trim().slice(0, 48) : "";
  const bio = typeof input.bio === "string" ? input.bio.trim().slice(0, 120) : "";
  const birthday = profileDate(input.birthday);
  const colorIndex = Number(input.colorIndex);
  if (!firstName) throw new AuthError("first name required", 400);
  if (!Number.isSafeInteger(colorIndex) || colorIndex < 0 || colorIndex > 7) {
    throw new AuthError("invalid profile color", 400);
  }
  const displayName = [firstName, lastName].filter(Boolean).join(" ");
  try {
    return await sql.begin(async (tx) => {
    const current = (await tx`
      SELECT id, username, first_name, last_name, display_name, bio, birthday, profile_color,
             profile_photo_media_id, profile_photo_revision, updated_at
      FROM accounts WHERE id = ${accountId} AND status IN ('active','limited') FOR UPDATE`)[0];
    if (!current) throw new AuthError("account unavailable", 403);
    await requireActiveDevice(tx, accountId, deviceId);
    // Username was added after the profile endpoint shipped. Older clients omit the key, so
    // absence must mean "preserve"; explicit null/empty string remains the clear operation.
    const username = requestedUsername === undefined
      ? (current.username == null ? null : String(current.username))
      : requestedUsername;
    const currentBirthday = birthdayString(current.birthday);
    const changed = (current.username ?? null) !== username
      || current.first_name !== firstName || current.last_name !== lastName
      || current.bio !== bio || currentBirthday !== birthday || Number(current.profile_color) !== colorIndex;
    if (!changed) {
      return {
        profile: profileDTO(current, await loadMediaDTO(tx, current.profile_photo_media_id)),
        pushes: [],
      };
    }

    const updated = (await tx`
      UPDATE accounts SET username = ${username}, first_name = ${firstName}, last_name = ${lastName},
        display_name = ${displayName}, bio = ${bio}, birthday = ${birthday}::date,
        profile_color = ${colorIndex}, updated_at = now()
      WHERE id = ${accountId}
      RETURNING id, username, first_name, last_name, display_name, bio, birthday, profile_color,
                profile_photo_media_id, profile_photo_revision, updated_at`)[0];

    const profile = profileDTO(updated, await loadMediaDTO(tx, updated.profile_photo_media_id));
    const pushes = await fanoutProfileUpdate(tx, accountId, deviceId, profile);
    return { profile, pushes };
    });
  } catch (error: any) {
    const duplicateCode = error?.code === "23505" || error?.errno === "23505";
    const duplicateUsername = `${error?.constraint ?? ""} ${error?.message ?? ""}`.includes("username");
    if (duplicateCode && duplicateUsername) {
      throw new AuthError("username is already taken", 409);
    }
    throw error;
  }
}

/** Public-handle lookup with the same abuse budget as contact discovery. */
export async function lookupAccountByUsername(
  sql: SQL, requesterAccountId: string, value: unknown,
): Promise<UsernameLookupDTO | null> {
  const username = typeof value === "string" ? value.trim().toLowerCase().replace(/^@/, "") : "";
  if (!/^[a-z][a-z0-9_]{4,31}$/.test(username)) return null;
  const target = tokenHashIndex(`username:${username}`);
  const targetCandidates = tokenHashCandidates(`username:${username}`).map((entry) => entry.digest);
  return await sql.begin(async (tx) => {
    await tx`SELECT pg_advisory_xact_lock(hashtextextended(${`contact-lookup:${requesterAccountId}`}, 0))`;
    const repeated = await tx`
      SELECT 1 FROM contact_lookup_attempts
      WHERE requester_account_id = ${requesterAccountId} AND target_phone_hash IN (
        SELECT decode(value, 'hex') FROM unnest(
          ${tx.array(targetCandidates.map((digest) => digest.toString("hex")), "text")}::text[]
        ) candidate(value)
      )
        AND created_at > now() - (${CONTACT_LOOKUP_WINDOW_MINUTES} * interval '1 minute') LIMIT 1`;
    if (!repeated.length) {
      const counts = (await tx`
        SELECT count(*) FILTER (WHERE created_at > now() - (${CONTACT_LOOKUP_WINDOW_MINUTES} * interval '1 minute')) AS recent,
          count(*) FILTER (WHERE created_at > now() - interval '24 hours') AS daily
        FROM contact_lookup_attempts WHERE requester_account_id = ${requesterAccountId}`)[0];
      if (Number(counts.recent) >= CONTACT_LOOKUP_WINDOW_LIMIT || Number(counts.daily) >= CONTACT_LOOKUP_DAILY_LIMIT) {
        throw new AuthError("contact discovery limit reached; try again later", 429, CONTACT_LOOKUP_WINDOW_MINUTES * 60);
      }
      await tx`INSERT INTO contact_lookup_attempts (
        requester_account_id, target_phone_hash, target_phone_key_id
      ) VALUES (${requesterAccountId}, ${target.digest}, ${target.keyId})`;
    }
    const row = (await tx`
      SELECT id, username, first_name, last_name, display_name, profile_color, updated_at
      FROM accounts WHERE lower(username) = ${username} AND status IN ('active','limited')`)[0];
    if (!row) return null;
    return {
      accountId: row.id,
      username: row.username,
      firstName: row.first_name,
      lastName: row.last_name,
      displayName: row.display_name,
      colorIndex: Number(row.profile_color),
      updatedAt: row.updated_at instanceof Date ? row.updated_at.toISOString() : String(row.updated_at),
    };
  });
}

export async function resolveDevice(
  sql: SQL,
  token: string,
): Promise<{ accountId: string; deviceId: string; accessExpiresAt?: string }> {
  if (isV2AccessToken(token)) {
    const v2 = await resolveV2Access(sql, token);
    if (!v2) throw new AuthError("invalid device token", 401, undefined, "device_revoked");
    return {
      accountId: v2.accountId,
      deviceId: v2.deviceId,
      accessExpiresAt: v2.accessExpiresAt.toISOString(),
    };
  }
  const tokenHashes = tokenHashCandidates(token).map((candidate) => candidate.digest);
  const rows = await sql`
    SELECT d.id, d.account_id, d.auth_token_hash, d.auth_token_key_id FROM devices d
    JOIN accounts a ON a.id = d.account_id
    WHERE d.auth_token_hash IN (
      SELECT decode(value, 'hex') FROM unnest(
        ${sql.array(tokenHashes.map((hash) => hash.toString("hex")), "text")}::text[]
      ) AS candidate(value)
    )
      AND d.revoked_at IS NULL
      AND a.status IN ('active','limited')`;
  // An ambiguous match across rotation candidates is rejected rather than resolved arbitrarily.
  if (rows.length !== 1) throw new AuthError("invalid device token", 401, undefined, "device_revoked");
  // Re-key the stored digest on use so legacy-keyed rows drain onto the active blind-index key.
  const active = tokenHashIndex(token);
  await sql`UPDATE devices SET auth_token_hash = ${active.digest},
    auth_token_key_id = ${active.keyId}, last_seen_at = now()
    WHERE id = ${rows[0].id} AND auth_token_hash = ${rows[0].auth_token_hash}`;
  return { accountId: rows[0].account_id, deviceId: rows[0].id };
}

/**
 * Revalidates a device while holding a row lock for the lifetime of a mutation transaction.
 * This closes the gap between HTTP authentication and a slow request body finishing after the
 * device was revoked.
 */
export async function requireActiveDevice(
  sql: SQL,
  accountId: string,
  deviceId: string,
): Promise<void> {
  // Account deletion locks the account before revoking devices. Take the same explicit order here:
  // a joined FOR SHARE can lock the device first and deadlock with deletion (account -> device).
  const accounts = await sql`
    SELECT id FROM accounts
    WHERE id = ${accountId} AND status IN ('active','limited')
    FOR SHARE`;
  if (!accounts.length) throw new AuthError("device is no longer active", 401);

  const devices = await sql`
    SELECT id FROM devices
    WHERE id = ${deviceId} AND account_id = ${accountId} AND revoked_at IS NULL
    FOR SHARE`;
  if (!devices.length) throw new AuthError("device is no longer active", 401);
}

export async function revokeDevice(
  sql: SQL,
  accountId: string,
  deviceId: string,
  options: { beforeCommit?: (tx: SQL) => Promise<void> } = {},
): Promise<{ revoked: true }> {
  return await sql.begin(async (tx) => {
    const account = await tx`SELECT id FROM accounts WHERE id = ${accountId} FOR UPDATE`;
    if (!account.length) throw new AuthError("device not found", 404);
    const rows = await tx`
      UPDATE devices SET
        revoked_at = COALESCE(revoked_at, now()),
        auth_token_hash = digest(id::text || gen_random_uuid()::text, 'sha256'),
        auth_token_key_id = 'random-deleted',
        push_token_hash = NULL,
        push_token_hash_key_id = NULL,
        push_token_ciphertext = NULL,
        push_token_nonce = NULL,
        push_token_key_id = NULL,
        push_environment = NULL,
        push_updated_at = now(),
        voip_push_token_hash = NULL,
        voip_push_token_hash_key_id = NULL,
        voip_push_token_ciphertext = NULL,
        voip_push_token_nonce = NULL,
        voip_push_token_key_id = NULL,
        voip_push_environment = NULL,
        voip_push_updated_at = now()
      WHERE id = ${deviceId} AND account_id = ${accountId}
      RETURNING id`;
    if (rows.length === 0) throw new AuthError("device not found", 404);
    await revokePushBindingsForDevice(tx, deviceId);
    await tx`
      UPDATE device_sessions SET revoked_at = COALESCE(revoked_at, now()), revocation_reason = 'device_revoked'
      WHERE device_id = ${deviceId}`;
    await notifySessionRevocation(tx, accountId, deviceId, "device_revoked");
    await options.beforeCommit?.(tx);
    return { revoked: true };
  });
}

type AccountDeletionStartOptions = {
  networkKey?: string | null;
  deliveries?: OTPDeliveryRegistry | null;
  deliveryChannel?: unknown;
};

export async function startAccountDeletion(
  sql: SQL,
  accountId: string,
  options: AccountDeletionStartOptions = {},
): Promise<{ code?: string; retryAfter?: number }> {
  const account = (await sql`
    SELECT phone_e164_ciphertext, phone_nonce, phone_key_id, status
    FROM accounts WHERE id = ${accountId}`)[0];
  if (!account || !["active", "limited"].includes(account.status)) {
    throw new AuthError("account unavailable", 403);
  }
  let phone: string;
  try {
    phone = (await openForScope(sql, { kind: "account", accountId }, {
      keyId: account.phone_key_id,
      nonce: Buffer.from(account.phone_nonce),
      ciphertext: Buffer.from(account.phone_e164_ciphertext),
    }, PHONE_AAD)).toString("utf8");
  } catch (error) {
    if (error instanceof CryptoUnavailableError) throw error;
    throw new AuthError("account unavailable", 403);
  }
  return await startVerification(sql, phone, {
    networkKey: options.networkKey,
    deliveries: options.deliveries,
    deliveryChannel: options.deliveryChannel,
    purpose: "account_deletion",
  });
}

export async function deleteAccount(
  sql: SQL,
  accountId: string,
  code: string,
  options: {
    beforeCleanup?: (tx: SQL) => Promise<void>;
    beforeCommit?: (tx: SQL) => Promise<void>;
  } = {},
): Promise<{ deleted: true }> {
  if (!/^\d{6}$/.test(code)) throw new AuthError("enter the 6-digit code", 400);
  const result: { deleted: true } | AuthError = await sql.begin(async (tx) => {
    const identity = (await tx`
      SELECT phone_e164_ciphertext, phone_nonce, phone_key_id FROM accounts
      WHERE id = ${accountId} AND status IN ('active','limited')`)[0];
    if (!identity) return new AuthError("account unavailable", 403);
    let phone: string;
    try {
      phone = (await openForScope(tx, { kind: "account", accountId }, {
        keyId: String(identity.phone_key_id),
        nonce: Buffer.from(identity.phone_nonce),
        ciphertext: Buffer.from(identity.phone_e164_ciphertext),
      }, PHONE_AAD)).toString("utf8");
    } catch (error) {
      if (error instanceof CryptoUnavailableError) throw error;
      return new AuthError("account unavailable", 403);
    }
    const lookupCandidates = phoneLookupCandidates(phone).map((candidate) => candidate.digest);

    // OTP challenge is locked before the account row, matching login verification order.
    const challenge = (await tx`
      SELECT id, code_hash, code_key_id, code_salt, attempts
      FROM otp_challenges
      WHERE phone_lookup_hash IN (
        SELECT decode(value, 'hex') FROM unnest(
          ${tx.array(lookupCandidates.map((digest) => digest.toString("hex")), "text")}::text[]
        ) candidate(value)
      ) AND purpose = 'account_deletion'
        AND consumed_at IS NULL AND expires_at > now()
      ORDER BY created_at DESC LIMIT 1
      FOR UPDATE`)[0];
    if (!challenge) return new AuthError("no active deletion code", 400);
    if (challenge.attempts >= OTP_MAX_ATTEMPTS) {
      return new AuthError("too many attempts; request a new code", 429);
    }
    const expected = codeHashIndex(
      code,
      challenge.code_salt ? Buffer.from(challenge.code_salt) : undefined,
      challenge.code_key_id ?? "legacy-v1",
    ).digest;
    if (!constantTimeEqual(Buffer.from(challenge.code_hash), expected)) {
      await tx`UPDATE otp_challenges SET attempts = attempts + 1 WHERE id = ${challenge.id}`;
      return new AuthError("incorrect code", 400);
    }

    const account = (await tx`
      SELECT status, profile_photo_media_id FROM accounts WHERE id = ${accountId} FOR UPDATE`)[0];
    if (!account || !["active", "limited"].includes(account.status)) {
      return new AuthError("account unavailable", 403);
    }
    await options.beforeCleanup?.(tx);
    // This database-boundary function is also called by the account-status trigger used by old
    // binaries. Keeping current and mixed-node deletion on one path prevents semantic drift.
    await tx`SELECT public.toj_cleanup_account_private_state_v1(${accountId})`;
    const anonymizedPhone = await sealForScope(
      tx,
      { kind: "account", accountId },
      `deleted:${accountId}`,
      PHONE_AAD,
    );
    const anonymizedLookup = randomBytes(32);
    await tx`
      UPDATE accounts SET
        username = NULL,
        phone_lookup_hash = ${anonymizedLookup},
        phone_lookup_key_id = 'random-deleted',
        phone_e164_ciphertext = ${anonymizedPhone.ciphertext},
        phone_nonce = ${anonymizedPhone.nonce},
        phone_key_id = ${anonymizedPhone.keyId},
        first_name = 'Deleted Account',
        last_name = '',
        display_name = 'Deleted Account',
        bio = '',
        birthday = NULL,
        profile_color = 0,
        profile_photo_media_id = NULL,
        status = 'deleted',
        updated_at = now()
      WHERE id = ${accountId}`;
    if (account.profile_photo_media_id) {
      await tx`
        DELETE FROM media_objects media
        WHERE media.id = ${account.profile_photo_media_id}
          AND NOT EXISTS (SELECT 1 FROM messages WHERE media_id = media.id)
          AND NOT EXISTS (SELECT 1 FROM dialogs WHERE photo_media_id = media.id)
          AND NOT EXISTS (SELECT 1 FROM accounts WHERE profile_photo_media_id = media.id)
          AND NOT EXISTS (SELECT 1 FROM draft_attachments WHERE media_id = media.id)`;
    }
    await tx`
      UPDATE push_deliveries SET status = 'dead', claimed_at = NULL,
        last_error = 'account deleted'
      WHERE account_id = ${accountId} AND status IN ('pending','sending')`;
    const revokedDevices = await tx`
      UPDATE devices SET
        device_name = NULL,
        auth_token_hash = digest(id::text || gen_random_uuid()::text, 'sha256'),
        auth_token_key_id = 'random-deleted',
        revoked_at = COALESCE(revoked_at, now()),
        push_token_hash = NULL,
        push_token_hash_key_id = NULL,
        push_token_ciphertext = NULL,
        push_token_nonce = NULL,
        push_token_key_id = NULL,
        push_environment = NULL,
        push_updated_at = now(),
        voip_push_token_hash = NULL,
        voip_push_token_hash_key_id = NULL,
        voip_push_token_ciphertext = NULL,
        voip_push_token_nonce = NULL,
        voip_push_token_key_id = NULL,
        voip_push_environment = NULL,
        voip_push_updated_at = now()
      WHERE account_id = ${accountId}
      RETURNING id`;
    for (const device of revokedDevices) {
      // Account deletion must close authenticated sockets on every server process, not only the
      // node that handled the request. NOTIFY is transaction-bound and therefore cannot escape a
      // later rollback.
      await notifySessionRevocation(tx, accountId, String(device.id), "device_revoked");
    }
    // Device rows are revoked and locked before call rows, matching call-mutation lock order.
    // The injected call cleanup therefore commits atomically with account deletion without letting
    // an in-flight device mutation recreate state after the termination scan.
    await options.beforeCommit?.(tx);
    await tx`DELETE FROM otp_challenges WHERE phone_lookup_hash IN (
      SELECT decode(value, 'hex') FROM unnest(
        ${tx.array(lookupCandidates.map((digest) => digest.toString("hex")), "text")}::text[]
      ) candidate(value)
    )`;
    return { deleted: true };
  });
  if (result instanceof AuthError) throw result;
  return result;
}

export type DeviceSummary = {
  id: string;
  platform: string;
  deviceName: string | null;
  createdAt: string;
  lastSeenAt: string | null;
  sessionExpiresAt: string | null;
  current: boolean;
};

export async function listDevices(
  sql: SQL,
  accountId: string,
  currentDeviceId: string,
): Promise<{ devices: DeviceSummary[] }> {
  const rows = await sql`
    SELECT device.id, device.platform,
           device.device_name AS "deviceName",
           device.created_at AS "createdAt",
           device.last_seen_at AS "lastSeenAt",
           session.absolute_expires_at AS "sessionExpiresAt",
           (device.id = ${currentDeviceId}) AS current
    FROM devices device
    LEFT JOIN device_sessions session ON session.device_id = device.id AND session.revoked_at IS NULL
    WHERE device.account_id = ${accountId} AND device.revoked_at IS NULL
    ORDER BY (device.id = ${currentDeviceId}) DESC,
             COALESCE(device.last_seen_at, device.created_at) DESC`;
  return { devices: rows as DeviceSummary[] };
}
