import type { SQL } from "bun";
import { cleanupCallData } from "./calls";
import { savedMessagesSchemaReadiness } from "./saved-messages";
import {
  draftMutationReceiptKey,
  lockMutationKeys,
  mediaGroupReceiptKey,
} from "./locks";
import { dialogPreferenceSchemaState } from "./dialog-preference-readiness";
import { draftMediaSchemaState } from "./draft-media-readiness";
import { groupCallSchemaReadiness, groupCallsConfigured } from "./group-calls";
import { presenceSchemaReadiness } from "./presence";
import { profilePhotosSchemaReadiness } from "./profile-photos";
import { cleanupAbuseReports } from "./reports";
import { EXPIRED_BLIND_INDEX_KEY_ID } from "./blind-index";
import { otpSchemaReadiness } from "./auth";
import { expireAcceptedMessages, expiredMessageBacklog } from "./message-expiry";
import { cleanupMessagingFeatureReceipts } from "./messaging-features";
import { messagingFeatureSchemaState } from "./messaging-feature-readiness";
import { cloudProductivitySchemaState } from "./cloud-productivity-readiness";
import { ROTATION_RECEIPT_RETAINED_GENERATIONS } from "./session-security";

const REQUEST_ID_PATTERN = /^[A-Za-z0-9._:-]{8,128}$/;
export const CLEANUP_BATCH_SIZE = 1_000;
export const MAINTENANCE_INTERVAL_MS = 60 * 1_000;
export const ALLOWED_MUTATION_INGRESS_PER_MINUTE = 720;

export type ProviderState = "configured" | "development" | "disabled";

export function requestIdFrom(req: Request): string {
  const supplied = req.headers.get("x-request-id")?.trim() ?? "";
  return REQUEST_ID_PATTERN.test(supplied) ? supplied : crypto.randomUUID();
}

export function safeRoute(pathname: string): string {
  if (/^\/v1\/devices\/[0-9a-f-]+$/i.test(pathname)) return "/v1/devices/:id";
  if (/^\/v1\/media\/uploads\/[0-9a-f-]+\/chunks$/i.test(pathname)) return "/v1/media/uploads/:id/chunks";
  if (/^\/v1\/media\/uploads\/[0-9a-f-]+\/parts\/\d+$/i.test(pathname)) return "/v1/media/uploads/:id/parts/:part";
  if (/^\/v1\/media\/uploads\/[0-9a-f-]+\/thumbnail$/i.test(pathname)) return "/v1/media/uploads/:id/thumbnail";
  if (/^\/v1\/media\/uploads\/[0-9a-f-]+\/complete$/i.test(pathname)) return "/v1/media/uploads/:id/complete";
  if (/^\/v1\/media\/uploads\/[0-9a-f-]+$/i.test(pathname)) return "/v1/media/uploads/:id";
  if (/^\/v1\/media\/[0-9a-f-]+\/chunks$/i.test(pathname)) return "/v1/media/:id/chunks";
  if (/^\/v1\/media\/[0-9a-f-]+\/thumbnail$/i.test(pathname)) return "/v1/media/:id/thumbnail";
  if (/^\/v1\/blocks\/[0-9a-f-]+$/i.test(pathname)) return "/v1/blocks/:id";
  if (/^\/v1\/dialogs\/[0-9a-f-]+\/preferences$/i.test(pathname)) {
    return "/v1/dialogs/:id/preferences";
  }
  if (/^\/v1\/chat-folders\/[0-9a-f-]+\/move$/i.test(pathname)) return "/v1/chat-folders/:id/move";
  if (/^\/v1\/chat-folders\/[0-9a-f-]+$/i.test(pathname)) return "/v1/chat-folders/:id";
  if (/^\/v1\/scheduled-messages\/[0-9a-f-]+\/reschedule$/i.test(pathname)) {
    return "/v1/scheduled-messages/:id/reschedule";
  }
  if (/^\/v1\/scheduled-messages\/[0-9a-f-]+$/i.test(pathname)) return "/v1/scheduled-messages/:id";
  if (/^\/v1\/link-previews\/assets\/[0-9a-f-]+$/i.test(pathname)) {
    return "/v1/link-previews/assets/:id";
  }
  if (/^\/v1\/dialogs\/[0-9a-f-]+\/pins\/\d+$/i.test(pathname)) {
    return "/v1/dialogs/:id/pins/:msg";
  }
  if (/^\/v1\/dialogs\/[0-9a-f-]+\/pins$/i.test(pathname)) return "/v1/dialogs/:id/pins";
  if (/^\/v1\/dialogs\/[0-9a-f-]+\/auto-delete$/i.test(pathname)) {
    return "/v1/dialogs/:id/auto-delete";
  }
  if (/^\/v1\/dialogs\/[0-9a-f-]+\/polls\/\d+\/(vote|close)$/i.test(pathname)) {
    return pathname.endsWith("/vote")
      ? "/v1/dialogs/:id/polls/:msg/vote"
      : "/v1/dialogs/:id/polls/:msg/close";
  }
  if (/^\/v1\/dialogs\/[0-9a-f-]+\/polls\/\d+\/voters$/i.test(pathname)) {
    return "/v1/dialogs/:id/polls/:msg/voters";
  }
  if (/^\/v1\/calls\/[0-9a-f-]+\/(accept|reveal|confirm|decline|cancel|end|events|ice-config|telemetry)$/i.test(pathname)) {
    return pathname.replace(/[0-9a-f-]{36}/i, ":id");
  }
  if (/^\/v1\/calls\/[0-9a-f-]+$/i.test(pathname)) return "/v1/calls/:id";
  if (/^\/v1\/group-calls\/[0-9a-f-]+\/participants\/[0-9a-f-]+$/i.test(pathname)) {
    return "/v1/group-calls/:id/participants/:device";
  }
  if (/^\/v1\/group-calls\/[0-9a-f-]+\/screen-share\/heartbeat$/i.test(pathname)) {
    return "/v1/group-calls/:id/screen-share/heartbeat";
  }
  if (/^\/v1\/group-calls\/[0-9a-f-]+\/camera\/heartbeat$/i.test(pathname)) {
    return "/v1/group-calls/:id/camera/heartbeat";
  }
  if (/^\/v1\/group-calls\/[0-9a-f-]+\/camera\/release$/i.test(pathname)) {
    return "/v1/group-calls/:id/camera/release";
  }
  if (/^\/v1\/group-calls\/[0-9a-f-]+\/screen-share\/release$/i.test(pathname)) {
    return "/v1/group-calls/:id/screen-share/release";
  }
  if (/^\/v1\/group-calls\/[0-9a-f-]+\/(join|leave|end|heartbeat|credentials|epochs|camera|screen-share)$/i.test(pathname)) {
    return pathname.replace(/[0-9a-f-]{36}/i, ":id");
  }
  if (/^\/v1\/group-calls\/[0-9a-f-]+$/i.test(pathname)) return "/v1/group-calls/:id";
  const known = new Set([
    "/health", "/ready", "/metrics", "/v1/capabilities", "/v1/ws", "/v1/auth/start", "/v1/auth/check",
    "/v1/auth/two-factor/check", "/v1/session/refresh", "/v1/session/upgrade",
    "/v1/security/two-factor", "/v1/security/step-up/start", "/v1/security/step-up/check",
    "/v1/devices", "/v1/devices/push", "/v1/devices/voip-push",
    "/v1/devices/push-v2", "/v1/devices/voip-push-v2",
    "/v1/devices/group-call-capabilities", "/v1/session", "/v1/account/deletion/start",
    "/v1/account", "/v1/sync/state",
    "/v1/sync/difference", "/v1/bootstrap/start", "/v1/bootstrap/dialogs",
    "/v1/contacts/lookup", "/v1/dialogs/direct", "/v1/dialogs/saved", "/v1/messages/send", "/v1/messages/react",
    "/v1/messages/edit", "/v1/messages/delete", "/v1/history", "/v1/read",
    "/v1/media/uploads", "/v1/calls", "/v1/calls/active",
    "/v1/group-calls", "/v1/group-calls/active",
    "/v1/chat-folders", "/v1/scheduled-messages",
    "/v1/presence/query", "/v1/reports",
    "/v1/stickers", "/v1/stickers/preferences", "/v1/giphy/config",
  ]);
  return known.has(pathname) ? pathname : "unmatched";
}

function statusClass(status: number): string {
  return `${Math.floor(status / 100)}xx`;
}

function metricLabel(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n");
}

export class OperationalMetrics {
  private readonly startedAt = Date.now();
  private readonly requests = new Map<string, number>();
  private readonly durations = new Map<string, { count: number; sumSeconds: number }>();
  private readonly savedMessageEnsures = new Map<string, number>();
  private savedMessageEnsureCount = 0;
  private savedMessageEnsureSumSeconds = 0;
  private savedMessageInvariantViolations = 0;
  private scheduledWorkerUnavailable = 0;
  private scheduledCancellationsDuringOutage = 0;
  private cleanupDeleted = 0;
  private cleanupBacklog = 0;
  private readonly abuseReports = new Map<string, number>();
  private readonly authSecurityEvents = new Map<string, number>();

  recordCleanup(deleted: number, backlog: number): void {
    this.cleanupDeleted += deleted;
    this.cleanupBacklog = backlog;
  }

  record(method: string, route: string, status: number, durationMs: number): void {
    const key = `${method}\u0000${route}\u0000${statusClass(status)}`;
    this.requests.set(key, (this.requests.get(key) ?? 0) + 1);
    const durationKey = `${method}\u0000${route}`;
    const duration = this.durations.get(durationKey) ?? { count: 0, sumSeconds: 0 };
    duration.count += 1;
    duration.sumSeconds += durationMs / 1_000;
    this.durations.set(durationKey, duration);
  }

  recordAbuseReport(result: "submitted" | "duplicate" | "rate_limited"): void {
    this.abuseReports.set(result, (this.abuseReports.get(result) ?? 0) + 1);
  }

  recordAuthSecurity(event: AuthSecurityMetricEvent): void {
    this.authSecurityEvents.set(event, (this.authSecurityEvents.get(event) ?? 0) + 1);
  }

  recordSavedMessagesEnsure(
    result: "created" | "existing" | "repaired" | "error",
    durationMs: number,
  ): void {
    this.savedMessageEnsures.set(result, (this.savedMessageEnsures.get(result) ?? 0) + 1);
    this.savedMessageEnsureCount += 1;
    this.savedMessageEnsureSumSeconds += durationMs / 1_000;
    if (result === "repaired") this.savedMessageInvariantViolations += 1;
  }

  recordScheduledWorkerUnavailable(): void {
    this.scheduledWorkerUnavailable += 1;
  }

  recordScheduledCancellationDuringOutage(): void {
    this.scheduledCancellationsDuringOutage += 1;
  }

  render(): string {
    const lines = [
      "# HELP toj_process_uptime_seconds Process uptime in seconds.",
      "# TYPE toj_process_uptime_seconds gauge",
      `toj_process_uptime_seconds ${Math.floor((Date.now() - this.startedAt) / 1_000)}`,
      "# HELP toj_http_requests_total HTTP requests by safe route and status class.",
      "# TYPE toj_http_requests_total counter",
    ];
    for (const [key, count] of [...this.requests].sort()) {
      const [method, route, status] = key.split("\u0000");
      lines.push(`toj_http_requests_total{method="${metricLabel(method)}",route="${metricLabel(route)}",status="${status}"} ${count}`);
    }
    lines.push(
      "# HELP toj_abuse_report_requests_total Report submissions by safe outcome.",
      "# TYPE toj_abuse_report_requests_total counter",
    );
    for (const result of ["submitted", "duplicate", "rate_limited"] as const) {
      lines.push(`toj_abuse_report_requests_total{result="${result}"} ${this.abuseReports.get(result) ?? 0}`);
    }
    lines.push(
      "# HELP toj_http_request_duration_seconds_sum Cumulative HTTP request duration.",
      "# TYPE toj_http_request_duration_seconds_sum counter",
      "# HELP toj_http_request_duration_seconds_count Count of timed HTTP requests.",
      "# TYPE toj_http_request_duration_seconds_count counter",
    );
    for (const [key, value] of [...this.durations].sort()) {
      const [method, route] = key.split("\u0000");
      const labels = `method="${metricLabel(method)}",route="${metricLabel(route)}"`;
      lines.push(`toj_http_request_duration_seconds_sum{${labels}} ${value.sumSeconds.toFixed(6)}`);
      lines.push(`toj_http_request_duration_seconds_count{${labels}} ${value.count}`);
    }
    lines.push(
      "# HELP toj_saved_messages_ensure_total Saved Messages ensures by bounded result.",
      "# TYPE toj_saved_messages_ensure_total counter",
    );
    for (const result of ["created", "existing", "repaired", "error"]) {
      lines.push(`toj_saved_messages_ensure_total{result="${result}"} ${this.savedMessageEnsures.get(result) ?? 0}`);
    }
    lines.push(
      "# HELP toj_saved_messages_ensure_duration_seconds_sum Cumulative Saved Messages ensure duration.",
      "# TYPE toj_saved_messages_ensure_duration_seconds_sum counter",
      `toj_saved_messages_ensure_duration_seconds_sum ${this.savedMessageEnsureSumSeconds.toFixed(6)}`,
      "# HELP toj_saved_messages_ensure_duration_seconds_count Count of timed Saved Messages ensures.",
      "# TYPE toj_saved_messages_ensure_duration_seconds_count counter",
      `toj_saved_messages_ensure_duration_seconds_count ${this.savedMessageEnsureCount}`,
      "# HELP toj_saved_messages_invariant_violation_total Saved Messages rows repaired during ensure.",
      "# TYPE toj_saved_messages_invariant_violation_total counter",
      `toj_saved_messages_invariant_violation_total ${this.savedMessageInvariantViolations}`,
      "# HELP toj_scheduled_worker_unavailable_total Create or reschedule requests rejected because the delivery worker heartbeat was stale.",
      "# TYPE toj_scheduled_worker_unavailable_total counter",
      `toj_scheduled_worker_unavailable_total ${this.scheduledWorkerUnavailable}`,
      "# HELP toj_scheduled_cancellations_during_worker_outage_total Cancellations accepted while the delivery worker heartbeat was stale.",
      "# TYPE toj_scheduled_cancellations_during_worker_outage_total counter",
      `toj_scheduled_cancellations_during_worker_outage_total ${this.scheduledCancellationsDuringOutage}`,
      "# HELP toj_cleanup_deleted_total Rows deleted by maintenance cleanup.",
      "# TYPE toj_cleanup_deleted_total counter",
      `toj_cleanup_deleted_total ${this.cleanupDeleted}`,
      "# HELP toj_cleanup_backlog Expired rows waiting for maintenance cleanup.",
      "# TYPE toj_cleanup_backlog gauge",
      `toj_cleanup_backlog ${this.cleanupBacklog}`,
      "# HELP toj_cleanup_batch_capacity Maximum rows cleaned per category per run.",
      "# TYPE toj_cleanup_batch_capacity gauge",
      `toj_cleanup_batch_capacity ${CLEANUP_BATCH_SIZE}`,
      "# HELP toj_allowed_mutation_ingress_per_minute Maximum draft mutations plus album items.",
      "# TYPE toj_allowed_mutation_ingress_per_minute gauge",
      `toj_allowed_mutation_ingress_per_minute ${ALLOWED_MUTATION_INGRESS_PER_MINUTE}`,
      "# HELP toj_auth_security_events_total Authentication and two-step outcomes by bounded event.",
      "# TYPE toj_auth_security_events_total counter",
    );
    for (const event of AUTH_SECURITY_METRIC_EVENTS) {
      lines.push(`toj_auth_security_events_total{event="${event}"} ${this.authSecurityEvents.get(event) ?? 0}`);
    }
    return `${lines.join("\n")}\n`;
  }
}

const AUTH_SECURITY_METRIC_EVENTS = [
  "refresh_success",
  "refresh_failure",
  "refresh_replay_revocation",
  "session_expired",
  "second_factor_failure",
  "second_factor_locked",
  "recovery_used",
  "recovery_codes_regenerated",
  "two_factor_configured",
  "two_factor_disabled",
] as const;
export type AuthSecurityMetricEvent = typeof AUTH_SECURITY_METRIC_EVENTS[number];

export async function dialogPreferenceBacklogMetrics(sql: SQL): Promise<string> {
  const schema = (await sql`
    SELECT pg_catalog.to_regclass('public.dialog_preference_requests') IS NOT NULL
             AS requests_present,
           pg_catalog.to_regclass('public.dialog_preference_action_budgets') IS NOT NULL
             AS budgets_present`)[0];
  if (!schema?.requests_present || !schema?.budgets_present) {
    return [
      "# HELP toj_dialog_preference_schema_available Whether preference metrics relations exist.",
      "# TYPE toj_dialog_preference_schema_available gauge",
      "toj_dialog_preference_schema_available 0",
      "",
    ].join("\n");
  }
  const row = (await sql`
    SELECT
      (SELECT pg_catalog.count(*)
       FROM public.dialog_preference_requests
       WHERE status = 'pending')
        AS pending_requests,
      (SELECT GREATEST(reltuples, 0)::bigint
       FROM pg_catalog.pg_class
       WHERE oid = 'public.dialog_preference_requests'::pg_catalog.regclass)
        AS retained_request_estimate,
      (SELECT pg_catalog.count(*)
       FROM public.dialog_preference_action_budgets
       WHERE updated_at < now() - interval '24 hours')
        AS expired_budget_rows`)[0];
  return [
    "# HELP toj_dialog_preference_schema_available Whether preference metrics relations exist.",
    "# TYPE toj_dialog_preference_schema_available gauge",
    "toj_dialog_preference_schema_available 1",
    "# HELP toj_dialog_preference_pending_requests Pending idempotency claims.",
    "# TYPE toj_dialog_preference_pending_requests gauge",
    `toj_dialog_preference_pending_requests ${Number(row.pending_requests)}`,
    "# HELP toj_dialog_preference_idempotency_rows_estimate Planner estimate of durable dedupe rows.",
    "# TYPE toj_dialog_preference_idempotency_rows_estimate gauge",
    `toj_dialog_preference_idempotency_rows_estimate ${Number(row.retained_request_estimate)}`,
    "# HELP toj_dialog_preference_cleanup_backlog_rows Expired bounded-lifecycle rows awaiting cleanup.",
    "# TYPE toj_dialog_preference_cleanup_backlog_rows gauge",
    `toj_dialog_preference_cleanup_backlog_rows{table="budgets"} ${Number(row.expired_budget_rows)}`,
    "",
  ].join("\n");
}

export async function groupCallBacklogMetrics(sql: SQL): Promise<string> {
  const schema = (await sql`
    SELECT pg_catalog.to_regclass('public.group_calls') IS NOT NULL AS calls_present,
           pg_catalog.to_regclass('public.group_call_sfu_participant_states') IS NOT NULL
             AS sfu_states_present`)[0];
  if (!schema?.calls_present || !schema?.sfu_states_present) {
    return [
      "# HELP toj_group_call_schema_available Whether group-call metrics relations exist.",
      "# TYPE toj_group_call_schema_available gauge",
      "toj_group_call_schema_available 0",
      "",
    ].join("\n");
  }
  const row = (await sql`
    SELECT
      (SELECT count(*) FROM public.group_calls WHERE state = 'active') AS active_calls,
      (SELECT count(*) FROM public.group_calls call
       JOIN public.group_call_epochs epoch
         ON epoch.call_id = call.id AND epoch.epoch = call.media_epoch
       WHERE call.state = 'active'
         AND epoch.membership_revision <> call.membership_revision) AS rekeying_calls,
      (SELECT count(*) FROM public.group_call_sfu_participant_states
       WHERE applied_revision < revision) AS pending_sfu_states,
      (SELECT count(*) FROM public.group_call_sfu_participant_states
       WHERE applied_revision < revision AND last_error_code IS NOT NULL) AS failed_sfu_states,
      (SELECT COALESCE(EXTRACT(EPOCH FROM now() - min(updated_at)), 0)
       FROM public.group_call_sfu_participant_states
       WHERE applied_revision < revision) AS oldest_pending_sfu_seconds,
      (SELECT count(*) FROM public.group_call_camera_leases WHERE expires_at <= now())
        + (SELECT count(*) FROM public.group_call_screen_share_leases WHERE expires_at <= now())
        AS expired_media_leases`)[0];
  return [
    "# HELP toj_group_call_schema_available Whether group-call metrics relations exist.",
    "# TYPE toj_group_call_schema_available gauge",
    "toj_group_call_schema_available 1",
    "# HELP toj_group_call_active_rooms Active group-call rooms.",
    "# TYPE toj_group_call_active_rooms gauge",
    `toj_group_call_active_rooms ${Number(row.active_calls)}`,
    "# HELP toj_group_call_rekeying_rooms Active rooms fenced on a membership epoch transition.",
    "# TYPE toj_group_call_rekeying_rooms gauge",
    `toj_group_call_rekeying_rooms ${Number(row.rekeying_calls)}`,
    "# HELP toj_group_call_sfu_pending_states Durable SFU operations not yet applied.",
    "# TYPE toj_group_call_sfu_pending_states gauge",
    `toj_group_call_sfu_pending_states ${Number(row.pending_sfu_states)}`,
    "# HELP toj_group_call_sfu_failed_states Pending SFU operations with a recorded failure.",
    "# TYPE toj_group_call_sfu_failed_states gauge",
    `toj_group_call_sfu_failed_states ${Number(row.failed_sfu_states)}`,
    "# HELP toj_group_call_sfu_oldest_pending_seconds Age of the oldest pending SFU operation.",
    "# TYPE toj_group_call_sfu_oldest_pending_seconds gauge",
    `toj_group_call_sfu_oldest_pending_seconds ${Number(row.oldest_pending_sfu_seconds)}`,
    "# HELP toj_group_call_expired_media_leases Expired camera and screen leases awaiting cleanup.",
    "# TYPE toj_group_call_expired_media_leases gauge",
    `toj_group_call_expired_media_leases ${Number(row.expired_media_leases)}`,
    "",
  ].join("\n");
}

export function providerState(value: unknown): ProviderState {
  return value ? "configured" : "disabled";
}

export async function readiness(sql: SQL, providers: { sms: ProviderState; push: ProviderState; telegram?: ProviderState }) {
  const started = performance.now();
  await sql`SELECT 1`;
  const savedMessages = await savedMessagesSchemaReadiness(sql);
  const preferences = await dialogPreferenceSchemaState(sql, { bypassCache: true });
  const draftMedia = await draftMediaSchemaState(sql, { bypassCache: true });
  const groupCallSchema = await groupCallSchemaReadiness(sql, { bypassCache: true });
  const presence = await presenceSchemaReadiness(sql);
  const otpSchema = await otpSchemaReadiness(sql);
  const profilePhotos = await profilePhotosSchemaReadiness(sql);
  const messagingFeatures = await messagingFeatureSchemaState(sql, { bypassCache: true });
  const cloudProductivity = await cloudProductivitySchemaState(sql, { bypassCache: true });
  const authSecurityRow = (await sql`
    SELECT
      to_regclass('public.device_sessions') IS NOT NULL
        AND to_regclass('public.session_access_tokens') IS NOT NULL
        AND to_regclass('public.session_refresh_token_history') IS NOT NULL
        AND to_regclass('public.session_rotation_receipts') IS NOT NULL
        AND to_regclass('public.account_two_factor') IS NOT NULL
        AND to_regclass('public.two_factor_recovery_codes') IS NOT NULL
        AND to_regclass('public.two_factor_login_challenges') IS NOT NULL
        AND to_regclass('public.two_factor_attempt_budgets') IS NOT NULL
        AND to_regclass('public.security_step_up_tickets') IS NOT NULL
        AND EXISTS (
          SELECT 1 FROM information_schema.columns
          WHERE table_schema = 'public' AND table_name = 'session_rotation_receipts'
            AND column_name = 'response_generation' AND data_type = 'bigint'
            AND is_nullable = 'NO'
        )
        AND EXISTS (
          SELECT 1 FROM schema_migrations
          WHERE name = 'session-rotation-generation-v1'
        )
        AND EXISTS (
          SELECT 1 FROM information_schema.columns
          WHERE table_schema = 'public' AND table_name = 'devices' AND column_name = 'auth_scheme'
        ) AS ready`)[0];
  const authSecurityReady = Boolean(authSecurityRow?.ready);
  const groupCallsRequested = process.env.TOJ_GROUP_CALLS_ENABLED === "1";
  const groupCallInfrastructure = groupCallsConfigured();
  return {
    // This binary touches group-call device columns and revocation tables from ordinary auth,
    // PushKit, membership, and account-deletion paths even while admission is dark. Schema is an
    // unconditional binary contract; feature flags only control new starts and joins.
    status: savedMessages.ready && preferences.ready && draftMedia.ready
      && groupCallSchema.ready && authSecurityReady && messagingFeatures.ready
      && cloudProductivity.ready && presence.ready && profilePhotos.ready
      && (!groupCallsRequested || groupCallInfrastructure)
      ? "ready"
      : "not_ready",
    database: "ready",
    providers,
    savedMessagesSchema: savedMessages.ready ? "ready" : "incomplete",
    missingSchemaObjects: savedMessages.missing,
    // Preference relations and snapshot columns are linked into ordinary messaging SQL. Feature
    // switches control entrypoints and behavior, not whether this binary can run on a pre-expand
    // schema, so traffic admission must always fail closed while they are incomplete.
    dialogPreferences: preferences,
    // Maintenance, bootstrap, difference sync, and send paths all touch these relations whenever
    // the binary is live. Entry-point switches cannot make a partial schema safe.
    draftMedia,
    presence,
    // Profile columns are read by ordinary auth and sync paths even while photo mutation entry
    // points are dark, so this is an unconditional binary/schema admission contract.
    profilePhotos: profilePhotos.ready ? "ready" : "incomplete",
    authSecuritySchema: authSecurityReady ? "ready" : "incomplete",
    // A deploy carrying a schema change starts clean and only fails on the first request
    // that touches the new column, because `bun run staging` does not migrate. Surface the
    // drift here so /ready cannot report healthy while OTP is broken.
    otpSchema: otpSchema.ready ? "ready" : "incomplete",
    ...(otpSchema.ready ? {} : { otpSchemaMissing: otpSchema.missing }),
    messagingFeatures,
    cloudProductivity,
    groupCalls: {
      requested: groupCallsRequested,
      infrastructure: groupCallInfrastructure ? "ready" : "disabled_or_incomplete",
      schema: groupCallSchema,
    },
    databaseLatencyMs: Math.max(0, Math.round((performance.now() - started) * 10) / 10),
  };
}

export async function cleanupExpiredData(sql: SQL, batchSize = CLEANUP_BATCH_SIZE) {
  const expiredMessages = await expireAcceptedMessages(sql, batchSize);
  const messagingFeatureReceipts = await cleanupMessagingFeatureReceipts(sql, batchSize);
  const callData = await cleanupCallData(sql, batchSize);
  const abuseReportData = await cleanupAbuseReports(sql, batchSize);
  // Retention feeds the Telegram pilot's 24-hour request budget (auth.ts startVerification), which
  // counts rows by created_at. expires_at is created_at + OTP_TTL, so rows outlive the budget
  // window by that TTL; shortening either side would silently make the budget resettable.
  const otp = await sql`
    WITH doomed AS (
      SELECT id FROM otp_challenges
      WHERE expires_at < now() - interval '24 hours'
      ORDER BY expires_at LIMIT ${batchSize}
      FOR UPDATE SKIP LOCKED
    )
    DELETE FROM otp_challenges WHERE id IN (SELECT id FROM doomed)
    RETURNING id`;
  const accessTokens = await sql`
    WITH doomed AS (
      SELECT id FROM session_access_tokens
      WHERE expires_at < now() - interval '24 hours'
      ORDER BY expires_at LIMIT ${batchSize}
      FOR UPDATE SKIP LOCKED
    )
    DELETE FROM session_access_tokens WHERE id IN (SELECT id FROM doomed)
    RETURNING id`;
  // Receipt absence is destructive — a miss revokes the session as refresh_reuse_detected — so
  // these are pruned by rotation depth rather than age. A client stuck mid-rotation cannot advance
  // its own generation, so its receipt survives any delay; only another party rotating the session
  // buries it, which is the case that must not replay. The expires_at arm is a storage backstop for
  // sessions that stopped rotating, and tracks the idle TTL: past it the session is itself dead, so
  // the client gets session_expired rather than a false reuse alarm. See session-security.ts.
  const rotationReceipts = await sql`
    WITH doomed AS (
      SELECT receipt.session_id, receipt.rotation_id
      FROM session_rotation_receipts receipt
      JOIN device_sessions session ON session.id = receipt.session_id
      WHERE receipt.response_generation
              <= session.rotation_generation - ${ROTATION_RECEIPT_RETAINED_GENERATIONS}
         OR receipt.expires_at < now()
      ORDER BY receipt.expires_at LIMIT ${batchSize}
      -- Lock only the receipts. A bare FOR UPDATE would also lock the joined device_sessions row
      -- and put this worker in contention with live refreshes.
      FOR UPDATE OF receipt SKIP LOCKED
    )
    DELETE FROM session_rotation_receipts receipt USING doomed
    WHERE receipt.session_id = doomed.session_id AND receipt.rotation_id = doomed.rotation_id
    RETURNING receipt.rotation_id`;
  const authChallenges = await sql`
    WITH doomed AS (
      SELECT id FROM two_factor_login_challenges
      WHERE expires_at < now() - interval '24 hours'
      ORDER BY expires_at LIMIT ${batchSize}
      FOR UPDATE SKIP LOCKED
    )
    DELETE FROM two_factor_login_challenges WHERE id IN (SELECT id FROM doomed)
    RETURNING id`;
  const stepUpTickets = await sql`
    WITH doomed AS (
      SELECT id FROM security_step_up_tickets
      WHERE expires_at < now() - interval '24 hours'
      ORDER BY expires_at LIMIT ${batchSize}
      FOR UPDATE SKIP LOCKED
    )
    DELETE FROM security_step_up_tickets WHERE id IN (SELECT id FROM doomed)
    RETURNING id`;
  const twoFactorBudgets = await sql`
    WITH doomed AS (
      SELECT id FROM two_factor_attempt_budgets
      WHERE accepted_at < now() - interval '15 minutes'
      ORDER BY accepted_at LIMIT ${batchSize}
      FOR UPDATE SKIP LOCKED
    )
    DELETE FROM two_factor_attempt_budgets WHERE id IN (SELECT id FROM doomed)
    RETURNING id`;
  const snapshots = await sql`
    WITH doomed AS (
      SELECT id FROM bootstrap_snapshots
      WHERE expires_at < now()
      ORDER BY expires_at LIMIT ${batchSize}
      FOR UPDATE SKIP LOCKED
    )
    DELETE FROM bootstrap_snapshots WHERE id IN (SELECT id FROM doomed)
    RETURNING id`;
  const deliveries = await sql`
    WITH doomed AS (
      SELECT id FROM push_deliveries
      WHERE status IN ('sent', 'dead') AND created_at < now() - interval '7 days'
      ORDER BY created_at LIMIT ${batchSize}
      FOR UPDATE SKIP LOCKED
    )
    DELETE FROM push_deliveries WHERE id IN (SELECT id FROM doomed)
    RETURNING id`;
  const contactLookups = await sql`
    WITH doomed AS (
      SELECT id FROM contact_lookup_attempts
      WHERE created_at < now() - interval '24 hours'
      ORDER BY created_at LIMIT ${batchSize}
      FOR UPDATE SKIP LOCKED
    )
    DELETE FROM contact_lookup_attempts WHERE id IN (SELECT id FROM doomed)
    RETURNING id`;
  const media = await sql`
    WITH doomed AS (
      SELECT id FROM media_objects
      WHERE status IN ('uploading', 'rejected') AND expires_at < now()
      ORDER BY expires_at LIMIT ${batchSize}
      FOR UPDATE SKIP LOCKED
    )
    DELETE FROM media_objects object
    WHERE object.id IN (SELECT id FROM doomed)
      AND object.status IN ('uploading', 'rejected')
      AND object.expires_at < now()
    RETURNING id`;
  const mediaAttempts = await sql`
    WITH doomed AS (
      SELECT id FROM media_upload_attempts
      WHERE created_at < now() - interval '24 hours'
      ORDER BY created_at LIMIT ${batchSize}
      FOR UPDATE SKIP LOCKED
    )
    DELETE FROM media_upload_attempts WHERE id IN (SELECT id FROM doomed)
    RETURNING id`;
  const mediaOrphans = await sql`
    WITH doomed AS (
      SELECT mo.id FROM media_objects mo
      WHERE mo.status = 'ready'
        AND GREATEST(mo.completed_at, mo.last_accessed_at) < now() - interval '24 hours'
        AND NOT EXISTS (
          SELECT 1 FROM messages m WHERE m.media_id = mo.id AND m.state = 'visible'
            AND (m.expires_at IS NULL OR m.expires_at > now())
        )
        AND NOT EXISTS (SELECT 1 FROM dialogs d WHERE d.photo_media_id = mo.id)
        AND NOT EXISTS (SELECT 1 FROM accounts a WHERE a.profile_photo_media_id = mo.id)
        AND NOT EXISTS (
          SELECT 1 FROM scheduled_delivery_items item
          JOIN scheduled_deliveries delivery ON delivery.id = item.delivery_id
          WHERE item.media_id = mo.id AND delivery.state IN ('scheduled','processing')
        )
        AND NOT EXISTS (
          SELECT 1
          FROM draft_attachments attachment
          JOIN account_dialog_drafts draft
            ON draft.account_id = attachment.account_id
           AND draft.dialog_id = attachment.dialog_id
          JOIN dialogs dialog ON dialog.id = draft.dialog_id AND dialog.closed_at IS NULL
          JOIN dialog_members member
            ON member.dialog_id = draft.dialog_id
           AND member.account_id = draft.account_id
           AND member.left_at IS NULL
          WHERE attachment.media_id = mo.id AND draft.state = 'active'
        )
      ORDER BY mo.completed_at LIMIT ${batchSize}
      FOR UPDATE OF mo SKIP LOCKED
    )
    DELETE FROM media_objects mo
    WHERE mo.id IN (SELECT id FROM doomed)
      AND mo.status = 'ready'
      AND GREATEST(mo.completed_at, mo.last_accessed_at) < now() - interval '24 hours'
      AND NOT EXISTS (
        SELECT 1 FROM messages m WHERE m.media_id = mo.id AND m.state = 'visible'
          AND (m.expires_at IS NULL OR m.expires_at > now())
      )
      AND NOT EXISTS (SELECT 1 FROM dialogs d WHERE d.photo_media_id = mo.id)
      AND NOT EXISTS (SELECT 1 FROM accounts a WHERE a.profile_photo_media_id = mo.id)
      AND NOT EXISTS (
        SELECT 1 FROM scheduled_delivery_items item
        JOIN scheduled_deliveries delivery ON delivery.id = item.delivery_id
        WHERE item.media_id = mo.id AND delivery.state IN ('scheduled','processing')
      )
      AND NOT EXISTS (
        SELECT 1
        FROM draft_attachments attachment
        JOIN account_dialog_drafts draft
          ON draft.account_id = attachment.account_id
         AND draft.dialog_id = attachment.dialog_id
        JOIN dialogs dialog ON dialog.id = draft.dialog_id AND dialog.closed_at IS NULL
        JOIN dialog_members member
          ON member.dialog_id = draft.dialog_id
         AND member.account_id = draft.account_id
         AND member.left_at IS NULL
        WHERE attachment.media_id = mo.id AND draft.state = 'active'
      )
    RETURNING mo.id`;
  const sendRequests = await sql`
    WITH doomed AS (
      SELECT sender_account_id, client_msg_id FROM send_requests
      WHERE status = 'pending' AND created_at < now() - interval '24 hours'
      ORDER BY created_at LIMIT ${batchSize}
      FOR UPDATE SKIP LOCKED
    )
    DELETE FROM send_requests request USING doomed
    WHERE request.sender_account_id = doomed.sender_account_id
      AND request.client_msg_id = doomed.client_msg_id
    RETURNING request.client_msg_id`;
  const messageMutations = await sql`
    WITH doomed AS (
      SELECT actor_account_id, client_mutation_id FROM message_mutation_requests
      WHERE created_at < now() - interval '24 hours'
      ORDER BY created_at LIMIT ${batchSize}
      FOR UPDATE SKIP LOCKED
    )
    DELETE FROM message_mutation_requests request USING doomed
    WHERE request.actor_account_id = doomed.actor_account_id
      AND request.client_mutation_id = doomed.client_mutation_id
    RETURNING request.client_mutation_id`;
  const draftMutations = await sql.begin(async (tx) => {
    const candidates = await tx`
      SELECT account_id, operation_id
      FROM draft_mutation_requests
      WHERE created_at < now() - interval '24 hours'
      ORDER BY created_at LIMIT ${batchSize}`;
    await lockMutationKeys(
      tx,
      candidates.map((row: any) =>
        draftMutationReceiptKey(String(row.account_id), String(row.operation_id))
      ),
    );
    const doomed = candidates.length ? await tx`
      SELECT account_id, operation_id, dialog_id, payload_fingerprint, fingerprint_key_id,
             status, resulting_revision
      FROM draft_mutation_requests
      WHERE created_at < now() - interval '24 hours'
        AND (account_id, operation_id) IN (
          SELECT * FROM unnest(
            ${tx.array(candidates.map((row: any) => row.account_id), "uuid")}::uuid[],
            ${tx.array(candidates.map((row: any) => row.operation_id), "uuid")}::uuid[]
          )
        )
      ORDER BY created_at
      FOR UPDATE SKIP LOCKED` : [];
    const completed = doomed.filter((row: any) => row.status === "completed");
    if (completed.length) {
      await tx`
        INSERT INTO draft_mutation_tombstones (
          account_id, operation_id, dialog_id, payload_fingerprint, fingerprint_key_id,
          resulting_revision
        )
        SELECT request.account_id, request.operation_id, request.dialog_id,
               request.payload_fingerprint, request.fingerprint_key_id,
               request.resulting_revision
        FROM draft_mutation_requests request
        WHERE (request.account_id, request.operation_id) IN (
          SELECT * FROM unnest(
            ${tx.array(completed.map((row: any) => row.account_id), "uuid")}::uuid[],
            ${tx.array(completed.map((row: any) => row.operation_id), "uuid")}::uuid[]
          )
        )
        ON CONFLICT (account_id, operation_id) DO NOTHING`;
    }
    if (!doomed.length) return [];
    return await tx`
      DELETE FROM draft_mutation_requests request
      WHERE (request.account_id, request.operation_id) IN (
        SELECT * FROM unnest(
          ${tx.array(doomed.map((row: any) => row.account_id), "uuid")}::uuid[],
          ${tx.array(doomed.map((row: any) => row.operation_id), "uuid")}::uuid[]
        )
      )
      RETURNING request.operation_id`;
  });
  const draftBudgets = await sql`
    WITH doomed AS (
      SELECT id FROM draft_mutation_budgets
      WHERE accepted_at < now() - interval '2 minutes'
      ORDER BY accepted_at LIMIT ${batchSize}
    )
    DELETE FROM draft_mutation_budgets WHERE id IN (SELECT id FROM doomed)
    RETURNING id`;
  const mediaGroupSends = await sql.begin(async (tx) => {
    const candidates = await tx`
      SELECT sender_account_id, client_group_id
      FROM media_group_send_requests
      WHERE created_at < now() - interval '24 hours'
      ORDER BY created_at LIMIT ${batchSize}`;
    await lockMutationKeys(
      tx,
      candidates.map((row: any) =>
        mediaGroupReceiptKey(String(row.sender_account_id), String(row.client_group_id))
      ),
    );
    const doomed = candidates.length ? await tx`
      SELECT sender_account_id, client_group_id, dialog_id, payload_fingerprint,
             fingerprint_key_id, status,
             first_msg_id, last_msg_id, sender_pts, cleared_draft_revision
      FROM media_group_send_requests
      WHERE created_at < now() - interval '24 hours'
        AND (sender_account_id, client_group_id) IN (
          SELECT * FROM unnest(
            ${tx.array(candidates.map((row: any) => row.sender_account_id), "uuid")}::uuid[],
            ${tx.array(candidates.map((row: any) => row.client_group_id), "uuid")}::uuid[]
          )
        )
      ORDER BY created_at
      FOR UPDATE SKIP LOCKED` : [];
    const completed = doomed.filter((row: any) => row.status === "completed");
    if (completed.length) {
      await tx`
        INSERT INTO media_group_send_tombstones (
          sender_account_id, client_group_id, dialog_id, payload_fingerprint,
          fingerprint_key_id,
          first_msg_id, last_msg_id, sender_pts, cleared_draft_revision
        )
        SELECT request.sender_account_id, request.client_group_id, request.dialog_id,
               request.payload_fingerprint, request.fingerprint_key_id,
               request.first_msg_id, request.last_msg_id,
               request.sender_pts, request.cleared_draft_revision
        FROM media_group_send_requests request
        WHERE (request.sender_account_id, request.client_group_id) IN (
          SELECT * FROM unnest(
            ${tx.array(completed.map((row: any) => row.sender_account_id), "uuid")}::uuid[],
            ${tx.array(completed.map((row: any) => row.client_group_id), "uuid")}::uuid[]
          )
        )
        ON CONFLICT (sender_account_id, client_group_id) DO NOTHING`;
    }
    if (!doomed.length) return [];
    return await tx`
      DELETE FROM media_group_send_requests request
      WHERE (request.sender_account_id, request.client_group_id) IN (
        SELECT * FROM unnest(
          ${tx.array(doomed.map((row: any) => row.sender_account_id), "uuid")}::uuid[],
          ${tx.array(doomed.map((row: any) => row.client_group_id), "uuid")}::uuid[]
        )
      )
      RETURNING request.client_group_id`;
  });
  const mediaGroupBudgets = await sql`
    WITH doomed AS (
      SELECT id FROM media_group_send_budgets
      WHERE accepted_at < now() - interval '2 minutes'
      ORDER BY accepted_at LIMIT ${batchSize}
      FOR UPDATE SKIP LOCKED
    )
    DELETE FROM media_group_send_budgets budget USING doomed
    WHERE budget.id = doomed.id
    RETURNING budget.id`;
  const groupCreates = await sql`
    WITH doomed AS (
      SELECT creator_account_id, client_group_id FROM group_create_requests
      WHERE created_at < now() - interval '24 hours'
      ORDER BY created_at LIMIT ${batchSize}
      FOR UPDATE SKIP LOCKED
    )
    DELETE FROM group_create_requests request USING doomed
    WHERE request.creator_account_id = doomed.creator_account_id
      AND request.client_group_id = doomed.client_group_id
    RETURNING request.client_group_id`;
  const groupMutations = await sql`
    WITH doomed AS (
      SELECT actor_account_id, client_mutation_id FROM group_mutation_requests
      WHERE created_at < now() - interval '24 hours'
      ORDER BY created_at LIMIT ${batchSize}
      FOR UPDATE SKIP LOCKED
    )
    DELETE FROM group_mutation_requests request USING doomed
    WHERE request.actor_account_id = doomed.actor_account_id
      AND request.client_mutation_id = doomed.client_mutation_id
    RETURNING request.client_mutation_id`;
  // Idempotency identifiers remain permanently consumed, but their keyed canonical digest is
  // only needed during the documented retry horizon. Replacing it after 90 days lets operators
  // retire historical blind-index keys without permitting the operation ID to execute again.
  const expiredSendFingerprints = await sql`
    WITH doomed AS (
      SELECT sender_account_id, client_msg_id FROM send_requests
      WHERE status = 'completed' AND fingerprint IS NOT NULL
        AND created_at < now() - interval '90 days'
      ORDER BY created_at LIMIT ${batchSize} FOR UPDATE SKIP LOCKED
    )
    UPDATE send_requests request SET fingerprint = NULL,
      fingerprint_key_id = ${EXPIRED_BLIND_INDEX_KEY_ID}
    FROM doomed WHERE request.sender_account_id = doomed.sender_account_id
      AND request.client_msg_id = doomed.client_msg_id
    RETURNING request.client_msg_id`;
  const expiredMessageFingerprints = await sql`
    WITH doomed AS (
      SELECT dialog_id, msg_id FROM messages
      WHERE send_fingerprint IS NOT NULL AND server_ts < now() - interval '90 days'
      ORDER BY server_ts, dialog_id, msg_id LIMIT ${batchSize} FOR UPDATE SKIP LOCKED
    )
    UPDATE messages message SET send_fingerprint = NULL,
      send_fingerprint_key_id = ${EXPIRED_BLIND_INDEX_KEY_ID}
    FROM doomed WHERE message.dialog_id = doomed.dialog_id AND message.msg_id = doomed.msg_id
    RETURNING message.msg_id`;
  const expiredDraftFingerprints = await sql`
    WITH doomed AS (
      SELECT account_id, operation_id FROM draft_mutation_tombstones
      WHERE fingerprint_key_id <> ${EXPIRED_BLIND_INDEX_KEY_ID}
        AND created_at < now() - interval '90 days'
      ORDER BY created_at LIMIT ${batchSize} FOR UPDATE SKIP LOCKED
    )
    UPDATE draft_mutation_tombstones tombstone
    SET payload_fingerprint = gen_random_bytes(32),
      fingerprint_key_id = ${EXPIRED_BLIND_INDEX_KEY_ID}
    FROM doomed WHERE tombstone.account_id = doomed.account_id
      AND tombstone.operation_id = doomed.operation_id
    RETURNING tombstone.operation_id`;
  const expiredMediaGroupFingerprints = await sql`
    WITH doomed AS (
      SELECT sender_account_id, client_group_id FROM media_group_send_tombstones
      WHERE fingerprint_key_id <> ${EXPIRED_BLIND_INDEX_KEY_ID}
        AND created_at < now() - interval '90 days'
      ORDER BY created_at LIMIT ${batchSize} FOR UPDATE SKIP LOCKED
    )
    UPDATE media_group_send_tombstones tombstone
    SET payload_fingerprint = gen_random_bytes(32),
      fingerprint_key_id = ${EXPIRED_BLIND_INDEX_KEY_ID}
    FROM doomed WHERE tombstone.sender_account_id = doomed.sender_account_id
      AND tombstone.client_group_id = doomed.client_group_id
    RETURNING tombstone.client_group_id`;
  const expiredFolderFingerprints = await sql`
    WITH doomed AS (
      SELECT account_id, client_mutation_id FROM chat_folder_mutation_requests
      WHERE status = 'completed' AND fingerprint_key_id <> ${EXPIRED_BLIND_INDEX_KEY_ID}
        AND created_at < now() - interval '90 days'
      ORDER BY created_at LIMIT ${batchSize} FOR UPDATE SKIP LOCKED
    )
    UPDATE chat_folder_mutation_requests request
    SET fingerprint = gen_random_bytes(32), request_fingerprint = NULL,
      fingerprint_key_id = ${EXPIRED_BLIND_INDEX_KEY_ID}
    FROM doomed WHERE request.account_id = doomed.account_id
      AND request.client_mutation_id = doomed.client_mutation_id
    RETURNING request.client_mutation_id`;
  const expiredScheduledFingerprints = await sql`
    WITH doomed AS (
      SELECT account_id, client_mutation_id FROM scheduled_delivery_mutation_requests
      WHERE status = 'completed' AND fingerprint_key_id <> ${EXPIRED_BLIND_INDEX_KEY_ID}
        AND created_at < now() - interval '90 days'
      ORDER BY created_at LIMIT ${batchSize} FOR UPDATE SKIP LOCKED
    )
    UPDATE scheduled_delivery_mutation_requests request
    SET fingerprint = gen_random_bytes(32), request_fingerprint = NULL,
      fingerprint_key_id = ${EXPIRED_BLIND_INDEX_KEY_ID}
    FROM doomed WHERE request.account_id = doomed.account_id
      AND request.client_mutation_id = doomed.client_mutation_id
    RETURNING request.client_mutation_id`;
  const blindIndexReceiptsExpired = expiredSendFingerprints.length
    + expiredMessageFingerprints.length
    + expiredDraftFingerprints.length
    + expiredMediaGroupFingerprints.length
    + expiredFolderFingerprints.length
    + expiredScheduledFingerprints.length;
  // Preference mutation IDs are client-generated and can be retried after an arbitrarily long
  // offline period or lost response. Keep completed dedupe state until account deletion so a
  // committed patch can never be interpreted as a new mutation.
  const dialogPreferenceRequests: any[] = [];
  const dialogPreferenceBudgets = await sql`
    WITH doomed AS (
      SELECT account_id, bucket_started FROM dialog_preference_action_budgets
      WHERE updated_at < now() - interval '24 hours'
      ORDER BY updated_at LIMIT ${batchSize}
      FOR UPDATE SKIP LOCKED
    )
    DELETE FROM dialog_preference_action_budgets budget USING doomed
    WHERE budget.account_id = doomed.account_id
      AND budget.bucket_started = doomed.bucket_started
    RETURNING budget.account_id`;
  const profilePhotoBudgets = await sql`
    WITH doomed AS (
      SELECT account_id, bucket_started FROM profile_photo_action_budgets
      WHERE updated_at < now() - interval '48 hours'
      ORDER BY updated_at LIMIT ${batchSize}
      FOR UPDATE SKIP LOCKED
    )
    DELETE FROM profile_photo_action_budgets budget USING doomed
    WHERE budget.account_id = doomed.account_id
      AND budget.bucket_started = doomed.bucket_started
    RETURNING budget.account_id`;
  const scheduledDeliveries = await sql`
    WITH doomed AS (
      SELECT id FROM scheduled_deliveries
      WHERE state IN ('delivered','failed','canceled')
        AND completed_at < now() - interval '30 days'
      ORDER BY completed_at LIMIT ${batchSize}
      FOR UPDATE SKIP LOCKED
    )
    DELETE FROM scheduled_deliveries delivery
    WHERE delivery.id IN (SELECT id FROM doomed)
    RETURNING delivery.id`;
  const scheduledBudgets = await sql`
    WITH doomed AS (
      SELECT account_id, action, bucket_started FROM scheduled_delivery_action_budgets
      WHERE updated_at < now() - interval '24 hours'
      ORDER BY updated_at LIMIT ${batchSize}
      FOR UPDATE SKIP LOCKED
    )
    DELETE FROM scheduled_delivery_action_budgets budget USING doomed
    WHERE budget.account_id = doomed.account_id
      AND budget.action = doomed.action
      AND budget.bucket_started = doomed.bucket_started
    RETURNING budget.account_id`;
  const folderBudgets = await sql`
    WITH doomed AS (
      SELECT account_id, bucket_started FROM chat_folder_action_budgets
      WHERE updated_at < now() - interval '24 hours'
      ORDER BY updated_at LIMIT ${batchSize}
      FOR UPDATE SKIP LOCKED
    )
    DELETE FROM chat_folder_action_budgets budget USING doomed
    WHERE budget.account_id = doomed.account_id
      AND budget.bucket_started = doomed.bucket_started
    RETURNING budget.account_id`;
  const previewBudgets = await sql`
    WITH doomed AS (
      SELECT account_id, bucket_started FROM link_preview_action_budgets
      WHERE updated_at < now() - interval '24 hours'
      ORDER BY updated_at LIMIT ${batchSize}
      FOR UPDATE SKIP LOCKED
    )
    DELETE FROM link_preview_action_budgets budget USING doomed
    WHERE budget.account_id = doomed.account_id
      AND budget.bucket_started = doomed.bucket_started
    RETURNING budget.account_id`;
  const previewCache = await sql`
    WITH doomed AS (
      SELECT entry.url_lookup_hmac
      FROM link_preview_cache_entries entry
      WHERE entry.expires_at < now()
        AND NOT EXISTS (
          SELECT 1 FROM link_preview_waiters waiter
          WHERE waiter.url_lookup_hmac = entry.url_lookup_hmac
        )
      ORDER BY entry.expires_at LIMIT ${batchSize}
      FOR UPDATE OF entry SKIP LOCKED
    )
    DELETE FROM link_preview_cache_entries entry
    WHERE entry.url_lookup_hmac IN (SELECT url_lookup_hmac FROM doomed)
    RETURNING entry.url_lookup_hmac`;
  const previewSnapshots = await sql`
    WITH doomed AS (
      SELECT snapshot.id
      FROM link_preview_snapshots snapshot
      WHERE snapshot.expires_at < now()
        AND NOT EXISTS (
          SELECT 1 FROM message_link_previews relation WHERE relation.snapshot_id = snapshot.id
        )
        AND NOT EXISTS (
          SELECT 1 FROM link_preview_cache_entries entry
          WHERE entry.current_snapshot_id = snapshot.id
        )
      ORDER BY snapshot.expires_at LIMIT ${batchSize}
      FOR UPDATE OF snapshot SKIP LOCKED
    )
    DELETE FROM link_preview_snapshots snapshot
    WHERE snapshot.id IN (SELECT id FROM doomed)
    RETURNING snapshot.id`;
  const previewAssets = await sql`
    WITH doomed AS (
      SELECT asset.id FROM link_preview_assets asset
      WHERE asset.created_at < now() - interval '24 hours'
        AND NOT EXISTS (
          SELECT 1 FROM link_preview_snapshots snapshot WHERE snapshot.asset_id = asset.id
        )
      ORDER BY asset.created_at LIMIT ${batchSize}
      FOR UPDATE OF asset SKIP LOCKED
    )
    DELETE FROM link_preview_assets asset
    WHERE asset.id IN (SELECT id FROM doomed)
    RETURNING asset.id`;
  const events = await sql.begin(async (tx) => {
    const doomed = await tx`
      SELECT account_id, pts
      FROM account_events
      WHERE created_at < now() - interval '30 days'
      ORDER BY created_at, account_id, pts
      LIMIT ${batchSize}
      FOR UPDATE SKIP LOCKED`;
    if (doomed.length === 0) return [];
    const accountIds = [...new Set(doomed.map((row: any) => String(row.account_id)))];
    await tx`
      WITH floors AS (
        SELECT account_id, max(pts) AS pts
        FROM account_events
        WHERE (account_id, pts) IN (
          SELECT * FROM unnest(
            ${tx.array(doomed.map((row: any) => row.account_id), "uuid")}::uuid[],
            ${tx.array(doomed.map((row: any) => Number(row.pts)), "int8")}::bigint[]
          )
        )
        GROUP BY account_id
      )
      UPDATE account_sync_states state
      SET pruned_through_pts = GREATEST(state.pruned_through_pts, floors.pts),
          updated_at = now()
      FROM floors
      WHERE state.account_id = floors.account_id`;
    const deleted = await tx`
      DELETE FROM account_events event
      WHERE (event.account_id, event.pts) IN (
        SELECT * FROM unnest(
          ${tx.array(doomed.map((row: any) => row.account_id), "uuid")}::uuid[],
          ${tx.array(doomed.map((row: any) => Number(row.pts)), "int8")}::bigint[]
        )
      )
      RETURNING event.account_id`;
    void accountIds;
    return deleted;
  });
  return {
    otp: otp.length,
    expiredMessages: expiredMessages.expired,
    expiredMessageMedia: expiredMessages.mediaRemoved,
    messagingFeatureReceipts,
    accessTokens: accessTokens.length,
    rotationReceipts: rotationReceipts.length,
    authChallenges: authChallenges.length,
    stepUpTickets: stepUpTickets.length,
    twoFactorBudgets: twoFactorBudgets.length,
    snapshots: snapshots.length,
    pushDeliveries: deliveries.length,
    contactLookups: contactLookups.length,
    mediaUploads: media.length,
    mediaAttempts: mediaAttempts.length,
    mediaOrphans: mediaOrphans.length,
    sendRequests: sendRequests.length,
    messageMutations: messageMutations.length,
    draftMutations: draftMutations.length,
    draftBudgets: draftBudgets.length,
    mediaGroupSends: mediaGroupSends.length,
    mediaGroupBudgets: mediaGroupBudgets.length,
    groupCreates: groupCreates.length,
    groupMutations: groupMutations.length,
    blindIndexReceiptsExpired,
    dialogPreferenceRequests: dialogPreferenceRequests.length,
    dialogPreferenceBudgets: dialogPreferenceBudgets.length,
    profilePhotoBudgets: profilePhotoBudgets.length,
    scheduledDeliveries: scheduledDeliveries.length,
    scheduledBudgets: scheduledBudgets.length,
    folderBudgets: folderBudgets.length,
    previewBudgets: previewBudgets.length,
    previewCache: previewCache.length,
    previewSnapshots: previewSnapshots.length,
    previewAssets: previewAssets.length,
    accountEvents: events.length,
    callData,
    abuseReportData,
  };
}

function cleanupCount(value: Awaited<ReturnType<typeof cleanupExpiredData>>): number {
  return value.otp + value.expiredMessages + value.messagingFeatureReceipts
    + value.accessTokens + value.rotationReceipts + value.authChallenges
    + value.stepUpTickets + value.twoFactorBudgets
    + value.snapshots + value.pushDeliveries + value.contactLookups
    + value.mediaUploads + value.mediaAttempts + value.mediaOrphans + value.sendRequests
    + value.messageMutations + value.draftMutations + value.draftBudgets
    + value.mediaGroupSends + value.mediaGroupBudgets + value.groupCreates + value.groupMutations
    + value.blindIndexReceiptsExpired
    + value.dialogPreferenceRequests + value.dialogPreferenceBudgets + value.accountEvents
    + value.profilePhotoBudgets
    + value.scheduledDeliveries + value.scheduledBudgets + value.folderBudgets
    + value.previewBudgets + value.previewCache + value.previewSnapshots + value.previewAssets
    + Object.values(value.callData).reduce((sum, count) => sum + count, 0)
    + Object.values(value.abuseReportData).reduce((sum, count) => sum + count, 0);
}

export async function drainExpiredData(
  sql: SQL,
  options: { batchSize?: number; maxRows?: number; maxRuntimeMs?: number } = {},
) {
  const batchSize = Math.max(1, options.batchSize ?? Number(
    process.env.TOJ_MAINTENANCE_BATCH_SIZE ?? CLEANUP_BATCH_SIZE,
  ));
  const maxRows = Math.max(batchSize, options.maxRows ?? Number(
    process.env.TOJ_MAINTENANCE_MAX_ROWS_PER_TICK ?? 10_000,
  ));
  const maxRuntimeMs = Math.max(1, options.maxRuntimeMs ?? Number(
    process.env.TOJ_MAINTENANCE_MAX_RUNTIME_MS ?? 5_000,
  ));
  const startedAt = performance.now();
  let rows = 0;
  let passes = 0;
  let last = await cleanupExpiredData(sql, Math.min(batchSize, maxRows));
  while (true) {
    passes += 1;
    const deleted = cleanupCount(last);
    rows += deleted;
    if (
      deleted === 0
      || rows >= maxRows
      || performance.now() - startedAt >= maxRuntimeMs
    ) break;
    last = await cleanupExpiredData(sql, Math.min(batchSize, maxRows - rows));
  }
  return {
    rows,
    passes,
    runtimeMs: Math.round((performance.now() - startedAt) * 10) / 10,
    exhausted: rows >= maxRows || performance.now() - startedAt >= maxRuntimeMs,
  };
}

function cleanError(value: unknown): string {
  return (value instanceof Error ? value.message : String(value)).replace(/[\r\n]+/g, " ").slice(0, 300);
}

export function startMaintenanceWorker(
  sql: SQL,
  intervalMs = MAINTENANCE_INTERVAL_MS,
  metrics?: OperationalMetrics,
): () => void {
  let running = false;
  const tick = async () => {
    if (running) return;
    running = true;
    try {
      const drained = await drainExpiredData(sql);
      const backlogRows = await sql`
        SELECT
          (SELECT count(*) FROM media_objects
             WHERE expires_at < now() AND status IN ('uploading','rejected'))
          + (SELECT count(*) FROM draft_mutation_requests
             WHERE created_at < now() - interval '24 hours')
          + (SELECT count(*) FROM media_group_send_requests
             WHERE created_at < now() - interval '24 hours') AS count`;
      const expiredMessages = await expiredMessageBacklog(sql);
      const deletedCount = drained.rows;
      const backlog = Number(backlogRows[0]?.count ?? 0) + expiredMessages;
      metrics?.recordCleanup(deletedCount, backlog);
      if (drained.rows > 0) {
        console.log(JSON.stringify({
          ts: new Date().toISOString(),
          event: "maintenance.cleanup",
          drained,
          backlog,
          capacity_per_category: CLEANUP_BATCH_SIZE,
        }));
      }
    } catch (error) {
      console.error(JSON.stringify({ ts: new Date().toISOString(), event: "maintenance.error", error: cleanError(error) }));
    } finally {
      running = false;
    }
  };
  const timer = setInterval(() => { void tick(); }, intervalMs);
  timer.unref?.();
  return () => clearInterval(timer);
}

export function logRequest(fields: {
  requestId: string; method: string; route: string; status: number; durationMs: number;
}): void {
  console.log(JSON.stringify({
    ts: new Date().toISOString(),
    event: "http.request",
    requestId: fields.requestId,
    method: fields.method,
    route: fields.route,
    status: fields.status,
    durationMs: Math.round(fields.durationMs * 10) / 10,
  }));
}
