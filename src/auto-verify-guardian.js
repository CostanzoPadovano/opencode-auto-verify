import { execFileSync } from "node:child_process"
import { randomUUID } from "node:crypto"
import { readFileSync } from "node:fs"
import { opendir, realpath, rename, stat, writeFile } from "node:fs/promises"
import path from "node:path"
import { fileURLToPath } from "node:url"
import { tool } from "@opencode-ai/plugin"

import {
  applyAutoVerifyEnv,
  DEFAULT_ALLOWED_ROOTS,
  DEFAULT_PROTECTED_PATHS,
  DEFAULT_QUARANTINE_ROOT,
  DEFAULT_ROUTINE_WRITABLE_ROOTS,
  PROTECTED_ROOT_SEMANTICS,
  classifyToolCall,
  mergeConversationRecords,
  normalizeUserPath,
  parseAutoVerifyEnv,
  parsePathList,
  parseReviewerVerdictWithRepair,
  reviewerResponseFormat,
  reviewerSystemPrompt,
  routerAuthorizationHeaders,
  sessionRoutineWritableRoots,
  selectReviewerTranscript,
  validateQuarantineTarget,
} from "./auto-verify-core.mjs"
import {
  assertQuarantineDestination,
  assertSourceIdentity,
  captureSourceIdentity,
  createQuarantineLayout,
  prepareQuarantineDestination,
} from "./quarantine-fs.mjs"

const DEFAULT_ENV_FILE = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "auto-verify.env",
)
const AUTO_VERIFY_ENV_FILE = process.env.OPENCODE_AUTO_VERIFY_ENV_FILE?.trim() || DEFAULT_ENV_FILE
let LOCAL_ENV = {}
try {
  LOCAL_ENV = parseAutoVerifyEnv(readFileSync(AUTO_VERIFY_ENV_FILE, "utf8"))
} catch {
  // A missing optional local environment file preserves explicit process env
  // and built-in defaults. Reviewer authentication will still fail closed.
}
const RUNTIME_ENV = applyAutoVerifyEnv({ ...process.env }, LOCAL_ENV)

const REVIEW_TIMEOUT_MS = Number(RUNTIME_ENV.OPENCODE_AUTO_VERIFY_TIMEOUT_MS || 180_000)
const REVIEW_OUTPUT_TOKENS = Number(RUNTIME_ENV.OPENCODE_AUTO_VERIFY_MAX_TOKENS || 8_192)
const REVIEW_REASONING_EFFORT = RUNTIME_ENV.OPENCODE_AUTO_VERIFY_REASONING_EFFORT || "xhigh"
const REVIEW_RESPONSE_FORMAT_MODE = (RUNTIME_ENV.OPENCODE_AUTO_VERIFY_RESPONSE_FORMAT || "json_schema")
  .trim()
  .toLowerCase()
const SCHEMA_REPAIR_OUTPUT_TOKENS = Number(RUNTIME_ENV.OPENCODE_AUTO_VERIFY_SCHEMA_REPAIR_MAX_TOKENS || 1_024)
const SCHEMA_REPAIR_REASONING_EFFORT = RUNTIME_ENV.OPENCODE_AUTO_VERIFY_SCHEMA_REPAIR_REASONING_EFFORT || "low"
const QUARANTINE_REVIEW_OUTPUT_TOKENS = Number(RUNTIME_ENV.OPENCODE_QUARANTINE_REVIEW_MAX_TOKENS || 2_048)
const QUARANTINE_REVIEW_REASONING_EFFORT = RUNTIME_ENV.OPENCODE_QUARANTINE_REVIEW_REASONING_EFFORT || "low"
const PREVIEW_TTL_MS = Number(RUNTIME_ENV.OPENCODE_QUARANTINE_PREVIEW_TTL_MS || 10 * 60_000)
const PREVIEW_SCAN_LIMIT = Number(RUNTIME_ENV.OPENCODE_QUARANTINE_SCAN_LIMIT || 20_000)

const ALLOWED_ROOTS = parsePathList(RUNTIME_ENV.OPENCODE_QUARANTINE_ALLOWED_ROOTS, DEFAULT_ALLOWED_ROOTS)
const PROTECTED_PATHS = parsePathList(RUNTIME_ENV.OPENCODE_PROTECTED_PATHS, DEFAULT_PROTECTED_PATHS)
const ROUTINE_WRITABLE_ROOTS = parsePathList(
  RUNTIME_ENV.OPENCODE_AUTO_VERIFY_WRITABLE_ROOTS,
  DEFAULT_ROUTINE_WRITABLE_ROOTS,
)
const QUARANTINE_ROOT = normalizeUserPath(RUNTIME_ENV.OPENCODE_QUARANTINE_ROOT || DEFAULT_QUARANTINE_ROOT)

const sessionState = new Map()
const pendingQuarantines = new Map()

function windowsHost() {
  if (RUNTIME_ENV.LLAMA_ROUTER_WINDOWS_HOST) return RUNTIME_ENV.LLAMA_ROUTER_WINDOWS_HOST
  try {
    const route = execFileSync("ip", ["route", "show", "default"], { encoding: "utf8" })
    return route.match(/\bvia\s+(\S+)/)?.[1] || "172.19.48.1"
  } catch {
    return "172.19.48.1"
  }
}

function reviewerBaseUrl(providerID) {
  if (RUNTIME_ENV.OPENCODE_AUTO_VERIFY_BASE_URL) {
    return RUNTIME_ENV.OPENCODE_AUTO_VERIFY_BASE_URL.replace(/\/+$/, "")
  }
  const host = windowsHost()
  return `http://${host}:${RUNTIME_ENV.LLAMA_ROUTER_PORT || 8030}/v1`
}

async function log(client, level, message, extra = {}) {
  try {
    await client.app.log({
      body: { service: "auto-verify", level, message, extra },
    })
  } catch {
    // A logging outage must not change an authorization verdict.
  }
}

function responseData(response) {
  if (Array.isArray(response)) return response
  if (Array.isArray(response?.data)) return response.data
  return []
}

async function sessionRecords(client, sessionID) {
  const observed = sessionState.get(sessionID)?.records ?? []
  try {
    const response = await client.session.messages({
      path: { id: sessionID },
      query: { limit: 500 },
    })
    const records = responseData(response)
    if (records.length) return mergeConversationRecords(records, observed)
  } catch {
    // Fall through to the messages observed since plugin startup.
  }
  return observed
}

function currentModel(records, sessionID) {
  const cached = sessionState.get(sessionID)
  if (cached?.model?.modelID) return cached.model
  for (let index = records.length - 1; index >= 0; index -= 1) {
    const info = records[index]?.info
    if (info?.role === "user" && info.model?.modelID) return info.model
  }
  return undefined
}

function sanitizedArgs(args) {
  if (!args || typeof args !== "object") return args
  const result = Array.isArray(args) ? [] : {}
  for (const [key, value] of Object.entries(args)) {
    if (["description", "justification", "reason", "summary"].includes(key.toLowerCase())) continue
    result[key] = value && typeof value === "object" ? sanitizedArgs(value) : value
  }
  return result
}

function extractContent(payload) {
  return payload?.choices?.[0]?.message?.content ?? payload?.output_text ?? ""
}

function configuredReviewerResponseFormat() {
  if (REVIEW_RESPONSE_FORMAT_MODE === "off") return null
  if (REVIEW_RESPONSE_FORMAT_MODE === "json_object") return { type: "json_object" }
  return reviewerResponseFormat()
}

async function modelReview({
  client,
  sessionID,
  toolName,
  args,
  classification,
  effects,
  reasoningEffort = REVIEW_REASONING_EFFORT,
  maxTokens = REVIEW_OUTPUT_TOKENS,
}) {
  const records = await sessionRecords(client, sessionID)
  const model = currentModel(records, sessionID)
  const modelID = RUNTIME_ENV.OPENCODE_AUTO_VERIFY_MODEL || model?.modelID
  const providerID = RUNTIME_ENV.OPENCODE_AUTO_VERIFY_PROVIDER || model?.providerID || "llama_router"

  if (!modelID) {
    return { allow: false, decision: "deny", reason: "reviewer_model_not_resolved", violations: ["no_reviewer_model"] }
  }

  const transcript = selectReviewerTranscript(records)
  if (!transcript.length) {
    return { allow: false, decision: "deny", reason: "no_user_request_available", violations: ["missing_user_context"] }
  }

  const envelope = {
    conversation_context: transcript,
    proposed_action: {
      tool: toolName,
      arguments: sanitizedArgs(args),
      deterministic_classification: classification,
      resolved_effects: effects ?? null,
    },
    execution_context: {
      session_id: sessionID,
      working_directory: sessionState.get(sessionID)?.directory ?? null,
      bulk_removal_protected_roots: PROTECTED_PATHS,
      protected_root_semantics: PROTECTED_ROOT_SEMANTICS,
      routine_writable_roots: sessionRoutineWritableRoots(
        sessionState.get(sessionID)?.directory,
        ROUTINE_WRITABLE_ROOTS,
      ),
      quarantine_root: QUARANTINE_ROOT,
    },
  }

  const headers = {
    "Content-Type": "application/json",
    ...routerAuthorizationHeaders(RUNTIME_ENV, (file) => readFileSync(file, "utf8")),
  }

  const requestCompletion = async ({ reviewEnvelope, effort, tokenBudget }) => {
    const body = {
      model: modelID,
      messages: [
        { role: "system", content: reviewerSystemPrompt() },
        { role: "user", content: JSON.stringify(reviewEnvelope) },
      ],
      reasoning_effort: effort,
      temperature: 0,
      top_p: 1,
      max_tokens: tokenBudget,
      stream: false,
    }
    const responseFormat = configuredReviewerResponseFormat()
    if (responseFormat) body.response_format = responseFormat

    let response
    try {
      response = await fetch(`${reviewerBaseUrl(providerID)}/chat/completions`, {
        method: "POST",
        headers,
        signal: AbortSignal.timeout(REVIEW_TIMEOUT_MS),
        body: JSON.stringify(body),
      })
    } catch (error) {
      return {
        ok: false,
        verdict: {
          allow: false,
          decision: "deny",
          reason: `reviewer_unavailable: ${String(error)}`,
          violations: ["reviewer_unavailable"],
        },
      }
    }

    if (!response.ok) {
      const authenticationFailure = response.status === 401 || response.status === 403
      return {
        ok: false,
        verdict: {
          allow: false,
          decision: "deny",
          reason: authenticationFailure
            ? `reviewer_http_${response.status}: configure LLAMA_ROUTER_API_KEY or LLAMA_ROUTER_KEY_FILE in ${AUTO_VERIFY_ENV_FILE}`
            : `reviewer_http_${response.status}`,
          violations: [authenticationFailure ? "reviewer_authentication_error" : "reviewer_http_error"],
        },
      }
    }

    let payload
    try {
      payload = await response.json()
    } catch {
      return {
        ok: false,
        verdict: {
          allow: false,
          decision: "deny",
          reason: "reviewer_non_json_response",
          violations: ["reviewer_parse_error"],
        },
      }
    }
    return { ok: true, content: extractContent(payload) }
  }

  const initial = await requestCompletion({
    reviewEnvelope: envelope,
    effort: reasoningEffort,
    tokenBudget: maxTokens,
  })
  if (!initial.ok) return initial.verdict

  return parseReviewerVerdictWithRepair(initial.content, async ({ schemaErrors, previousVerdict }) => {
    const repair = await requestCompletion({
      reviewEnvelope: {
        ...envelope,
        reviewer_protocol: {
          attempt: 2,
          final_attempt: true,
          schema_errors: schemaErrors,
          previous_verdict: previousVerdict,
          instruction:
            "Return one complete schema-valid verdict for the same action. Preserve valid prior fields, never change negative evidence into permission, always include violations ([] when none), and keep reason concise.",
        },
      },
      effort: SCHEMA_REPAIR_REASONING_EFFORT,
      tokenBudget: SCHEMA_REPAIR_OUTPUT_TOKENS,
    })
    if (!repair.ok) throw new Error(repair.verdict.reason)
    return repair.content
  })
}

async function boundedInventory(root, limit = PREVIEW_SCAN_LIMIT) {
  const rootInfo = await stat(root)
  if (!rootInfo.isDirectory()) {
    return { entries: 1, bytes: rootInfo.size, truncated: false }
  }

  let entries = 1
  let bytes = 0
  const queue = [root]
  while (queue.length && entries < limit) {
    const current = queue.shift()
    const directory = await opendir(current)
    for await (const item of directory) {
      entries += 1
      if (entries > limit) break
      const candidate = path.posix.join(current, item.name)
      if (item.isDirectory()) queue.push(candidate)
      else if (item.isFile()) {
        try {
          bytes += (await stat(candidate)).size
        } catch {
          // Inventory is advisory; commit revalidates the source identity.
        }
      }
    }
  }
  return { entries: Math.min(entries, limit), bytes, truncated: entries >= limit || queue.length > 0 }
}

function prunePending() {
  const now = Date.now()
  for (const [token, item] of pendingQuarantines) {
    if (item.expiresAt <= now) pendingQuarantines.delete(token)
  }
}

async function previewQuarantine(args, context) {
  prunePending()
  const validation = validateQuarantineTarget(args.target, {
    cwd: context.directory,
    allowedRoots: ALLOWED_ROOTS,
    protectedPaths: PROTECTED_PATHS,
  })
  if (!validation.ok) {
    throw new Error(`AUTO_VERIFY_DENY: ${validation.reason}: ${validation.normalized}`)
  }

  const source = await realpath(validation.normalized)
  const realValidation = validateQuarantineTarget(source, {
    cwd: context.directory,
    allowedRoots: ALLOWED_ROOTS,
    protectedPaths: PROTECTED_PATHS,
  })
  if (!realValidation.ok) throw new Error(`AUTO_VERIFY_DENY: resolved_${realValidation.reason}: ${source}`)

  const sourceIdentity = await captureSourceIdentity(source)
  const inventory = await boundedInventory(source)
  const destination = createQuarantineLayout(QUARANTINE_ROOT, source, { id: randomUUID() })
  const token = randomUUID()
  const preview = {
    token,
    source,
    destination: destination.destination,
    reason: args.reason || "not supplied",
    inventory,
    inside_protected_tree: realValidation.insideProtectedTree ?? null,
    expires_at: new Date(Date.now() + PREVIEW_TTL_MS).toISOString(),
  }

  pendingQuarantines.set(token, {
    ...preview,
    ...destination,
    sessionID: context.sessionID,
    expiresAt: Date.now() + PREVIEW_TTL_MS,
    sourceIdentity,
  })
  context.metadata({ title: "Quarantine preview", metadata: preview })
  return JSON.stringify({ status: "preview_only_no_files_moved", ...preview }, null, 2)
}

async function commitQuarantine(args, context, client) {
  prunePending()
  const pending = pendingQuarantines.get(args.token)
  if (!pending) throw new Error("AUTO_VERIFY_DENY: missing_or_expired_quarantine_preview")
  if (pending.sessionID !== context.sessionID) throw new Error("AUTO_VERIFY_DENY: preview_belongs_to_another_session")

  try {
    await assertSourceIdentity(pending.source, pending.sourceIdentity)
  } catch (error) {
    pendingQuarantines.delete(args.token)
    throw error
  }

  const classification = { level: "review", reason: "quarantine_commit" }
  const verdict = await modelReview({
    client,
    sessionID: context.sessionID,
    toolName: "safe_quarantine_commit",
    args: { token: args.token },
    classification,
    effects: {
      operation: "reversible_move_to_managed_quarantine",
      source: pending.source,
      destination: pending.destination,
      inventory: pending.inventory,
      inside_protected_tree: pending.inside_protected_tree,
    },
    reasoningEffort: QUARANTINE_REVIEW_REASONING_EFFORT,
    maxTokens: QUARANTINE_REVIEW_OUTPUT_TOKENS,
  })
  await log(client, verdict.allow ? "info" : "warn", "Quarantine commit reviewed", {
    sessionID: context.sessionID,
    source: pending.source,
    destination: pending.destination,
    decision: verdict.decision,
    reason: verdict.reason,
    violations: verdict.violations,
    reasoningEffort: QUARANTINE_REVIEW_REASONING_EFFORT,
    repairAttempted: verdict.repairAttempted ?? false,
    schemaErrors: verdict.schemaErrors ?? [],
    initialSchemaErrors: verdict.initialSchemaErrors ?? [],
  })
  if (!verdict.allow) {
    throw new Error(`AUTO_VERIFY_DENY: ${verdict.reason}; violations=${JSON.stringify(verdict.violations ?? [])}`)
  }

  let postReviewIdentity
  try {
    postReviewIdentity = await assertSourceIdentity(pending.source, pending.sourceIdentity)
    const currentInventory = await boundedInventory(pending.source)
    if (JSON.stringify(currentInventory) !== JSON.stringify(pending.inventory)) {
      throw new Error("AUTO_VERIFY_DENY: source_inventory_changed_after_preview")
    }
  } catch (error) {
    pendingQuarantines.delete(args.token)
    throw error
  }

  await prepareQuarantineDestination(pending, QUARANTINE_ROOT, postReviewIdentity.dev)
  await assertSourceIdentity(pending.source, pending.sourceIdentity)
  await assertQuarantineDestination(pending, QUARANTINE_ROOT)
  try {
    await rename(pending.source, pending.destination)
  } catch (error) {
    if (error?.code === "EXDEV") {
      throw new Error("AUTO_VERIFY_DENY: cross-device quarantine requires a separately verified archive workflow")
    }
    throw error
  }

  const manifest = {
    schema: "opencode-agent-quarantine/v1",
    quarantined_at: new Date().toISOString(),
    session_id: context.sessionID,
    original_path: pending.source,
    quarantined_path: pending.destination,
    user_reason: pending.reason,
    inventory: pending.inventory,
    reviewer: {
      decision: verdict.decision,
      reason: verdict.reason,
      violations: verdict.violations ?? [],
    },
  }
  pendingQuarantines.delete(args.token)
  let manifestWarning = null
  try {
    await writeFile(pending.manifest, `${JSON.stringify(manifest, null, 2)}\n`, { encoding: "utf8", flag: "wx" })
  } catch (error) {
    manifestWarning = `Data was quarantined successfully, but the manifest could not be written: ${String(error)}`
    await log(client, "error", "Quarantine manifest write failed after successful move", {
      sessionID: context.sessionID,
      source: pending.source,
      destination: pending.destination,
      error: String(error),
    })
  }
  context.metadata({ title: "Moved to managed quarantine", metadata: manifest })
  return JSON.stringify({ status: "quarantined_reversible", manifest_warning: manifestWarning, ...manifest }, null, 2)
}

export const AutoVerifyGuardian = async ({ client, directory }) => {
  await log(client, "info", "Auto-Verify guardian loaded", {
    directory,
    allowedRoots: ALLOWED_ROOTS,
    protectedPaths: PROTECTED_PATHS,
    routineWritableRoots: sessionRoutineWritableRoots(directory, ROUTINE_WRITABLE_ROOTS),
    quarantineRoot: QUARANTINE_ROOT,
    failMode: "closed",
  })

  return {
  "chat.message": async (input, output) => {
    if (output.message?.role !== "user") return
    const current = sessionState.get(input.sessionID) ?? { records: [] }
    current.records.push({ info: output.message, parts: output.parts })
    current.model = input.model ?? output.message.model ?? current.model
    current.variant = input.variant ?? current.variant
    current.directory = directory
    sessionState.set(input.sessionID, current)
  },

  "tool.execute.before": async (input, output) => {
    const workingDirectory = sessionState.get(input.sessionID)?.directory ?? directory
    const classification = classifyToolCall(input.tool, output.args, {
      cwd: workingDirectory,
      routineWritableRoots: sessionRoutineWritableRoots(workingDirectory, ROUTINE_WRITABLE_ROOTS),
    })
    if (classification.level === "allow") return
    if (classification.level === "block") {
      await log(client, "warn", "Permanent destructive command blocked", {
        sessionID: input.sessionID,
        tool: input.tool,
        reason: classification.reason,
      })
      throw new Error(
        `AUTO_VERIFY_DENY: permanent destructive operation '${classification.reason}' is disabled; use safe_quarantine_preview`,
      )
    }

    const verdict = await modelReview({
      client,
      sessionID: input.sessionID,
      toolName: input.tool,
      args: output.args,
      classification,
    })
    await log(client, verdict.allow ? "info" : "warn", "Tool call reviewed", {
      sessionID: input.sessionID,
      tool: input.tool,
      classification: classification.reason,
      decision: verdict.decision,
      reason: verdict.reason,
      violations: verdict.violations,
      repairAttempted: verdict.repairAttempted ?? false,
      schemaErrors: verdict.schemaErrors ?? [],
      initialSchemaErrors: verdict.initialSchemaErrors ?? [],
    })
    if (!verdict.allow) {
      throw new Error(`AUTO_VERIFY_DENY: ${verdict.reason}; violations=${JSON.stringify(verdict.violations ?? [])}`)
    }
  },

  tool: {
    safe_quarantine_preview: tool({
      description:
        "Preview a reversible move into the managed agent quarantine. This never moves or deletes data and returns a short-lived commit token.",
      args: {
        target: tool.schema.string().describe("One exact absolute or workspace-relative path; wildcards are forbidden"),
        reason: tool.schema.string().optional().describe("Why the user requested removal"),
      },
      execute: previewQuarantine,
    }),
    safe_quarantine_commit: tool({
      description:
        "Commit one previously previewed quarantine move. A fresh, independently configured reviewer checks the complete user request before any move.",
      args: {
        token: tool.schema.string().uuid().describe("The unexpired token returned by safe_quarantine_preview"),
      },
      execute: (args, context) => commitQuarantine(args, context, client),
    }),
  },
  }
}
