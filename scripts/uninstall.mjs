import { existsSync } from "node:fs"
import { copyFile, mkdir, readFile, rename, writeFile } from "node:fs/promises"
import path from "node:path"

const configRoot = process.argv[2]
const apply = process.argv.includes("--apply")

if (!configRoot) {
  throw new Error("Usage: node scripts/uninstall.mjs <OpenCode config directory> [--apply]")
}

const beginMarker = "<!-- BEGIN OPENCODE AUTO-VERIFY -->"
const endMarker = "<!-- END OPENCODE AUTO-VERIFY -->"
const timestamp = new Date().toISOString().replace(/[:.]/g, "-")
const agentsFile = path.join(configRoot, "AGENTS.md")
const pluginFiles = [
  path.join(configRoot, "plugins", "auto-verify-guardian.js"),
  path.join(configRoot, "plugins", "auto-verify-core.mjs"),
  path.join(configRoot, "plugins", "quarantine-fs.mjs"),
]
const disabledRoot = path.join(configRoot, "auto-verify-disabled", timestamp)

function withoutManagedPolicy(existing) {
  const beginCount = existing.split(beginMarker).length - 1
  const endCount = existing.split(endMarker).length - 1
  if (beginCount !== endCount || beginCount > 1) {
    throw new Error("AGENTS.md contains incomplete or duplicate Auto-Verify marker blocks; refusing to edit it")
  }

  const begin = existing.indexOf(beginMarker)
  const end = existing.indexOf(endMarker)
  if (begin < 0 && end < 0) return { found: false, content: existing }
  if (begin < 0 || end < begin) {
    throw new Error("AGENTS.md contains an incomplete Auto-Verify marker block; refusing to edit it")
  }

  const after = end + endMarker.length
  const prefix = existing.slice(0, begin).trimEnd()
  const suffix = existing.slice(after).trimStart()
  const joined = [prefix, suffix].filter(Boolean).join("\n\n")
  return { found: true, content: joined ? `${joined}\n` : "" }
}

const existingAgents = existsSync(agentsFile) ? await readFile(agentsFile, "utf8") : ""
const policy = withoutManagedPolicy(existingAgents)
const presentPlugins = pluginFiles.filter((file) => existsSync(file))
const report = {
  mode: apply ? "apply" : "dry-run",
  config_root: configRoot,
  managed_policy_found: policy.found,
  installed_modules_found: presentPlugins,
  disabled_modules_destination: disabledRoot,
  quarantine_contents_touched: false,
}

if (!apply) {
  console.log(JSON.stringify(report, null, 2))
  process.exit(0)
}

const backups = []
if (policy.found) {
  const backup = `${agentsFile}.bak-auto-verify-uninstall-${timestamp}`
  await copyFile(agentsFile, backup)
  backups.push(backup)
  const temporary = `${agentsFile}.tmp-auto-verify-${timestamp}`
  await writeFile(temporary, policy.content, { encoding: "utf8", flag: "wx" })
  await rename(temporary, agentsFile)
}

const disabledModules = []
if (presentPlugins.length) await mkdir(disabledRoot, { recursive: true })
for (const source of presentPlugins) {
  const destination = path.join(disabledRoot, path.basename(source))
  await rename(source, destination)
  disabledModules.push(destination)
}

console.log(JSON.stringify({ ...report, backups, disabled_modules: disabledModules }, null, 2))
