import { existsSync } from "node:fs"
import { copyFile, mkdir, readFile, rename, writeFile } from "node:fs/promises"
import path from "node:path"
import { fileURLToPath } from "node:url"

const scriptRoot = path.dirname(fileURLToPath(import.meta.url))
const projectRoot = path.dirname(scriptRoot)
const sourceRoot = path.join(projectRoot, "src")
const configRoot = process.argv[2]
const apply = process.argv.includes("--apply")

if (!configRoot) {
  throw new Error("Usage: node scripts/install.mjs <OpenCode config directory> [--apply]")
}

const agentsBeginMarker = "<!-- BEGIN OPENCODE AUTO-VERIFY -->"
const agentsEndMarker = "<!-- END OPENCODE AUTO-VERIFY -->"
const timestamp = new Date().toISOString().replace(/[:.]/g, "-")

const agentsFile = path.join(configRoot, "AGENTS.md")
const environmentFile = path.join(configRoot, "auto-verify.env")
const pluginsDir = path.join(configRoot, "plugins")
const pluginFile = path.join(pluginsDir, "auto-verify-guardian.js")
const coreFile = path.join(pluginsDir, "auto-verify-core.mjs")
const quarantineFile = path.join(pluginsDir, "quarantine-fs.mjs")

function mergeAgentsFile(existing, staged) {
  const beginCount = existing.split(agentsBeginMarker).length - 1
  const endCount = existing.split(agentsEndMarker).length - 1
  if (beginCount !== endCount || beginCount > 1) {
    throw new Error("AGENTS.md contains incomplete or duplicate Auto-Verify marker blocks; refusing to edit it")
  }

  const begin = existing.indexOf(agentsBeginMarker)
  const end = existing.indexOf(agentsEndMarker)
  if (begin >= 0 && end > begin) {
    const after = end + agentsEndMarker.length
    return `${existing.slice(0, begin)}${staged.trim()}${existing.slice(after)}`
  }

  return `${existing.trimEnd()}${existing.trim() ? "\n\n" : ""}${staged.trim()}\n`
}

async function backupIfPresent(file) {
  if (!existsSync(file)) return null
  const backup = `${file}.bak-auto-verify-${timestamp}`
  await copyFile(file, backup)
  return backup
}

async function atomicCopy(source, destination) {
  const temporary = `${destination}.tmp-auto-verify-${timestamp}`
  await copyFile(source, temporary)
  await rename(temporary, destination)
}

const existingAgents = existsSync(agentsFile) ? await readFile(agentsFile, "utf8") : ""
const stagedAgents = await readFile(path.join(projectRoot, "policy", "AGENTS.md"), "utf8")
const mergedAgents = mergeAgentsFile(existingAgents, stagedAgents)

const report = {
  mode: apply ? "apply" : "dry-run",
  config_root: configRoot,
  agents_patch_required: mergedAgents !== existingAgents,
  plugin_target: pluginFile,
  core_target: coreFile,
  quarantine_target: quarantineFile,
  permissions_example: path.join(projectRoot, "examples", "opencode.permissions.jsonc"),
  environment_example: path.join(projectRoot, "examples", "server.env.example"),
  environment_target: environmentFile,
  environment_file_present: existsSync(environmentFile),
}

if (!apply) {
  console.log(JSON.stringify(report, null, 2))
  process.exit(0)
}

await mkdir(pluginsDir, { recursive: true })
const backups = []
for (const file of [agentsFile, pluginFile, coreFile, quarantineFile]) {
  const backup = await backupIfPresent(file)
  if (backup) backups.push(backup)
}

if (mergedAgents !== existingAgents) {
  const temporary = `${agentsFile}.tmp-auto-verify-${timestamp}`
  await writeFile(temporary, mergedAgents, { encoding: "utf8", flag: "wx" })
  await rename(temporary, agentsFile)
}

await atomicCopy(path.join(sourceRoot, "auto-verify-guardian.js"), pluginFile)
await atomicCopy(path.join(sourceRoot, "auto-verify-core.mjs"), coreFile)
await atomicCopy(path.join(sourceRoot, "quarantine-fs.mjs"), quarantineFile)

console.log(JSON.stringify({ ...report, backups }, null, 2))
