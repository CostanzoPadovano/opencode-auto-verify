import { lstat, mkdir, realpath, stat } from "node:fs/promises"
import path from "node:path"

function resolvedPath(value) {
  return path.resolve(value)
}

function sameResolvedPath(left, right) {
  return resolvedPath(left) === resolvedPath(right)
}

function isWithin(candidate, root) {
  const relative = path.relative(resolvedPath(root), resolvedPath(candidate))
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative))
}

export function createQuarantineLayout(quarantineRoot, source, options = {}) {
  const timestamp = options.timestamp ?? new Date().toISOString().replace(/[:.]/g, "-")
  const id = options.id
  if (!id) throw new Error("A unique quarantine layout id is required")

  const itemsRoot = path.join(quarantineRoot, "items")
  const container = path.join(itemsRoot, `${timestamp}_${id}`)
  const payload = path.join(container, "payload")
  return {
    itemsRoot,
    container,
    payload,
    destination: path.join(payload, path.basename(source)),
    manifest: path.join(container, "manifest.json"),
  }
}

export async function captureSourceIdentity(source) {
  const resolved = await realpath(source)
  if (!sameResolvedPath(resolved, source)) {
    throw new Error("AUTO_VERIFY_DENY: source_resolves_to_an_unexpected_location")
  }

  const info = await lstat(source)
  if (info.isSymbolicLink()) throw new Error("AUTO_VERIFY_DENY: source_became_a_symbolic_link")
  return {
    dev: String(info.dev),
    ino: String(info.ino),
    size: info.size,
    mtimeMs: info.mtimeMs,
  }
}

export async function assertSourceIdentity(source, expected) {
  const actual = await captureSourceIdentity(source)
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error("AUTO_VERIFY_DENY: source_changed_after_preview")
  }
  return actual
}

async function assertRealDirectory(directory, expectedParent) {
  const info = await lstat(directory)
  if (info.isSymbolicLink() || !info.isDirectory()) {
    throw new Error("AUTO_VERIFY_DENY: quarantine_path_component_is_not_a_real_directory")
  }
  const resolved = await realpath(directory)
  if (!sameResolvedPath(resolved, directory) || !isWithin(resolved, expectedParent)) {
    throw new Error("AUTO_VERIFY_DENY: quarantine_path_escapes_the_managed_root")
  }
  return { info, resolved }
}

async function ensureRealDirectoryTree(directory) {
  const target = resolvedPath(directory)
  const parsed = path.parse(target)
  const segments = path.relative(parsed.root, target).split(path.sep).filter(Boolean)
  let current = parsed.root

  for (const segment of segments) {
    current = path.join(current, segment)
    try {
      await mkdir(current, { recursive: false, mode: 0o700 })
    } catch (error) {
      if (error?.code !== "EEXIST") throw error
    }

    const info = await lstat(current)
    if (info.isSymbolicLink() || !info.isDirectory()) {
      throw new Error("AUTO_VERIFY_DENY: quarantine_path_component_is_not_a_real_directory")
    }
    const real = await realpath(current)
    if (!sameResolvedPath(real, current)) {
      throw new Error("AUTO_VERIFY_DENY: quarantine_path_escapes_the_managed_root")
    }
  }
  return target
}

export async function assertQuarantineDestination(layout, quarantineRoot) {
  const root = await assertRealDirectory(quarantineRoot, quarantineRoot)
  const items = await assertRealDirectory(layout.itemsRoot, root.resolved)
  const container = await assertRealDirectory(layout.container, items.resolved)
  const payload = await assertRealDirectory(layout.payload, container.resolved)
  if (!isWithin(layout.destination, payload.resolved) || !isWithin(layout.manifest, container.resolved)) {
    throw new Error("AUTO_VERIFY_DENY: quarantine_layout_escapes_the_verified_container")
  }
  return {
    quarantineRoot: root.resolved,
    itemsRoot: items.resolved,
    container: container.resolved,
    payload: payload.resolved,
  }
}

export async function prepareQuarantineDestination(layout, quarantineRoot, sourceDevice) {
  await ensureRealDirectoryTree(quarantineRoot)
  const root = await assertRealDirectory(quarantineRoot, quarantineRoot)
  if (String((await stat(root.resolved)).dev) !== String(sourceDevice)) {
    throw new Error("AUTO_VERIFY_DENY: cross-device quarantine requires a separately verified archive workflow")
  }

  try {
    await mkdir(layout.itemsRoot, { recursive: false, mode: 0o700 })
  } catch (error) {
    if (error?.code !== "EEXIST") throw error
  }
  await assertRealDirectory(layout.itemsRoot, root.resolved)

  try {
    await mkdir(layout.container, { recursive: false, mode: 0o700 })
  } catch (error) {
    if (error?.code === "EEXIST") {
      throw new Error("AUTO_VERIFY_DENY: quarantine_container_already_exists")
    }
    throw error
  }
  const container = await assertRealDirectory(layout.container, root.resolved)

  await mkdir(layout.payload, { recursive: false, mode: 0o700 })
  const payload = await assertRealDirectory(layout.payload, container.resolved)
  if (!isWithin(layout.destination, payload.resolved) || !isWithin(layout.manifest, container.resolved)) {
    throw new Error("AUTO_VERIFY_DENY: quarantine_layout_escapes_the_verified_container")
  }

  return assertQuarantineDestination(layout, quarantineRoot)
}
