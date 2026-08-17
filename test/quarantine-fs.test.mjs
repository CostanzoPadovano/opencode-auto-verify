import assert from "node:assert/strict"
import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import test from "node:test"

import {
  assertSourceIdentity,
  captureSourceIdentity,
  createQuarantineLayout,
  prepareQuarantineDestination,
} from "../src/quarantine-fs.mjs"

async function temporaryRoot(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), "opencode-auto-verify-"))
  t.after(() => rm(root, { recursive: true, force: true }))
  return root
}

test("separates payload data from the quarantine manifest", async (t) => {
  const root = await temporaryRoot(t)
  const source = path.join(root, "workspace", "manifest.json")
  const quarantine = path.join(root, "quarantine")
  await mkdir(path.dirname(source), { recursive: true })
  await writeFile(source, "scientific data")

  const layout = createQuarantineLayout(quarantine, source, {
    timestamp: "2026-08-17T00-00-00Z",
    id: "00000000-0000-4000-8000-000000000000",
  })
  assert.notEqual(layout.destination, layout.manifest)
  assert.equal(path.dirname(layout.destination), layout.payload)
  assert.equal(path.dirname(layout.manifest), layout.container)

  const identity = await captureSourceIdentity(source)
  const prepared = await prepareQuarantineDestination(layout, quarantine, identity.dev)
  assert.equal(prepared.container, path.resolve(layout.container))
})

test("detects source replacement after preview", async (t) => {
  const root = await temporaryRoot(t)
  const source = path.join(root, "source.txt")
  await writeFile(source, "first")
  const identity = await captureSourceIdentity(source)
  await writeFile(source, "second and different")
  await assert.rejects(assertSourceIdentity(source, identity), /source_changed_after_preview/)
})

test(
  "rejects an items symlink that redirects quarantine output",
  async (t) => {
    const root = await temporaryRoot(t)
    const source = path.join(root, "workspace", "source.txt")
    const quarantine = path.join(root, "quarantine")
    const outside = path.join(root, "outside")
    await mkdir(path.dirname(source), { recursive: true })
    await mkdir(quarantine)
    await mkdir(outside)
    await writeFile(source, "protected data")
    await symlink(outside, path.join(quarantine, "items"), process.platform === "win32" ? "junction" : "dir")

    const identity = await captureSourceIdentity(source)
    const layout = createQuarantineLayout(quarantine, source, {
      timestamp: "2026-08-17T00-00-00Z",
      id: "00000000-0000-4000-8000-000000000001",
    })
    await assert.rejects(
      prepareQuarantineDestination(layout, quarantine, identity.dev),
      /quarantine_path_component_is_not_a_real_directory/,
    )
  },
)
