// Direct CLI invocation must follow a symlink to index.js and still refuse to
// present a missing report as a clean scan. Importing the module stays quiet.
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { cliInvoked } from "../index.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const cli = path.join(root, "index.js");
const harmless = path.join(root, "fixtures/harmless");
const dangerous = path.join(root, "fixtures/env-exfil");

function run(script, args, extra = {}) {
  return spawnSync(process.execPath, [script, ...args], {
    cwd: root,
    encoding: "utf8",
    timeout: 20000,
    ...extra,
  });
}

test("a symlink argv writes skillguard.report.v1 for a harmless tree and exits 0", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "skillguard-entry-ok-"));
  const link = path.join(dir, "skillguard");
  const report = path.join(dir, "report.json");
  try {
    fs.symlinkSync(cli, link);
    const scan = run(link, [harmless, "--report", report, "--json"]);
    assert.equal(scan.status, 0, scan.stdout + scan.stderr);
    assert.notEqual(scan.stdout.trim(), "");
    assert.match(scan.stdout, /skillguard\.report\.v1/);
    const written = JSON.parse(fs.readFileSync(report, "utf8"));
    assert.equal(written.schema, "skillguard.report.v1");
    assert.equal(written.verdict, "clean");
    assert.equal(written.exitCode, 0);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("a symlink argv reports a dangerous fixture with exit 3", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "skillguard-entry-danger-"));
  const link = path.join(dir, "via-link.js");
  try {
    fs.symlinkSync(cli, link);
    const scan = run(link, [dangerous, "--json"]);
    assert.equal(scan.status, 3, scan.stdout + scan.stderr);
    assert.match(scan.stdout, /skillguard\.report\.v1/);
    const report = JSON.parse(scan.stdout);
    assert.equal(report.verdict, "dangerous");
    assert.equal(report.exitCode, 3);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("a path that realpaths to a different file does not run the CLI", () => {
  assert.equal(cliInvoked(path.join(root, "mcp.js")), false);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "skillguard-entry-import-"));
  const other = path.join(dir, "other.js");
  const href = pathToFileURL(cli).href;
  try {
    fs.writeFileSync(other, `import ${JSON.stringify(href)};\nconsole.log("imported-only");\n`);
    const scan = spawnSync(process.execPath, [other], {
      cwd: dir,
      encoding: "utf8",
      timeout: 20000,
    });
    assert.equal(scan.status, 0, scan.stdout + scan.stderr);
    assert.equal(scan.stdout.trim(), "imported-only");
    assert.equal(scan.stdout.includes("skillguard.report.v1"), false);
    assert.equal(scan.stderr.includes("Usage:"), false);
    assert.equal(scan.stderr.includes("no report"), false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("an unresolved direct entry exits 65 and says no report was produced", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "skillguard-entry-miss-"));
  const missing = path.join(dir, "index.js");
  const preload = path.join(dir, "preload.mjs");
  try {
    assert.throws(
      () => cliInvoked(missing),
      (error) => error && error.code === "unresolved-entry" && /no report/.test(error.message),
    );
    fs.writeFileSync(preload, [
      'import fs from "node:fs";',
      "const orig = fs.realpathSync.bind(fs);",
      "fs.realpathSync = (target, options) => {",
      "  if (String(target).includes(\"index.js\")) {",
      "    const error = new Error(\"realpath refused\");",
      "    error.code = \"ELOOP\";",
      "    throw error;",
      "  }",
      "  return orig(target, options);",
      "};",
      "",
    ].join("\n"));
    const scan = spawnSync(process.execPath, ["--import", pathToFileURL(preload).href, cli, harmless, "--json"], {
      cwd: root,
      encoding: "utf8",
      timeout: 20000,
    });
    assert.equal(scan.status, 65, scan.stdout + scan.stderr);
    assert.match(scan.stderr, /no report was produced/);
    assert.equal(scan.stdout.includes("skillguard.report.v1"), false);
    assert.equal(scan.stdout.trim(), "");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
