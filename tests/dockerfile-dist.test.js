import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFileSync, existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const repo = dirname(dirname(fileURLToPath(import.meta.url)));
const PIN = "951230b727b84b95d3ce438a6aaa5bace381f820";

function copySources(text) {
  const sources = [];
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line.startsWith("COPY ")) continue;
    const parts = line.split(/\s+/);
    parts.shift();
    parts.pop();
    sources.push(...parts);
  }
  return sources;
}

function gitShow(spec) {
  const ran = spawnSync("git", ["show", spec], { cwd: repo, encoding: "utf8" });
  assert.equal(ran.status, 0, ran.stderr);
  return ran.stdout;
}

function applyCopy(sources, dest) {
  for (const name of sources) copyFileSync(join(repo, name), join(dest, name));
}

function runCli(imageRoot, args) {
  const env = { ...process.env };
  delete env.FORCE_COLOR;
  delete env.NO_COLOR;
  return spawnSync(process.execPath, [join(imageRoot, "index.js"), ...args], {
    encoding: "utf8",
    env,
  });
}

test("image copy includes report.js and the pin copy list does not", () => {
  const pinDocker = gitShow(`${PIN}:Dockerfile`);
  const headDocker = readFileSync(join(repo, "Dockerfile"), "utf8");
  const pinSources = copySources(pinDocker);
  const headSources = copySources(headDocker);
  process.stdout.write(`PIN_COPY:${pinSources.join(",")}\n`);
  process.stdout.write(`HEAD_COPY:${headSources.join(",")}\n`);

  const DIST = "56d59b5e2821ad1d72d1823f450e5cc797bdf5f4";
  const distSources = copySources(gitShow(`${DIST}:Dockerfile`));
  assert.deepEqual(pinSources, ["package.json", "index.js", "mcp.js"]);
  assert.equal(pinSources.includes("report.js"), false);
  assert.deepEqual(distSources, ["package.json", "index.js", "mcp.js", "report.js"]);
  assert.deepEqual(headSources, ["package.json", "index.js", "mcp.js", "report.js", "report.schema.json", "version.js", "rules.js", "secrets.js"]);
  assert.match(pinDocker, /ENTRYPOINT \["node", "mcp\.js"\]/);
  assert.match(headDocker, /ENTRYPOINT \["node", "mcp\.js"\]/);
  assert.doesNotMatch(readFileSync(join(repo, "mcp.js"), "utf8"), /report\.js/);

  const head = spawnSync("git", ["rev-parse", "HEAD"], { cwd: repo, encoding: "utf8" });
  assert.equal(head.status, 0, head.stderr);
  const dirty = spawnSync("git", ["status", "--porcelain"], { cwd: repo, encoding: "utf8" });
  if (head.stdout.trim() !== PIN && !dirty.stdout.trim()) {
    assert.equal(gitShow("HEAD:Dockerfile"), headDocker);
  }

  const image = mkdtempSync(join(tmpdir(), "sg-image-"));
  const omitted = mkdtempSync(join(tmpdir(), "sg-image-omit-"));
  const reportPath = join(image, "harmless-report.json");
  const envReport = join(image, "env-report.json");
  const harmless = join(repo, "fixtures/harmless");
  const envExfil = join(repo, "fixtures/env-exfil");
  try {
    applyCopy(headSources, image);
    assert.equal(existsSync(join(image, "report.js")), true);
    process.stdout.write("ROOTFS_REPORT_JS:present\n");

    const clean = runCli(image, [harmless, "--report", reportPath, "--json"]);
    process.stdout.write(`HARMLESS_FROM_ROOTFS_EXIT:${clean.status}\n`);
    assert.equal(clean.status, 0, clean.stderr);
    const cleanReport = JSON.parse(clean.stdout);
    assert.equal(cleanReport.schema, "skillguard.report.v1");
    assert.equal(cleanReport.verdict, "clean");
    assert.equal(cleanReport.blanketSafetyScore, null);
    assert.equal(cleanReport.scanner.executedTarget, false);
    assert.equal(existsSync(join(harmless, "EXECUTED")), false);
    assert.equal(existsSync(reportPath), true);

    const danger = runCli(image, [envExfil, "--report", envReport, "--json"]);
    process.stdout.write(`ENV_FROM_ROOTFS_EXIT:${danger.status}\n`);
    assert.equal(danger.status, 3, danger.stderr);
    assert.equal(existsSync(join(envExfil, "EXECUTED")), false);

    const shown = runCli(image, ["--show-report", reportPath]);
    process.stdout.write(`HARMLESS_SHOW_EXIT:${shown.status}\n`);
    assert.equal(shown.status, 66, shown.stdout + shown.stderr);
    assert.match(shown.stdout, /unverified:/);
    assert.equal(shown.stdout.includes("\u001b"), false);
    const shownDanger = runCli(image, ["--show-report", envReport]);
    process.stdout.write(`ENV_SHOW_EXIT:${shownDanger.status}\n`);
    assert.equal(shownDanger.status, 66, shownDanger.stdout + shownDanger.stderr);
    assert.match(shownDanger.stdout, /unverified:/);
    assert.match(shownDanger.stdout, /verdict: dangerous/);
    assert.doesNotMatch(shownDanger.stdout, /^unverified:.*\n0\n/);

    applyCopy(headSources.filter((name) => name !== "report.js"), omitted);
    assert.equal(existsSync(join(omitted, "report.js")), false);
    const missing = runCli(omitted, [harmless, "--report", join(omitted, "missing.json"), "--json"]);
    process.stdout.write(`MISSING_REPORT_JS_EXIT:${missing.status}\n`);
    assert.equal(missing.status, 65, missing.stdout + missing.stderr);
    assert.match(missing.stderr, /report\.js/);
  } finally {
    rmSync(image, { recursive: true, force: true });
    rmSync(omitted, { recursive: true, force: true });
  }
});
