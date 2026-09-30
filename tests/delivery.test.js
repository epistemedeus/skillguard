import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { analyze } from "../index.js";
import { buildReport, readReport, validateReport } from "../report.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const cli = path.join(root, "index.js");
const fixturesDir = path.join(root, "fixtures");

function run(args) {
  return spawnSync(process.execPath, [cli, ...args], {
    cwd: root,
    encoding: "utf8",
    timeout: 20000,
  });
}

function clearCanary(dir) {
  const marker = path.join(dir, "EXECUTED");
  if (fs.existsSync(marker)) fs.unlinkSync(marker);
  return marker;
}

function rules(findings, severity) {
  return findings.filter((finding) => finding.severity === severity).map((finding) => finding.rule).sort();
}

const manifest = JSON.parse(fs.readFileSync(path.join(fixturesDir, "manifest.json"), "utf8"));

test("fixture manifest freezes the three static samples", () => {
  assert.equal(manifest.staticOnly, true);
  assert.deepEqual(manifest.fixtures.map((fixture) => fixture.id), ["harmless", "prompt-injection", "env-exfil"]);
  for (const fixture of manifest.fixtures) {
    const dir = path.join(fixturesDir, fixture.path);
    assert.equal(fs.statSync(dir).isDirectory(), true);
    assert.equal(fs.existsSync(path.join(dir, "EXECUTED")), false);
  }
});

test("harmless fixture does not false-danger without an exfil host", () => {
  const dir = path.join(fixturesDir, "harmless");
  const marker = clearCanary(dir);
  const source = fs.readFileSync(path.join(dir, "index.js"), "utf8");
  assert.match(source, /ANTHROPIC_API_KEY/);
  assert.match(source, /api\.anthropic\.com/);
  assert.match(source, /\bfetch\b/);
  const scanned = analyze(dir);
  assert.equal(scanned.verdict, "clean");
  assert.equal(scanned.dangers.length, 0);
  const cliResult = run([dir]);
  assert.equal(cliResult.status, 0, cliResult.stdout + cliResult.stderr);
  assert.match(cliResult.stdout, /No known-malicious patterns found/);
  assert.doesNotMatch(cliResult.stdout, /DANGER/);
  assert.equal(fs.existsSync(marker), false);
});

test("seeded prompt-injection fixture fails closed", () => {
  const dir = path.join(fixturesDir, "prompt-injection");
  const marker = clearCanary(dir);
  const skill = fs.readFileSync(path.join(dir, "SKILL.md"), "utf8");
  assert.match(skill, /ignore previous instructions/);
  assert.match(skill, /do not tell the user/);
  const cliResult = run([dir]);
  assert.equal(cliResult.status, 3, cliResult.stdout + cliResult.stderr);
  assert.match(cliResult.stdout, /\[prompt-injection\]/);
  assert.match(cliResult.stdout, /DANGEROUS/);
  assert.equal(fs.existsSync(marker), false);
});

test("seeded env-exfil fixture fails closed", () => {
  const dir = path.join(fixturesDir, "env-exfil");
  const marker = clearCanary(dir);
  const source = fs.readFileSync(path.join(dir, "index.js"), "utf8");
  assert.match(source, /ANTHROPIC_API_KEY/);
  assert.match(source, /webhook\.site/);
  assert.match(source, /\bfetch\b/);
  const cliResult = run([dir]);
  assert.equal(cliResult.status, 3, cliResult.stdout + cliResult.stderr);
  assert.match(cliResult.stdout, /\[env-exfil\]/);
  assert.match(cliResult.stdout, /\[exfil-host\]/);
  assert.match(cliResult.stdout, /DANGEROUS/);
  assert.equal(fs.existsSync(marker), false);
});

test("manifest expectations match --json reports and the files were not executed", () => {
  for (const fixture of manifest.fixtures) {
    const dir = path.join(fixturesDir, fixture.path);
    const marker = clearCanary(dir);
    const cliResult = run([dir, "--json"]);
    assert.equal(cliResult.status, fixture.expectExit, `${fixture.id}\n${cliResult.stdout}\n${cliResult.stderr}`);
    assert.doesNotMatch(cliResult.stdout, /\x1b/);
    const report = JSON.parse(cliResult.stdout);
    assert.equal(validateReport(report).ok, true, validateReport(report).reason);
    assert.equal(report.verdict, fixture.expectVerdict);
    assert.equal(report.exitCode, fixture.expectExit);
    assert.equal(report.blanketSafetyScore, null);
    assert.equal(report.scanner.staticOnly, true);
    assert.equal(report.scanner.executedTarget, false);
    assert.equal(report.scanner.version, "1.3.0");
    assert.equal(report.scanned, fixture.expectScanned);
    assert.equal(report.fileCount, fixture.expectFileCount);
    assert.deepEqual(rules(report.findings, "danger"), [...fixture.expectDangerRules].sort());
    assert.deepEqual(rules(report.findings, "warn"), [...fixture.expectWarnRules].sort());
    assert.equal(report.correction.state, fixture.expectVerdict === "dangerous" ? "required" : "none");
    assert.match(report.correction.rescan.command, /--report/);
    assert.match(report.correction.rescan.command, /fixtures\/[^ ]+/);
    assert.equal(fs.existsSync(marker), false);
  }
});

test("scoped report can be retrieved and the correction path names the flagged file", () => {
  const dir = path.join(fixturesDir, "prompt-injection");
  const out = path.join(os.tmpdir(), `skillguard-report-${process.pid}-prompt.json`);
  try {
    const scan = run([dir, "--report", out]);
    assert.equal(scan.status, 3, scan.stdout + scan.stderr);
    assert.equal(fs.existsSync(out), true);
    assert.match(scan.stdout, /Scoped report:/);
    assert.match(scan.stdout, /DANGEROUS/);
    const stored = JSON.parse(fs.readFileSync(out, "utf8"));
    assert.equal(stored.findings[0].file, "SKILL.md");
    assert.equal(stored.findings[0].rule, "prompt-injection");
    assert.equal(stored.correction.steps[0].action, stored.findings[0].correction);
    const retrieved = run(["--show-report", out]);
    assert.equal(retrieved.status, 3, retrieved.stdout + retrieved.stderr);
    assert.match(retrieved.stdout, /SkillGuard report retrieval/);
    assert.match(retrieved.stdout, /verdict: dangerous/);
    assert.match(retrieved.stdout, /exitCode: 3/);
    assert.match(retrieved.stdout, /blanketSafetyScore: null/);
    assert.match(retrieved.stdout, /executedTarget: false/);
    assert.match(retrieved.stdout, /Correction \(required\)/);
    assert.match(retrieved.stdout, /SKILL\.md \[prompt-injection\]/);
    assert.match(retrieved.stdout, /Rescan: /);
    assert.equal(retrieved.stderr, "");
  } finally {
    fs.rmSync(out, { force: true });
  }
});

test("env-exfil report retrieval exits 3 and lists both rules", () => {
  const dir = path.join(fixturesDir, "env-exfil");
  const out = path.join(os.tmpdir(), `skillguard-report-${process.pid}-env.json`);
  try {
    const scan = run([dir, "--report", out, "--json"]);
    assert.equal(scan.status, 3, scan.stdout + scan.stderr);
    const report = JSON.parse(scan.stdout);
    assert.deepEqual(rules(report.findings, "danger"), ["env-exfil", "exfil-host"]);
    assert.match(report.correction.summary, /not a safety score/);
    const retrieved = run(["--show-report", out, "--json"]);
    assert.equal(retrieved.status, 3);
    const again = JSON.parse(retrieved.stdout);
    assert.equal(again.verdict, "dangerous");
    assert.equal(again.blanketSafetyScore, null);
    assert.deepEqual(again.correction.steps.map((step) => step.rule).sort(), ["env-exfil", "exfil-host"]);
  } finally {
    fs.rmSync(out, { force: true });
  }
});

test("default human scan stays text and does not print the JSON schema id", () => {
  const cliResult = run([path.join(fixturesDir, "harmless")]);
  assert.equal(cliResult.status, 0);
  assert.match(cliResult.stdout, /SkillGuard report/);
  assert.doesNotMatch(cliResult.stdout, /skillguard\.report\.v1/);
});

test("seeded blanket safety score is rejected", () => {
  const dir = path.join(fixturesDir, "harmless");
  const out = path.join(os.tmpdir(), `skillguard-report-${process.pid}-score.json`);
  try {
    const scan = run([dir, "--report", out, "--json"]);
    assert.equal(scan.status, 0, scan.stdout + scan.stderr);
    const report = JSON.parse(fs.readFileSync(out, "utf8"));
    report.blanketSafetyScore = 100;
    fs.writeFileSync(out, JSON.stringify(report));
    const retrieved = run(["--show-report", out]);
    assert.equal(retrieved.status, 65, retrieved.stdout + retrieved.stderr);
    assert.match(retrieved.stderr, /blanketSafetyScore must be null/);
    assert.equal(retrieved.stdout, "");
  } finally {
    fs.rmSync(out, { force: true });
  }
});

test("seeded extra numeric score field is rejected", () => {
  const report = buildReport(analyze(path.join(fixturesDir, "harmless")));
  report.score = 100;
  const check = validateReport(report);
  assert.equal(check.ok, false);
  assert.match(check.reason, /unknown field score/);
  const out = path.join(os.tmpdir(), `skillguard-report-${process.pid}-extra-score.json`);
  try {
    fs.writeFileSync(out, JSON.stringify(report));
    const retrieved = run(["--show-report", out]);
    assert.equal(retrieved.status, 65);
    assert.match(retrieved.stderr, /unknown field score/);
  } finally {
    fs.rmSync(out, { force: true });
  }
});

test("seeded clean verdict with a danger finding is rejected", () => {
  const dir = path.join(fixturesDir, "env-exfil");
  const out = path.join(os.tmpdir(), `skillguard-report-${process.pid}-contradiction.json`);
  try {
    assert.equal(run([dir, "--report", out]).status, 3);
    const report = JSON.parse(fs.readFileSync(out, "utf8"));
    report.verdict = "clean";
    report.exitCode = 0;
    fs.writeFileSync(out, JSON.stringify(report));
    const retrieved = run(["--show-report", out]);
    assert.equal(retrieved.status, 65);
    assert.match(retrieved.stderr, /verdict does not match findings/);
    assert.equal(retrieved.stdout, "");
  } finally {
    fs.rmSync(out, { force: true });
  }
});

test("a report that claims the target was executed is rejected", () => {
  const report = buildReport(analyze(path.join(fixturesDir, "harmless")));
  report.scanner.executedTarget = true;
  const out = path.join(os.tmpdir(), `skillguard-report-${process.pid}-executed.json`);
  try {
    fs.writeFileSync(out, JSON.stringify(report));
    const retrieved = run(["--show-report", out]);
    assert.equal(retrieved.status, 65);
    assert.match(retrieved.stderr, /executedTarget must be false/);
  } finally {
    fs.rmSync(out, { force: true });
  }
});

test("missing report is rejected", () => {
  const missing = path.join(os.tmpdir(), `skillguard-missing-${process.pid}.json`);
  const retrieved = run(["--show-report", missing]);
  assert.equal(retrieved.status, 65);
  assert.match(retrieved.stderr, /Report not found/);
});

test("suspicious verdict maps to exit 2 and correction state review", () => {
  const report = buildReport({
    target: "/tmp/example-skill",
    scanned: 1,
    fileCount: 1,
    verdict: "suspicious",
    findings: [{ file: "README.md", rule: "shell-pipe", sev: "warn", label: "pipe to shell" }],
  }, { reportPath: "out.json" });
  assert.equal(validateReport(report).ok, true);
  assert.equal(report.exitCode, 2);
  assert.equal(report.correction.state, "review");
  assert.equal(report.blanketSafetyScore, null);
  assert.equal(report.scanner.executedTarget, false);
  const readBack = readReportBuffer(report);
  assert.equal(readBack.correction.steps[0].rule, "shell-pipe");
});

test("published schema matches the report object and forbids a safety score", () => {
  const schema = JSON.parse(fs.readFileSync(path.join(root, "report.schema.json"), "utf8"));
  const report = buildReport(analyze(path.join(fixturesDir, "env-exfil")));
  assert.equal(schema.$id, "skillguard.report.v1");
  assert.equal(schema.additionalProperties, false);
  assert.equal(schema.properties.blanketSafetyScore.type, "null");
  assert.deepEqual(Object.keys(report).sort(), [...schema.required].sort());
  assert.ok(report.findings.length >= 1);
  assert.deepEqual(Object.keys(report.findings[0]).sort(), schema.properties.findings.items.required.sort());
  assert.deepEqual(Object.keys(report.correction).sort(), schema.properties.correction.required.sort());
});

test("report helper source is not itself classified as danger", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "skillguard-src-"));
  try {
    fs.copyFileSync(path.join(root, "report.js"), path.join(dir, "report.js"));
    fs.copyFileSync(path.join(root, "report.schema.json"), path.join(dir, "report.schema.json"));
    const cliResult = run([dir, "--json"]);
    assert.equal(cliResult.status, 0, cliResult.stdout + cliResult.stderr);
    const report = JSON.parse(cliResult.stdout);
    assert.equal(report.verdict, "clean");
    assert.equal(report.findings.length, 0);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("mcp server does not import the report helper", () => {
  const mcp = fs.readFileSync(path.join(root, "mcp.js"), "utf8");
  const cliSrc = fs.readFileSync(cli, "utf8");
  assert.match(mcp, /scan_skill/);
  assert.doesNotMatch(mcp, /report\.js/);
  assert.doesNotMatch(cliSrc, /^import\s+.*report\.js/m);
  assert.match(cliSrc, /import\("\.\/report\.js"\)/);
});

test("usage error exits 64 and does not scan", () => {
  const cliResult = run([]);
  assert.equal(cliResult.status, 64);
  assert.match(cliResult.stderr, /--show-report/);
  const unknown = run([path.join(fixturesDir, "harmless"), "--scores"]);
  assert.equal(unknown.status, 64);
  assert.match(unknown.stderr, /Unknown option/);
});

function readReportBuffer(report) {
  const out = path.join(os.tmpdir(), `skillguard-report-${process.pid}-unit.json`);
  fs.writeFileSync(out, JSON.stringify(report));
  try {
    return readReport(out);
  } finally {
    fs.rmSync(out, { force: true });
  }
}
