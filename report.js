// Scoped report delivery for the SkillGuard CLI.
// Turns an existing analyze() result into skillguard.report.v1 JSON.
// Does not score, does not scan, and does not execute the scanned tree.

import fs from "node:fs";
import path from "node:path";

export const SCHEMA_ID = "skillguard.report.v1";

const VERDICT_EXIT = { clean: 0, suspicious: 2, dangerous: 3 };
const VERDICT_STATE = { clean: "none", suspicious: "review", dangerous: "required" };

const CORRECTIONS = {
  "env-dump": "Remove full-environment serialization from the network path, or remove the network call. Then re-scan this target.",
  "env-exfil": "Remove the sensitive environment name from any file that also names a known exfil host. Then re-scan this target.",
  "exfil-host": "Remove the network call that targets a known exfil host. Then re-scan this target.",
  "obfuscation": "Remove decoded or encoded command execution from this file. Then re-scan this target.",
  "shell-pipe": "Replace the pipe-to-shell with a reviewed installer, or delete it. Then re-scan this target.",
  "forced-artifact": "Remove the honeypot build step from this file. Then re-scan this target.",
  "secret-literal": "Rotate the credential and delete the literal from this file. Then re-scan this target.",
  "prompt-injection": "Remove text that overrides earlier operator instructions or tells the agent to hide its actions. Then re-scan this target.",
  "dangerous-perms": "Remove auto-approve-all, sandbox bypass, or skip-permissions settings. Then re-scan this target.",
  "install-hook": "Remove the install-time script hook, or move it to a manual documented step. Then re-scan this target.",
  "committed-binary": "Remove the committed executable from the tree. Then re-scan this target.",
};

const REPORT_KEYS = ["schema", "generatedAt", "scanner", "target", "scanned", "fileCount", "verdict", "exitCode", "blanketSafetyScore", "findings", "correction"];
const SCANNER_KEYS = ["name", "version", "staticOnly", "executedTarget"];
const FINDING_KEYS = ["file", "rule", "severity", "label", "correction"];
const CORRECTION_KEYS = ["state", "summary", "steps", "rescan"];
const STEP_KEYS = ["file", "rule", "action"];

const SUMMARIES = {
  none: "No flagged files. Re-scan after the tree changes. This report is not a safety score.",
  review: "Review each warning and edit the file if the pattern is unintended, then re-scan this target. This report is not a safety score.",
  required: "Edit each flagged file, then re-scan this target. Do not install while the verdict is dangerous. This report is not a safety score.",
};

function scannerVersion() {
  try {
    const pkg = JSON.parse(fs.readFileSync(new URL("./package.json", import.meta.url), "utf8"));
    if (typeof pkg.version === "string" && pkg.version) return pkg.version;
  } catch { /* fall through */ }
  return "0.0.0";
}

export function quoteArg(value) {
  const text = String(value);
  if (/^[A-Za-z0-9_./:=@+-]+$/.test(text)) return text;
  return `'${text.replace(/'/g, `'\\''`)}'`;
}

export function correctionFor(rule) {
  return CORRECTIONS[rule] || "Review this file and remove the flagged pattern, then re-scan this target.";
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function sameKeys(value, allowed) {
  const keys = Object.keys(value);
  for (const key of keys) if (!allowed.includes(key)) return `unknown field ${key}`;
  for (const key of allowed) if (!Object.hasOwn(value, key)) return `missing ${key}`;
  return null;
}

export function validateReport(report) {
  if (!isObject(report)) return { ok: false, reason: "report must be an object" };
  const root = sameKeys(report, REPORT_KEYS);
  if (root) return { ok: false, reason: root };
  if (report.schema !== SCHEMA_ID) return { ok: false, reason: `schema must be ${SCHEMA_ID}` };
  if (typeof report.generatedAt !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/.test(report.generatedAt)) {
    return { ok: false, reason: "generatedAt must be UTC ISO time" };
  }
  if (!isObject(report.scanner)) return { ok: false, reason: "scanner must be an object" };
  const scannerKeys = sameKeys(report.scanner, SCANNER_KEYS);
  if (scannerKeys) return { ok: false, reason: `scanner ${scannerKeys}` };
  if (report.scanner.name !== "skillguard") return { ok: false, reason: "scanner.name must be skillguard" };
  if (typeof report.scanner.version !== "string" || !report.scanner.version) {
    return { ok: false, reason: "scanner.version must be a non-empty string" };
  }
  if (report.scanner.staticOnly !== true) return { ok: false, reason: "scanner.staticOnly must be true" };
  if (report.scanner.executedTarget !== false) return { ok: false, reason: "scanner.executedTarget must be false" };
  if (typeof report.target !== "string" || !report.target) return { ok: false, reason: "target must be a non-empty string" };
  if (!Number.isInteger(report.scanned) || report.scanned < 0) return { ok: false, reason: "scanned must be a non-negative integer" };
  if (!Number.isInteger(report.fileCount) || report.fileCount < 0) return { ok: false, reason: "fileCount must be a non-negative integer" };
  if (!Object.hasOwn(VERDICT_EXIT, report.verdict)) return { ok: false, reason: "verdict must be clean, suspicious, or dangerous" };
  if (report.exitCode !== VERDICT_EXIT[report.verdict]) return { ok: false, reason: "exitCode does not match verdict" };
  if (report.blanketSafetyScore !== null) return { ok: false, reason: "blanketSafetyScore must be null" };
  if (!Array.isArray(report.findings)) return { ok: false, reason: "findings must be an array" };

  for (const finding of report.findings) {
    if (!isObject(finding)) return { ok: false, reason: "finding must be an object" };
    const findingKeys = sameKeys(finding, FINDING_KEYS);
    if (findingKeys) return { ok: false, reason: `finding ${findingKeys}` };
    if (typeof finding.file !== "string" || !finding.file) return { ok: false, reason: "finding.file must be a non-empty string" };
    if (typeof finding.rule !== "string" || !finding.rule) return { ok: false, reason: "finding.rule must be a non-empty string" };
    if (finding.severity !== "danger" && finding.severity !== "warn") return { ok: false, reason: "finding.severity must be danger or warn" };
    if (typeof finding.label !== "string" || !finding.label) return { ok: false, reason: "finding.label must be a non-empty string" };
    if (typeof finding.correction !== "string" || !finding.correction) return { ok: false, reason: "finding.correction must be a non-empty string" };
  }

  const hasDanger = report.findings.some((finding) => finding.severity === "danger");
  const hasWarn = report.findings.some((finding) => finding.severity === "warn");
  const expectedVerdict = hasDanger ? "dangerous" : hasWarn ? "suspicious" : "clean";
  if (report.verdict !== expectedVerdict) return { ok: false, reason: "verdict does not match findings" };

  if (!isObject(report.correction)) return { ok: false, reason: "correction must be an object" };
  const correctionKeys = sameKeys(report.correction, CORRECTION_KEYS);
  if (correctionKeys) return { ok: false, reason: `correction ${correctionKeys}` };
  if (report.correction.state !== VERDICT_STATE[report.verdict]) return { ok: false, reason: "correction.state does not match verdict" };
  if (typeof report.correction.summary !== "string" || !report.correction.summary) {
    return { ok: false, reason: "correction.summary must be a non-empty string" };
  }
  if (!Array.isArray(report.correction.steps)) return { ok: false, reason: "correction.steps must be an array" };
  if (report.correction.steps.length !== report.findings.length) return { ok: false, reason: "correction.steps must match findings" };

  for (let i = 0; i < report.correction.steps.length; i++) {
    const step = report.correction.steps[i];
    const finding = report.findings[i];
    if (!isObject(step)) return { ok: false, reason: "correction step must be an object" };
    const stepKeys = sameKeys(step, STEP_KEYS);
    if (stepKeys) return { ok: false, reason: `correction step ${stepKeys}` };
    if (step.file !== finding.file || step.rule !== finding.rule) return { ok: false, reason: "correction step does not match finding" };
    if (typeof step.action !== "string" || !step.action) return { ok: false, reason: "correction step action must be a non-empty string" };
    if (step.action !== finding.correction) return { ok: false, reason: "correction step action must match finding correction" };
  }

  if (!isObject(report.correction.rescan)) return { ok: false, reason: "correction.rescan must be an object" };
  const rescanKeys = sameKeys(report.correction.rescan, ["command"]);
  if (rescanKeys) return { ok: false, reason: `rescan ${rescanKeys}` };
  const command = report.correction.rescan.command;
  if (typeof command !== "string" || !command.includes("--report") || !command.includes(quoteArg(report.target))) {
    return { ok: false, reason: "correction.rescan.command must name the target and --report" };
  }
  return { ok: true };
}

export function buildReport(result, { reportPath } = {}) {
  if (!result || !Object.hasOwn(VERDICT_EXIT, result.verdict)) {
    throw new Error(`Rejected report: unknown verdict ${result && result.verdict}`);
  }
  const findings = (result.findings || []).map((finding) => ({
    file: finding.file,
    rule: finding.rule,
    severity: finding.sev,
    label: finding.label,
    correction: correctionFor(finding.rule),
  }));
  const state = VERDICT_STATE[result.verdict];
  const outPath = reportPath || "skillguard-report.json";
  const report = {
    schema: SCHEMA_ID,
    generatedAt: new Date().toISOString(),
    scanner: {
      name: "skillguard",
      version: scannerVersion(),
      staticOnly: true,
      executedTarget: false,
    },
    target: result.target,
    scanned: result.scanned,
    fileCount: result.fileCount,
    verdict: result.verdict,
    exitCode: VERDICT_EXIT[result.verdict],
    blanketSafetyScore: null,
    findings,
    correction: {
      state,
      summary: SUMMARIES[state],
      steps: findings.map((finding) => ({ file: finding.file, rule: finding.rule, action: finding.correction })),
      rescan: { command: `node index.js ${quoteArg(result.target)} --report ${quoteArg(outPath)}` },
    },
  };
  const check = validateReport(report);
  if (!check.ok) throw new Error(`Rejected report: ${check.reason}`);
  return report;
}

export function reportToJson(report) {
  return `${JSON.stringify(report, null, 2)}\n`;
}

export function writeReport(filePath, report) {
  const check = validateReport(report);
  if (!check.ok) throw new Error(`Rejected report: ${check.reason}`);
  const abs = path.resolve(filePath);
  const dir = path.dirname(abs);
  fs.mkdirSync(dir, { recursive: true });
  const tmp = path.join(dir, `.skillguard-report-${process.pid}-${Date.now()}.tmp`);
  try {
    fs.writeFileSync(tmp, reportToJson(report), "utf8");
    fs.renameSync(tmp, abs);
  } catch (error) {
    try { fs.rmSync(tmp, { force: true }); } catch { /* ignore cleanup failure */ }
    throw error;
  }
  return abs;
}

export function readReport(filePath) {
  let text;
  try {
    text = fs.readFileSync(filePath, "utf8");
  } catch {
    throw new Error(`Report not found: ${filePath}`);
  }
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    throw new Error("Report is not JSON");
  }
  const check = validateReport(data);
  if (!check.ok) throw new Error(`Rejected report: ${check.reason}`);
  return data;
}

export function formatRetrieval(report) {
  const lines = [
    "SkillGuard report retrieval",
    `schema: ${report.schema}`,
    `target: ${report.target}`,
    `verdict: ${report.verdict}`,
    `exitCode: ${report.exitCode}`,
    "blanketSafetyScore: null",
    "staticOnly: true",
    "executedTarget: false",
    "",
    `Correction (${report.correction.state})`,
  ];
  if (!report.correction.steps.length) lines.push("  No file changes required.");
  for (const step of report.correction.steps) {
    lines.push(`  ${step.file} [${step.rule}]`);
    lines.push(`    ${step.action}`);
  }
  lines.push(`Rescan: ${report.correction.rescan.command}`);
  lines.push(report.correction.summary);
  lines.push("");
  return lines.join("\n");
}
