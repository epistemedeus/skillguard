// Scoped report delivery for the SkillGuard CLI.
// Turns an existing analyze() result into skillguard.report.v1 JSON.
// Does not score, does not scan, and does not execute the scanned tree.
// A stored rescan command is accepted only when it is the canonical argv line.
// That line is never passed to a shell.

import fs from "node:fs";
import path from "node:path";
import { escapeTerminal, scannerVersion } from "./version.js";

export const SCHEMA_ID = "skillguard.report.v1";

const VERDICT_EXIT = { clean: 0, suspicious: 2, dangerous: 3 };
const VERDICT_STATE = { clean: "none", suspicious: "review", dangerous: "required" };
const GENERATED_AT = "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?Z$";
const GENERATED_AT_RE = new RegExp(GENERATED_AT);
const CONTROL_RE = /[\u0000-\u001f\u007f-\u009f]/;

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
  "symlink-escape": "Remove the symlink that resolves outside the scanned tree. The scanner does not read that target. Then re-scan.",
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

export function quoteArg(value) {
  const text = String(value);
  if (/^[A-Za-z0-9_./:=@+-]+$/.test(text)) return text;
  return `'${text.replace(/'/g, `'\\''`)}'`;
}

export function canonicalRescan(target, reportPath) {
  return `node index.js ${quoteArg(target)} --report ${quoteArg(reportPath)}`;
}

function unquoteArg(token) {
  if (/^[A-Za-z0-9_./:=@+-]+$/.test(token)) return token;
  if (token.length >= 2 && token.startsWith("'") && token.endsWith("'")) {
    const body = token.slice(1, -1);
    if (body.includes("'") || CONTROL_RE.test(body) || /[;&|$`]/.test(body)) return null;
    return body;
  }
  return null;
}

export function boundRescan(command, target) {
  if (typeof command !== "string" || typeof target !== "string") return null;
  const prefix = `node index.js ${quoteArg(target)} --report `;
  if (!command.startsWith(prefix)) return null;
  const reportPath = unquoteArg(command.slice(prefix.length));
  if (reportPath == null || reportPath.length === 0) return null;
  if (canonicalRescan(target, reportPath) !== command) return null;
  return reportPath;
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

function plain(value, label) {
  if (typeof value !== "string" || value.length === 0) return `${label} must be a non-empty string`;
  if (CONTROL_RE.test(value)) return `${label} contains a terminal control`;
  return null;
}

export function schemaParityProblems(schema) {
  const problems = [];
  if (!schema || schema.$id !== SCHEMA_ID) problems.push("schema id");
  if (schema?.additionalProperties !== false) problems.push("additionalProperties");
  if (schema?.properties?.blanketSafetyScore?.type !== "null") problems.push("blanketSafetyScore");
  if (schema?.properties?.generatedAt?.pattern !== GENERATED_AT) problems.push("generatedAt");
  if (schema?.properties?.scanner?.properties?.staticOnly?.const !== true) problems.push("staticOnly");
  if (schema?.properties?.scanner?.properties?.executedTarget?.const !== false) problems.push("executedTarget");
  if (JSON.stringify(schema?.properties?.verdict?.enum) !== JSON.stringify(["clean", "suspicious", "dangerous"])) {
    problems.push("verdict enum");
  }
  if (JSON.stringify(schema?.properties?.exitCode?.enum) !== JSON.stringify([0, 2, 3])) problems.push("exitCode enum");
  if (JSON.stringify([...(schema?.required || [])].sort()) !== JSON.stringify([...REPORT_KEYS].sort())) {
    problems.push("required keys");
  }
  if (!Array.isArray(schema?.allOf) || schema.allOf.length !== 3) problems.push("allOf");
  else {
    for (const branch of schema.allOf) {
      const verdict = branch?.if?.properties?.verdict?.const;
      const exitCode = branch?.then?.properties?.exitCode?.const;
      const state = branch?.then?.properties?.correction?.properties?.state?.const;
      if (VERDICT_EXIT[verdict] !== exitCode) problems.push(`exit for ${verdict}`);
      if (VERDICT_STATE[verdict] !== state) problems.push(`state for ${verdict}`);
      if (verdict === "clean" && branch?.then?.properties?.findings?.maxItems !== 0) problems.push("clean findings");
    }
  }
  return problems;
}

let schemaReady = false;
function ensureSchemaParity() {
  if (schemaReady) return;
  const schema = JSON.parse(fs.readFileSync(new URL("./report.schema.json", import.meta.url), "utf8"));
  const problems = schemaParityProblems(schema);
  if (problems.length) throw new Error(`Schema/runtime mismatch: ${problems.join(", ")}`);
  schemaReady = true;
}

export function validateReport(report) {
  ensureSchemaParity();
  if (!isObject(report)) return { ok: false, reason: "report must be an object" };
  const root = sameKeys(report, REPORT_KEYS);
  if (root) return { ok: false, reason: root };
  if (report.schema !== SCHEMA_ID) return { ok: false, reason: `schema must be ${SCHEMA_ID}` };
  if (typeof report.generatedAt !== "string" || !GENERATED_AT_RE.test(report.generatedAt)) {
    return { ok: false, reason: "generatedAt must be UTC ISO time" };
  }
  if (!isObject(report.scanner)) return { ok: false, reason: "scanner must be an object" };
  const scannerKeys = sameKeys(report.scanner, SCANNER_KEYS);
  if (scannerKeys) return { ok: false, reason: `scanner ${scannerKeys}` };
  if (report.scanner.name !== "skillguard") return { ok: false, reason: "scanner.name must be skillguard" };
  const versionText = plain(report.scanner.version, "scanner.version");
  if (versionText) return { ok: false, reason: versionText };
  if (report.scanner.version !== scannerVersion()) {
    return { ok: false, reason: "scanner.version does not match this skillguard build" };
  }
  if (report.scanner.staticOnly !== true) return { ok: false, reason: "scanner.staticOnly must be true" };
  if (report.scanner.executedTarget !== false) return { ok: false, reason: "scanner.executedTarget must be false" };
  const targetText = plain(report.target, "target");
  if (targetText) return { ok: false, reason: targetText };
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
    for (const key of ["file", "rule", "label", "correction"]) {
      const problem = plain(finding[key], `finding.${key}`);
      if (problem) return { ok: false, reason: problem };
    }
    if (finding.severity !== "danger" && finding.severity !== "warn") return { ok: false, reason: "finding.severity must be danger or warn" };
  }

  const hasDanger = report.findings.some((finding) => finding.severity === "danger");
  const hasWarn = report.findings.some((finding) => finding.severity === "warn");
  const expectedVerdict = hasDanger ? "dangerous" : hasWarn ? "suspicious" : "clean";
  if (report.verdict !== expectedVerdict) return { ok: false, reason: "verdict does not match findings" };

  if (!isObject(report.correction)) return { ok: false, reason: "correction must be an object" };
  const correctionKeys = sameKeys(report.correction, CORRECTION_KEYS);
  if (correctionKeys) return { ok: false, reason: `correction ${correctionKeys}` };
  if (report.correction.state !== VERDICT_STATE[report.verdict]) return { ok: false, reason: "correction.state does not match verdict" };
  const summary = plain(report.correction.summary, "correction.summary");
  if (summary) return { ok: false, reason: summary };
  if (!Array.isArray(report.correction.steps)) return { ok: false, reason: "correction.steps must be an array" };
  if (report.correction.steps.length !== report.findings.length) return { ok: false, reason: "correction.steps must match findings" };

  for (let i = 0; i < report.correction.steps.length; i++) {
    const step = report.correction.steps[i];
    const finding = report.findings[i];
    if (!isObject(step)) return { ok: false, reason: "correction step must be an object" };
    const stepKeys = sameKeys(step, STEP_KEYS);
    if (stepKeys) return { ok: false, reason: `correction step ${stepKeys}` };
    if (step.file !== finding.file || step.rule !== finding.rule) return { ok: false, reason: "correction step does not match finding" };
    const action = plain(step.action, "correction step action");
    if (action) return { ok: false, reason: action };
    if (step.action !== finding.correction) return { ok: false, reason: "correction step action must match finding correction" };
  }

  if (!isObject(report.correction.rescan)) return { ok: false, reason: "correction.rescan must be an object" };
  const rescanKeys = sameKeys(report.correction.rescan, ["command"]);
  if (rescanKeys) return { ok: false, reason: `rescan ${rescanKeys}` };
  const command = report.correction.rescan.command;
  const commandText = plain(command, "correction.rescan.command");
  if (commandText) return { ok: false, reason: commandText };
  if (!boundRescan(command, report.target)) {
    return { ok: false, reason: "correction.rescan.command is not the canonical rescan" };
  }
  return { ok: true };
}

export function buildReport(result, { reportPath } = {}) {
  if (!result || !Object.hasOwn(VERDICT_EXIT, result.verdict)) {
    throw new Error(`Rejected report: unknown verdict ${result && result.verdict}`);
  }
  const findings = (result.findings || []).map((finding) => ({
    file: escapeTerminal(finding.file),
    rule: finding.rule,
    severity: finding.sev,
    label: finding.label,
    correction: correctionFor(finding.rule),
  }));
  const state = VERDICT_STATE[result.verdict];
  const outPath = reportPath || "skillguard-report.json";
  const target = escapeTerminal(result.target);
  const report = {
    schema: SCHEMA_ID,
    generatedAt: new Date().toISOString(),
    scanner: {
      name: "skillguard",
      version: scannerVersion(),
      staticOnly: true,
      executedTarget: false,
    },
    target,
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
      rescan: { command: canonicalRescan(target, outPath) },
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
  const fd = fs.openSync(tmp, "w", 0o600);
  try {
    fs.writeFileSync(fd, reportToJson(report));
    fs.fchmodSync(fd, 0o600);
    fs.closeSync(fd);
    fs.renameSync(tmp, abs);
    fs.chmodSync(abs, 0o600);
  } catch (error) {
    try { fs.closeSync(fd); } catch { /* the fd may already be closed */ }
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
  const show = (value) => escapeTerminal(value);
  const lines = [
    "SkillGuard report retrieval",
    `schema: ${show(report.schema)}`,
    `target: ${show(report.target)}`,
    `verdict: ${show(report.verdict)}`,
    `exitCode: ${show(report.exitCode)}`,
    "blanketSafetyScore: null",
    "staticOnly: true",
    "executedTarget: false",
    "",
    `Correction (${show(report.correction.state)})`,
  ];
  if (!report.correction.steps.length) lines.push("  No file changes required.");
  for (const step of report.correction.steps) {
    lines.push(`  ${show(step.file)} [${show(step.rule)}]`);
    lines.push(`    ${show(step.action)}`);
  }
  lines.push(`Rescan: ${show(report.correction.rescan.command)}`);
  lines.push(show(report.correction.summary));
  lines.push("");
  return lines.join("\n");
}
