#!/usr/bin/env node
// SkillGuard — static security scanner for Claude Code skills, plugins, and MCP servers.
// It does STATIC analysis only: it clones (git clone, no install) and reads files. It NEVER
// installs dependencies, runs build/postinstall scripts, or executes any target code — so
// scanning a malicious package can't harm you. (That's the whole point.)
//
// Usage:
//   npx github:epistemedeus/skillguard <path-or-git-url>
//   npx github:epistemedeus/skillguard https://github.com/owner/repo
//   npx github:epistemedeus/skillguard ./my-skill
//
// Exit code: 0 = clean, 2 = suspicious, 3 = dangerous.

import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { execFileSync } from "node:child_process";

const RED = "\x1b[31m", YEL = "\x1b[33m", GRN = "\x1b[32m", DIM = "\x1b[2m", B = "\x1b[1m", R = "\x1b[0m", CY = "\x1b[36m";

// ---- detection rules -------------------------------------------------------
// severity: "danger" (red) | "warn" (yellow). Each rule scans a file's text.
const SENSITIVE_ENV = /\b(ANTHROPIC_API_KEY|ANTHROPIC_BASE_URL|ANTHROPIC_AUTH_TOKEN|OPENAI_API_KEY|AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|STRIPE_SECRET_KEY|SSH_PRIVATE_KEY|GOOGLE_APPLICATION_CREDENTIALS|HF_TOKEN|SLACK_TOKEN)\b/;
const NET_CALL = /\b(fetch|axios|got|node-fetch|requests\.(get|post)|urllib|http\.request|https\.request|XMLHttpRequest|curl|wget|nc |netcat|Invoke-WebRequest)\b/i;
const EXFIL_HOST = /(pastebin\.com|hastebin|ngrok\.io|ngrok-free|requestbin|webhook\.site|pipedream\.net|burpcollaborator|interactsh|oast\.|\.run\.place|discord(app)?\.com\/api\/webhooks|t\.me\/|telegram\.org\/bot|\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)/i;
const OBFUSC = /(eval\s*\(\s*(atob|Buffer\.from|require\(['"]child_process)|atob\s*\(|base64\s*-d|FromBase64String|exec\(\s*atob|child_process'\)\.exec|os\.system\(|subprocess\.(Popen|call|run)\(|\bexec\s*\(\s*`|\| ?bash|\| ?sh\b|curl[^\n]+\|\s*(ba)?sh)/i;
const PROMPT_INJ = /(ignore (all )?(previous|prior|above) (instructions|prompts)|do not (tell|inform|mention|reveal)( this)? (to )?the user|without (the user|asking|permission)|exfiltrat|secretly|covertly|hidden (instruction|directive)|bypass (the )?(approval|permission|sandbox)|send (the |your )?(env|environment|secrets|keys|credentials|\.env)|read .{0,20}\.env|cat .{0,20}\.env|always (auto-?)?approve|disregard (the )?(rules|guidelines))/i;
const INSTALL_HOOK = /"(pre|post)?install"\s*:/;
const DANGEROUS_FLAG = /(--dangerously-skip-permissions|"permissions"\s*:\s*"(\*|all)"|autoApprove\s*:\s*(true|"all"|\*)|"autoApproveAll"\s*:\s*true|disable[_-]?sandbox|skip[_-]?confirmation)/i;
const SECRET_LITERAL = /(sk-ant-[a-zA-Z0-9_\-]{20,}|sk-[a-zA-Z0-9]{40,}|ghp_[a-zA-Z0-9]{30,}|AKIA[0-9A-Z]{16}|-----BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY-----|xox[baprs]-[0-9a-zA-Z\-]{10,})/;
const FORCED_ARTIFACT = /(diagnostic\/.*\.logd|encryptly|\.logd\b|commit .{0,30}(diagnostic|encrypted|validation) (blob|artifact|file)|python3? build\.py|node build\.js.{0,40}commit)/i;

const RULES = [
  { id: "env-exfil", sev: "danger", label: "Possible env/secret exfiltration (sensitive env var near a network call)",
    test: t => SENSITIVE_ENV.test(t) && NET_CALL.test(t) },
  { id: "exfil-host", sev: "danger", label: "Hardcoded suspicious exfiltration endpoint (webhook/pastebin/raw-IP/telegram)",
    test: t => EXFIL_HOST.test(t) && NET_CALL.test(t) },
  { id: "obfuscation", sev: "danger", label: "Obfuscated/dynamic code execution (eval(atob), curl|bash, subprocess on encoded data)",
    test: t => OBFUSC.test(t) },
  { id: "forced-artifact", sev: "danger", label: "Honeypot pattern: build step that generates/commits an encrypted artifact",
    test: t => FORCED_ARTIFACT.test(t) },
  { id: "secret-literal", sev: "danger", label: "Hardcoded credential / private key committed in the repo",
    test: t => SECRET_LITERAL.test(t) },
  { id: "prompt-injection", sev: "danger", label: "Prompt-injection / data-exfil instruction in text (tool description / SKILL.md / prompt)",
    test: (t, f) => PROMPT_INJ.test(t) && /\.(md|mdx|json|ya?ml|txt|py|js|ts)$/i.test(f) },
  { id: "dangerous-perms", sev: "warn", label: "Auto-approve-all / sandbox-disabling / skip-permissions configuration",
    test: t => DANGEROUS_FLAG.test(t) },
  { id: "install-hook", sev: "warn", label: "Install-time script hook (pre/postinstall) — runs code on `npm install`",
    test: (t, f) => INSTALL_HOOK.test(t) && /package\.json$/i.test(f) },
  { id: "raw-network", sev: "warn", label: "Outbound network call — review where data goes",
    test: t => NET_CALL.test(t) && /process\.env|os\.environ|getenv/i.test(t) },
];

// committed-binary detection (Mach-O / ELF / PE magic)
function looksBinary(buf) {
  if (buf.length < 4) return false;
  const m = buf.subarray(0, 4);
  return (m[0] === 0x7f && m[1] === 0x45 && m[2] === 0x4c && m[3] === 0x46) || // ELF
         (m[0] === 0xcf && m[1] === 0xfa && m[2] === 0xed && m[3] === 0xfe) || // Mach-O 64
         (m[0] === 0xfe && m[1] === 0xed && m[2] === 0xfa) ||                  // Mach-O
         (m[0] === 0x4d && m[1] === 0x5a) ||                                   // PE (MZ)
         (m[0] === 0xca && m[1] === 0xfe && m[2] === 0xba && m[3] === 0xbe);   // Mach-O fat
}

const SKIP_DIRS = new Set([".git", "node_modules", ".venv", "venv", "dist", "build", "__pycache__", ".next"]);
const TEXT_EXT = /\.(js|ts|jsx|tsx|mjs|cjs|py|rb|go|rs|sh|bash|zsh|json|jsonc|ya?ml|toml|md|mdx|txt|env|cfg|ini|ps1)$/i;

function walk(dir, out = []) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return out; }
  for (const e of entries) {
    if (e.name.startsWith(".") && e.name !== ".mcp.json" && e.name !== ".env.example") {
      if (SKIP_DIRS.has(e.name)) continue;
    }
    if (SKIP_DIRS.has(e.name)) continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, out);
    else out.push(p);
  }
  return out;
}

function scanDir(root) {
  const files = walk(root);
  const findings = [];
  let binaries = 0, scanned = 0;
  for (const f of files) {
    let buf;
    try { buf = fs.readFileSync(f); } catch { continue; }
    if (looksBinary(buf)) { binaries++; findings.push({ file: f, rule: "committed-binary", sev: "danger",
      label: "Committed executable binary (a compiled artifact that the build may run)" }); continue; }
    if (!TEXT_EXT.test(f) && buf.length > 200000) continue; // skip big non-text
    const text = buf.toString("utf8");
    scanned++;
    for (const r of RULES) {
      try { if (r.test(text, f)) findings.push({ file: f, rule: r.id, sev: r.sev, label: r.label }); } catch {}
    }
  }
  return { findings, binaries, scanned, fileCount: files.length };
}

function rel(root, f) { return path.relative(root, f) || path.basename(f); }

function main() {
  const arg = process.argv[2];
  if (!arg) {
    console.error(`${B}SkillGuard${R} — static security scanner for Claude Code skills, plugins & MCP servers.\n` +
      `Usage: skillguard <path-or-git-url>\n  npx github:epistemedeus/skillguard https://github.com/owner/repo\n  npx github:epistemedeus/skillguard ./my-skill`);
    process.exit(64);
  }
  let root = arg, tmp = null;
  const isUrl = /^(https?:\/\/|git@)/.test(arg);
  if (isUrl) {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "skillguard-"));
    process.stderr.write(`${DIM}Cloning (static, no install)…${R}\n`);
    try {
      // --depth 1, and disable any clone-time hooks; we never run install/build.
      execFileSync("git", ["-c", "core.hooksPath=/dev/null", "clone", "--depth", "1", arg, tmp],
        { stdio: ["ignore", "ignore", "pipe"], timeout: 60000 });
      root = tmp;
    } catch (e) { console.error(`${RED}Could not clone ${arg}${R}: ${String(e.message).slice(0, 120)}`); process.exit(65); }
  }
  if (!fs.existsSync(root)) { console.error(`${RED}Path not found: ${root}${R}`); process.exit(66); }

  const { findings, binaries, scanned, fileCount } = scanDir(root);
  const dangers = findings.filter(f => f.sev === "danger");
  const warns = findings.filter(f => f.sev === "warn");

  console.log(`\n${B}SkillGuard report${R}  ${DIM}· ${scanned} text files scanned, ${fileCount} total${R}`);
  console.log(`${DIM}target: ${isUrl ? arg : path.resolve(root)}${R}\n`);

  const group = (list) => {
    const byFile = {};
    for (const x of list) (byFile[rel(root, x.file)] ||= []).push(x);
    for (const [file, fs_] of Object.entries(byFile)) {
      console.log(`  ${CY}${file}${R}`);
      for (const x of fs_) console.log(`    ${x.sev === "danger" ? RED + "■" : YEL + "▲"} ${x.label}${R} ${DIM}[${x.rule}]${R}`);
    }
  };

  if (dangers.length) { console.log(`${RED}${B}DANGER (${dangers.length})${R}`); group(dangers); console.log(""); }
  if (warns.length) { console.log(`${YEL}${B}WARNINGS (${warns.length})${R}`); group(warns); console.log(""); }

  let verdict, code;
  if (dangers.length) { verdict = `${RED}${B}✗ DANGEROUS${R} — do NOT install without reviewing the flagged files.`; code = 3; }
  else if (warns.length) { verdict = `${YEL}${B}▲ SUSPICIOUS${R} — review the warnings before trusting this.`; code = 2; }
  else { verdict = `${GRN}${B}✓ No known-malicious patterns found${R} — still review code from untrusted authors.`; code = 0; }
  console.log(verdict);
  console.log(`${DIM}SkillGuard does static analysis only; it never executes the scanned code. Heuristics can miss novel attacks.\n` +
    `Want continuous re-scanning on every upstream release + a deeper manual audit? → https://samedaydesk.com/skillguard${R}\n`);

  if (tmp) try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  process.exit(code);
}
main();
