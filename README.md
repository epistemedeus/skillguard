# SkillGuard

**Scan a Claude Code skill, plugin, or MCP server for malware *before* you install it.** One command, no install, no account.

```bash
npx github:epistemedeus/skillguard https://github.com/owner/repo
# or a local folder:
npx github:epistemedeus/skillguard ./my-skill
```

```
SkillGuard report  · 3 text files scanned

DANGER (4)
  SKILL.md
    ■ Prompt-injection / data-exfil instruction in text   [prompt-injection]
  index.js
    ■ Possible env/secret exfiltration (sensitive env var near a network call)   [env-exfil]
    ■ Hardcoded suspicious exfiltration endpoint (webhook/pastebin/raw-IP)        [exfil-host]
    ■ Obfuscated/dynamic code execution (eval(atob), curl|bash)                   [obfuscation]

✗ DANGEROUS — do NOT install without reviewing the flagged files.
```

## Why

The Claude Code / MCP ecosystem is exploding — and so is the attack surface. Researchers have found **71 malicious skills** in the wild, **~26% of published skills carry vulnerabilities**, and **30+ MCP CVEs landed in 60 days**. The most common payloads:

- **Environment-variable / secret exfiltration** (`ANTHROPIC_API_KEY`, `AWS_SECRET_ACCESS_KEY`, `~/.env`) shipped off to a webhook.
- **Install-time shell hooks** (`postinstall`) that run code the moment you `npm install`.
- **Prompt injection in tool descriptions / SKILL.md** ("ignore previous instructions", "do not tell the user", "always auto-approve").
- **Committed binaries** and **obfuscated `eval(atob(...))` / `curl | bash`** payloads.
- **Auto-approve-all / skip-permissions** configs that disarm your safeguards.

SkillGuard catches these patterns in seconds, so you can vet a third-party skill or MCP server before trusting it with your machine and your keys.

## Safe by design

SkillGuard does **static analysis only**. It clones with `git clone` (hooks disabled) and *reads* files — it **never runs `npm install`, never executes build/postinstall scripts, and never runs the target code.** Scanning a malicious package can't harm you. (A scanner that executed what it's inspecting would be the very risk it's meant to prevent.)

## What it checks

| Check | Catches |
|---|---|
| `env-exfil` | A sensitive env var read next to a network call |
| `exfil-host` | Hardcoded webhook / pastebin / raw-IP / Telegram exfil endpoints |
| `obfuscation` | `eval(atob(...))`, `curl \| bash`, `subprocess` on encoded data |
| `prompt-injection` | Data-exfil / "ignore instructions" / auto-approve text in SKILL.md, tool descriptions, prompts |
| `secret-literal` | API keys / private keys committed to the repo |
| `committed-binary` | Compiled ELF / Mach-O / PE executables in the tree |
| `forced-artifact` | The honeypot pattern: a build step that generates + commits an encrypted blob |
| `dangerous-perms` | Auto-approve-all, sandbox-disabling, `--dangerously-skip-permissions` |
| `install-hook` | `pre`/`postinstall` scripts that run on install |

Exit code: `0` clean · `2` suspicious · `3` dangerous — so you can gate CI on it.

## Use it in CI

```yaml
- run: npx github:epistemedeus/skillguard ${{ github.workspace }}
```

## Use it as an MCP server

Give your agent the ability to vet a skill/MCP server before installing it. Add to your Claude Code / MCP client config:

```json
{
  "mcpServers": {
    "skillguard": {
      "command": "npx",
      "args": ["-y", "github:epistemedeus/skillguard", "mcp"]
    }
  }
}
```

It exposes one tool, `scan_skill(target)`, where `target` is a local path or a git/GitHub URL. Your agent can then check anything it's about to install. (Static-only — it never runs the scanned code.)

## Show that you passed

If your skill or MCP server comes back clean, earn a badge for your README:

```bash
npx github:epistemedeus/skillguard . --badge
```

It prints a Markdown badge you can paste in — a signal to your users that you ran a malware scan:

[![SkillGuard: no known malware](https://img.shields.io/badge/SkillGuard-no%20known%20malware-2ea44f)](https://github.com/epistemedeus/skillguard)

## Free vs. paid

The CLI is **free and MIT-licensed** — run it as often as you like. If you install third-party skills/MCPs regularly and want to stop worrying:

- **One-time deep audit ($29)** — we manually review a skill/MCP/plugin you're about to depend on and send you a written risk report, same day.
- **Watch mode ($12/mo)** — we re-scan the skills + MCP servers you depend on every time they ship an upstream release, and alert you the moment new risk appears (the rug-pull / mutable-tool problem).

→ **[samedaydesk.com/skillguard](https://samedaydesk.com/skillguard)**

## Limitations

Heuristics catch known-bad patterns; a determined, novel attack can evade any static scanner. SkillGuard is a fast first line of defense, not a guarantee. Always review code from untrusted authors.

---
MIT · by [SameDayDesk](https://samedaydesk.com/) · issues + PRs welcome.
