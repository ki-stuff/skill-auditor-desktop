# 🛡️ Skill-Auditor Desktop

## 🇩🇪 Kurzbeschreibung

**Skills sind Prompts. Manche bringen Scripts mit. Beides kann feindlich
sein — und beim Hochladen prüft das niemand.**

Der Skill-Auditor Desktop schließt genau diese Lücke für **claude.ai und
Claude Desktop**: Lade den Skill, den du prüfen willst (Datei, Ordner oder
`.zip`), in den Chat hoch und frag, ob er sicher ist. Der Auditor führt
automatisch einen Muster-Scan plus eine inhaltliche Prüfung durch — gegen
Prompt Injection, Datenexfiltration, Rechteausweitung, Persistenz und Social
Engineering — und gibt dir eine einfache Ampel-Einschätzung (🟢 / 🟡 / 🔴)
in Klartext zurück. Kein Kommando, kein Pfad, kein Fachjargon nötig.

> **Nutzt du Claude Code (die CLI)?** Diese Fassung ist bewusst auf die
> claude.ai/Desktop-Sandbox zugeschnitten (kein Dateisystemzugriff, daher
> Upload statt Pfadangabe, kein Inventar-Modus). Für die CLI mit vollem
> Funktionsumfang — inklusive Dashboard über alle installierten Skills —
> die Schwesterfassung nutzen: [skill-auditor](https://github.com/ki-stuff/skill-auditor).

---

A Claude Skill that vets *other* skills before you trust them — built
specifically for **claude.ai and Claude Desktop**, where Skills run in an
isolated sandbox with no access to your local filesystem.

Upload the skill you want to check (a file, a folder, or a `.zip`) into the
conversation and ask whether it's safe. The auditor runs an automated
pattern scan plus a manual content review — prompt injection, data
exfiltration, privilege escalation, persistence, social engineering — and
replies with a plain-language traffic-light verdict (🟢 / 🟡 / 🔴). No
commands, no paths, no jargon required.

> **Using Claude Code (the CLI) instead?** Use the full-featured sibling
> project instead: [skill-auditor](https://github.com/ki-stuff/skill-auditor).
> It has direct filesystem access, so it can also scan everything you
> already have installed under `~/.claude/skills/` (inventory mode) — a
> claude.ai/Desktop Skill has no equivalent access and can't do that safely.

## Why a separate edition

claude.ai/Desktop custom Skills run in a sandboxed VM with no access to the
user's local machine — every file the skill touches has to be uploaded into
the conversation first. The Claude Code edition of this tool assumes the
opposite: direct filesystem access to `~/.claude/skills/`, arbitrary cloned
repos, and an inventory scan across everything installed locally. Porting
that 1:1 would have meant faking a feature (an "installed skills overview")
that simply can't work in this environment — so this edition drops it
instead of simulating it. See [CHANGELOG.md](CHANGELOG.md) for the full
list of what changed and what got removed.

## What it checks

- **Network / exfiltration** — curl, wget, requests, fetch, and combinations
  that read a secret and send it somewhere
- **Code execution** — eval, exec, subprocess, child_process, `curl | bash`
- **Obfuscation** — base64, hex/unicode escapes, `String.fromCharCode`
- **Package installs / privilege escalation** — pip/npm/apt install, sudo,
  chmod 777, PATH tampering, cron/launch-agent persistence
- **Prompt injection & social engineering** — "ignore previous instructions",
  role reassignment, fake `<system-reminder>`/`<system>` tags, vetting-bypass
  language
- **Persistence & stealth** — crontab, shell rc-file edits, modifying
  `CLAUDE.md`/`settings.json`/`MEMORY.md`, self-update mechanisms
- **Secrets access** — `.ssh`, `.aws`, `.env`, API keys, passwords, private keys
- **Time bombs** — date/version-gated conditional logic that behaves
  differently on review day than later

Findings are split into `CRITICAL` / `HIGH` / `MEDIUM`, plus a `REJECT` tier
for pattern *combinations* (e.g. reading `.ssh` **and** piping it to curl in
the same file) that auto-fail regardless of individual pattern severity.
Patterns inside markdown code fences are skipped for most categories — a
regex shown as a documentation example isn't a live injection.

## Setup

1. Download [`skill-auditor-desktop.zip`](https://github.com/ki-stuff/skill-auditor-desktop/releases)
   (or clone this repo and zip the `skill-auditor-desktop/` folder yourself —
   it must be the zip's root, not nested in a subfolder).
2. On claude.ai (or Claude Desktop): **Settings → Features → Custom Skills →
   Upload**. Requires a Pro/Max/Team/Enterprise plan with code execution
   enabled.
3. Done. Upload a skill to check into any conversation and ask whether it's
   safe — the skill triggers automatically on that intent.

Custom Skills on claude.ai are per-account, not shared org-wide, and don't
sync with the Claude Code edition — each surface needs its own upload.

## Usage

Just upload the skill files (or a `.zip`) into the chat and ask something
like "is this skill safe?" or "check this skill". No manual steps beyond
that — the skill reads the uploaded files, runs `scripts/audit.py`
(pure Python stdlib, no `pip install` needed) against them, cross-checks
the findings for context, and replies with a short verdict. Ask for
"details" to get the full finding-by-finding table instead of just the
summary.

## Structure

```
skill-auditor-desktop/
├── SKILL.md          # the agent workflow, simplified for the sandbox
├── README.md
├── CHANGELOG.md
└── scripts/
    └── audit.py       # automated pattern scanner (no inventory mode)
```

## Limitations

This is a pragmatic first pass, not a full security audit. It catches known
patterns; it won't catch a genuinely novel obfuscation technique or a purely
prose-based social-engineering attempt with no matching keywords. Treat a
clean scan as "no obvious red flags," not "certified safe."

Network access for the manual skills.sh cross-check (an optional second
signal) depends on your account/admin settings ("varying network access")
and isn't guaranteed.

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

MIT.
