# Changelog — skill-auditor-desktop

## v1.0 (2026-09-11)

Erste Desktop-taugliche Fassung, abgeleitet vom Claude-Code-Skill `skill-auditor` v2.4.

Grund für eine eigene Variante: claude.ai/Desktop-Skills laufen in einer isolierten Sandbox ohne Zugriff auf das lokale Dateisystem des Nutzers — die CLI-Fassung geht dagegen von direktem Zugriff auf `~/.claude/skills/` und lokal geklonte Repos aus.

**Geändert gegenüber der CLI-Fassung:**
- Bedienung radikal vereinfacht: Nutzer lädt die Skill-Dateien/ein ZIP in den Chat hoch, kein Kommando, kein Pfad, keine Fachbegriffe nötig
- Report-Format vereinfacht: Ampel + Klartext zuerst, Fundstellen-Tabelle nur auf Nachfrage (vorher: immer volle Tabelle)
- Provenienz-Check (Phase 0 der CLI-Fassung) entschärft: kein Blocker mehr, wenn Sandra keine Quelle nennt — einfach mit maximaler Prüfintensität weitermachen statt aktiv nachzufragen
- skills.sh-Badge-Check als optionales Zusatzsignal weggelassen (Netzwerkzugriff auf Desktop nicht garantiert — "Varying network access" je nach Konto-/Admin-Einstellung)

**Entfernt:**
- **Inventar-Modus (Phase 7)** komplett gestrichen — Desktop hat keinen automatisierten Zugriff auf "welche Skills sind installiert" (kein Äquivalent zu `~/.claude/skills/` + `installed_plugins.json`, das ist nur manuell in den Settings einsehbar). Entscheidung: Feature weglassen statt eines Workarounds, der ein irreführendes Sicherheits-/Vollständigkeitssignal geben würde.
- HTML-Dashboard-Export — unnötiges Download-Handling für den Einzel-Audit-Use-Case, den es auf Desktop noch gibt
- `scan_installed_skills()`, `parse_frontmatter()`, `load_audit_status()`, `write_inventory_json()`, `print_inventory_summary()` sowie der `--inventory`-CLI-Zweig aus `audit.py` entfernt (totes Feature für diese Umgebung)

**Unverändert:**
- Scanner-Engine (Kategorien A–H, REJECT-Kombinationslogik, Codefence-Masking) — reine Python-Stdlib, läuft unverändert in der Sandbox (kein `pip install` nötig, Desktop erlaubt ohnehin nur vorinstallierte Pakete)
- Bewertungsregeln (🟢/🟡/🔴) und bekannte False-Positive-Muster

**Installation:** als `.zip` über claude.ai → Settings → Features → Custom Skills hochladen. Individuell pro Nutzerkonto, kein Sync mit der Claude-Code-Fassung und kein organisationsweites Rollout möglich.

Quelle der Basis-Version: https://github.com/ki-stuff/skill-auditor (v2.4)
