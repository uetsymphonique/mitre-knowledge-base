# extract_ttp — MITRE ATT&CK extraction scripts

All scripts default to the STIX bundle `enterprise-attack-v18-1.json` in the parent directory.  
Override with `--stix <path>`.

---

## `get_techniques_of_tactic.py`

Export techniques per tactic to TXT or Markdown files.  
One file per tactic by default, or aggregate into a single file with `--single-file`.

| Option | Default | Description |
|--------|---------|-------------|
| `--mode` | *(required)* | `all` — all tactics; `tactic` — specified tactics only |
| `--tactics` | | Tactic names (used with `--mode tactic`), space- or comma-separated |
| `--domain` | `enterprise-attack` | `enterprise-attack` / `mobile-attack` / `ics-attack` |
| `--outdir` | `tactics` | Output directory (multi-file mode) |
| `--format` | `txt` | `txt` or `markdown` |
| `--description` | | Include technique description |
| `--detection` | | Include detection guidance |
| `--detection-logsources` | | Include log source references per analytic (requires `--detection`) |
| `--detection-mutable` | | Include mutable elements per analytic (requires `--detection`) |
| `--procedures` | | Include procedure examples |
| `--procedures-top N` | | Limit number of procedure examples per technique |
| `--sanitize` | | Strip citations, links, and HTML from text |
| `--single-file PATH` | | Merge all tactics into one file (extension auto-set from `--format`) |

```bash
# Export all tactics, plain text
python get_techniques_of_tactic.py --mode all

# Export two tactics as markdown with description and detection
python get_techniques_of_tactic.py --mode tactic --tactics initial-access execution \
  --description --detection --format markdown

# Merge all tactics into one markdown file, top 3 procedures, sanitized
python get_techniques_of_tactic.py --mode all --description --procedures --procedures-top 3 \
  --format markdown --single-file all_techniques.md --sanitize

# Detection with log sources
python get_techniques_of_tactic.py --mode all --detection --detection-logsources \
  --format markdown --outdir techniques/
```

---

## `list_technique_names.py`

Export a flat list of all technique names (ID - Name) to a TXT file.

| Option | Default | Description |
|--------|---------|-------------|
| `--output` / `-o` | `technique_names.txt` | Output file path |
| `--format` | `plain` | `plain` — one technique per line; `array` — quoted strings with trailing comma |

```bash
# Plain list
python list_technique_names.py

# Array format (useful to paste into code)
python list_technique_names.py --format array -o technique_names_array.txt
```

---

## `mitre_dictionary.py`

Build a JSON mapping between tactics and techniques (bidirectional).

| Option | Default | Description |
|--------|---------|-------------|
| `--mapping` | *(required)* | `tactic-to-techniques` or `technique-to-tactics` |
| `--output` / `-o` | `mitre_dictionary.json` | Output JSON file path |
| `--domain` | `enterprise-attack` | ATT&CK domain |
| `--exclude-subtech` | | Exclude sub-techniques, keep parent techniques only |
| `--full-name` | | Use `ID - Name` keys instead of ID only |

```bash
# Tactic → list of technique IDs
python mitre_dictionary.py --mapping tactic-to-techniques -o tac2tech.json

# Technique → list of tactic IDs, with full names
python mitre_dictionary.py --mapping technique-to-tactics --full-name -o tech2tac.json

# Parent techniques only, no sub-techniques
python mitre_dictionary.py --mapping tactic-to-techniques --exclude-subtech -o tac2tech_parents.json
```

---

## `list_analytic_logsources.py`

Export all analytics with their log source references. One row per analytic × log source pair.

**Columns:** `an_id`, `platforms`, `logsource`, `channel`, `dc_id`, `dc_name`

| Option | Default | Description |
|--------|---------|-------------|
| `--format` | `table` | `table` / `markdown` / `csv` |
| `--out` | stdout | Output file path |
| `--logsource` | | Filter rows by log source name (contains, case-insensitive) |
| `--platform` | | Filter rows by platform (contains, case-insensitive) |
| `--exclude-platform` | | Exclude rows matching any of these platforms (space-separated) |
| `--no-empty` | | Exclude analytics with no log source references |
| `--logsource-stats` | | Print log source group breakdown to console; write to `--out` if specified |

```bash
# All analytics to CSV
python list_analytic_logsources.py --no-empty --format csv --out logsources.csv

# Windows only, filtered by log source prefix
python list_analytic_logsources.py --platform Windows --logsource "WinEventLog" \
  --no-empty --format csv --out logsources_wineventlog.csv

# Log source group stats, excluding Windows
python list_analytic_logsources.py --logsource-stats --no-empty \
  --exclude-platform Windows --format csv --out ls_groups_linux.csv

# Log source group stats for Windows
python list_analytic_logsources.py --logsource-stats --no-empty --platform Windows \
  --format csv --out ls_groups_windows.csv
```

---

## `list_logsource_events.py`

Export all unique `(logsource, channel)` events from Data Components, one Markdown file per log source group.

Events are sourced from `x-mitre-data-component → x_mitre_log_sources`.  
Each file contains a table of `(logsource, channel, data components)` for that group.

| Option | Default | Description |
|--------|---------|-------------|
| `--outdir` | `logsource-groups` | Output directory for Markdown files |
| `--group` | | Only export groups whose name contains this string (case-insensitive) |

```bash
# Export all groups
python list_logsource_events.py

# Custom output directory
python list_logsource_events.py --outdir logsource-groups

# Only the WinEventLog group
python list_logsource_events.py --group WinEventLog
```

---

## `export_datacomponents.py`

Export each Data Component as a separate Markdown file.  
Each file includes: description, parent Data Source, log sources, and techniques detected.

| Option | Default | Description |
|--------|---------|-------------|
| `--outdir` | `datacomponents` | Output directory |
| `--domain` | `enterprise-attack` | ATT&CK domain |
| `--filter` | | Only export DCs whose name contains this string (case-insensitive) |
| `--no-techniques` | | Omit the Techniques Detected section |

```bash
# Export all enterprise Data Components
python export_datacomponents.py

# Only Process-related DCs
python export_datacomponents.py --filter "Process" --outdir datacomponents/process

# Without Techniques Detected section
python export_datacomponents.py --no-techniques

# Custom output directory
python export_datacomponents.py --outdir ../datacomponents
```
