#!/usr/bin/env python3
# modules/report_gen.py — Report generator for APIX

import os, json
from datetime import datetime
from utils.colors import print_status


class ReportGenerator:

    def __init__(self, findings: dict, stats: dict):
        self.findings  = findings
        self.stats     = stats
        self.ts        = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.ts_human  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.all       = [i for v in findings.values() for i in (v if isinstance(v, list) else [v])]
        os.makedirs("reports", exist_ok=True)

    def generate(self, fmt="html", filename=None):
        fmt   = fmt.lower()
        if fmt not in ("txt", "json", "html"):
            print_status(f"Unknown format '{fmt}'.", "error"); return None
        fname = filename or f"apix_report_{self.ts}.{fmt}"
        if not fname.endswith(f".{fmt}"): fname += f".{fmt}"
        path  = os.path.join("reports", fname)
        content = {"txt": self._txt, "json": self._json, "html": self._html}[fmt]()
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return path

    def _txt(self):
        lines = ["="*60, "  APIX — API SECURITY REPORT", "="*60,
                 f"  Generated : {self.ts_human}",
                 f"  Session   : {self.stats['id']}",
                 f"  Findings  : {len(self.all)}", "="*60, ""]
        for module, items in self.findings.items():
            lines += [f"[{module}]", "-"*40]
            for item in (items if isinstance(items, list) else [items]):
                if isinstance(item, dict):
                    sev = item.get("severity", "?")
                    lines.append(f"  [{sev}] {item.get('check','')} — {item.get('endpoint','')}")
                    if item.get("detail"):
                        lines.append(f"    {item['detail']}")
                    lines.append("")
        return "\n".join(lines)

    def _json(self):
        high   = sum(1 for f in self.all if isinstance(f, dict) and f.get("severity") in ("HIGH", "CRITICAL"))
        medium = sum(1 for f in self.all if isinstance(f, dict) and f.get("severity") == "MEDIUM")
        return json.dumps({
            "meta":     {"tool": "APIX v1.0", "generated": self.ts_human, "session": self.stats},
            "summary":  {"total": len(self.all), "high": high, "medium": medium},
            "findings": self.findings,
        }, indent=2, default=str)

    def _html(self):
        SEV_COLOR = {
            "CRITICAL": "#f85149", "HIGH": "#f85149", "MEDIUM": "#e3b341",
            "LOW": "#79c0ff", "OK": "#3fb950", "INFO": "#6e7681",
        }
        rows = ""
        for item in self.all:
            if not isinstance(item, dict): continue
            sev   = item.get("severity", "INFO")
            color = SEV_COLOR.get(sev.split()[0], "#6e7681")
            rows += f"""<tr>
                <td><span style="background:{color}22;color:{color};border:1px solid {color};
                    padding:2px 8px;border-radius:3px;font-size:.75rem;font-family:monospace">{sev}</span></td>
                <td>{item.get('check','')}</td>
                <td style="font-family:monospace;font-size:.75rem;word-break:break-all">{item.get('endpoint','')}</td>
                <td style="color:#6e7681;font-size:.75rem">{item.get('detail','')}</td>
            </tr>"""

        high   = sum(1 for f in self.all if isinstance(f, dict) and f.get("severity") in ("HIGH","CRITICAL"))
        medium = sum(1 for f in self.all if isinstance(f, dict) and f.get("severity") == "MEDIUM")

        return f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>APIX Report — {self.ts_human}</title>
<style>
:root{{--bg:#0d1117;--surface:#161b22;--border:#30363d;--red:#f85149;--text:#c9d1d9;--dim:#6e7681;--blue:#79c0ff}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--text);font-family:-apple-system,sans-serif;padding:2rem}}
h1{{color:var(--red);font-size:1.5rem;font-family:monospace;letter-spacing:2px;margin-bottom:.5rem}}
.meta{{color:var(--dim);font-size:.85rem;margin-bottom:1.5rem}} .meta span{{color:var(--blue)}}
.summary{{display:flex;gap:1rem;margin-bottom:2rem}}
.card{{background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:.75rem 1.5rem;text-align:center}}
.card-num{{font-size:1.8rem;font-weight:700}} .card-label{{font-size:.7rem;color:var(--dim);text-transform:uppercase}}
table{{width:100%;border-collapse:collapse;font-size:.82rem}}
th{{background:#1c2128;color:var(--dim);padding:.6rem .8rem;text-align:left;border-bottom:1px solid var(--border)}}
td{{padding:.6rem .8rem;border-bottom:1px solid var(--border);vertical-align:top}}
footer{{color:var(--dim);font-size:.75rem;margin-top:2rem;padding-top:1rem;border-top:1px solid var(--border);text-align:center}}
</style></head><body>
<h1>APIX — API SECURITY REPORT</h1>
<p class="meta">Generated: <span>{self.ts_human}</span> | Session: <span>{self.stats['id']}</span></p>
<div class="summary">
  <div class="card"><div class="card-num" style="color:var(--text)">{len(self.all)}</div><div class="card-label">Total</div></div>
  <div class="card"><div class="card-num" style="color:#f85149">{high}</div><div class="card-label">High/Critical</div></div>
  <div class="card"><div class="card-num" style="color:#e3b341">{medium}</div><div class="card-label">Medium</div></div>
</div>
<table><thead><tr><th>Severity</th><th>Check</th><th>Endpoint</th><th>Detail</th></tr></thead>
<tbody>{rows or '<tr><td colspan="4" style="text-align:center;color:var(--dim)">No findings</td></tr>'}</tbody></table>
<footer>APIX v1.0 — For authorized security testing only | NeiveZ</footer>
</body></html>"""
