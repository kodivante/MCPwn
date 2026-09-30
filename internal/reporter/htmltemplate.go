package reporter

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MCPwn Audit Report v{{.Version}}</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { background: #f6f8fa; color: #1f2328; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; line-height: 1.5; padding: 32px 16px; }
.wrap { max-width: 960px; margin: 0 auto; background: #ffffff; border: 1px solid #d0d7de; border-radius: 10px; padding: 28px 32px 24px; box-shadow: 0 1px 3px rgba(31,35,40,0.08); }
h1 { color: #1f2328; font-size: 26px; letter-spacing: 0.5px; }
h1 span { color: #ff8000; font-size: 15px; margin-left: 10px; font-weight: 700; }
.sub { color: #57606a; font-size: 13px; margin-top: 6px; }
.meta { color: #6e7781; font-size: 12px; margin-top: 2px; }
.brandbar { height: 4px; background: linear-gradient(90deg, #ff8000, #ffb266); border-radius: 2px; margin-top: 14px; }
.dashboard { display: flex; gap: 12px; margin: 24px 0 8px; flex-wrap: wrap; }
.stat { flex: 1 1 120px; background: #ffffff; border: 1px solid #d0d7de; border-radius: 8px; padding: 12px 16px; }
.stat .num { font-size: 24px; font-weight: 700; }
.stat .label { font-size: 10px; color: #57606a; letter-spacing: 1px; text-transform: uppercase; margin-top: 2px; }
.stat.total .num { color: #1f2328; }
.stat.confirmed .num { color: #1a7f37; }
.stat.risk .num { color: #8250df; }
.stat.critical .num { color: #cf222e; }
.stat.high .num { color: #bc4c00; }
.stat.medium .num { color: #bf8700; }
.stat.low .num { color: #0969da; }
section { margin-top: 28px; }
h2 { font-size: 13px; letter-spacing: 2px; text-transform: uppercase; padding-bottom: 8px; border-bottom: 1px solid #d0d7de; }
h2.critical { color: #cf222e; }
h2.high { color: #bc4c00; }
h2.medium { color: #bf8700; }
h2.low { color: #0969da; }
.card { background: #ffffff; border: 1px solid #d0d7de; border-left-width: 3px; border-radius: 8px; padding: 16px 18px; margin-top: 12px; box-shadow: 0 1px 2px rgba(31,35,40,0.04); }
.card.critical { border-left-color: #cf222e; }
.card.high { border-left-color: #bc4c00; }
.card.medium { border-left-color: #bf8700; }
.card.low { border-left-color: #0969da; }
.card-head { display: flex; justify-content: space-between; align-items: center; gap: 8px; flex-wrap: wrap; }
.tool { color: #1f2328; font-weight: 700; font-size: 15px; }
.badge { font-size: 11px; padding: 3px 10px; border-radius: 999px; border: 1px solid #d0d7de; color: #57606a; letter-spacing: 1px; }
.badge.confirmed { color: #1a7f37; border-color: #1a7f37; background: #dafbe1; }
.row { margin-top: 10px; font-size: 13px; }
.row .k { color: #6e7781; display: inline-block; min-width: 64px; }
.row .rule { color: #0969da; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; }
.row .path { color: #8250df; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; }
.desc { margin-top: 10px; font-size: 13px; color: #1f2328; }
.remediation { margin-top: 8px; font-size: 13px; color: #57606a; }
.remediation .k { color: #6e7781; font-weight: 700; }
.evidence { margin-top: 8px; font-size: 12px; color: #116329; background: #dafbe1; border: 1px solid #aff0c4; border-radius: 6px; padding: 8px 10px; overflow-wrap: anywhere; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
.owasp { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; }
.owasp th { text-align: left; padding: 8px 10px; font-size: 11px; letter-spacing: 1px; text-transform: uppercase; color: #57606a; border-bottom: 2px solid #d0d7de; }
.owasp td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #d0d7de; }
.owasp .detected { color: #cf222e; font-weight: 700; }
.owasp .covered { color: #1a7f37; }
.owasp .partial { color: #bf8700; }
.owasp .planned { color: #6e7781; }
.empty { margin-top: 28px; text-align: center; color: #1a7f37; background: #ffffff; border: 1px solid #d0d7de; border-radius: 8px; padding: 32px; font-size: 15px; }
footer { margin-top: 36px; padding-top: 16px; border-top: 1px solid #d0d7de; color: #57606a; font-size: 12px; }
footer .author { color: #1f2328; font-weight: 700; font-size: 13px; margin-bottom: 2px; }
footer .author span { color: #ff8000; }
</style>
</head>
<body>
<div class="wrap">
<header>
<h1>MCPwn <span>v{{.Version}}</span></h1>
<p class="sub">Security Auditor and Fuzzing Linter for Model Context Protocol servers</p>
<p class="meta">Designed and developed by kodivante</p>
<p class="meta">Generated {{.GeneratedAt}}</p>
<div class="brandbar"></div>
</header>
<div class="dashboard">
<div class="stat total"><div class="num">{{.Total}}</div><div class="label">Findings</div></div>
<div class="stat confirmed"><div class="num">{{.Confirmed}}</div><div class="label">Confirmed</div></div>
<div class="stat risk"><div class="num">{{.RiskIndex}}</div><div class="label">Risk Index ({{.RiskGrade}})</div></div>
<div class="stat critical"><div class="num">{{.CountCritical}}</div><div class="label">Critical</div></div>
<div class="stat high"><div class="num">{{.CountHigh}}</div><div class="label">High</div></div>
<div class="stat medium"><div class="num">{{.CountMedium}}</div><div class="label">Medium</div></div>
<div class="stat low"><div class="num">{{.CountLow}}</div><div class="label">Low</div></div>
</div>
<section>
<h2>OWASP MCP Top 10</h2>
<table class="owasp">
<tr><th>ID</th><th>Risk</th><th>Coverage</th><th>Findings</th></tr>
{{range .Owasp}}
<tr><td>{{.ID}}</td><td>{{.Title}}</td><td class="{{.Status}}{{if .HasFindings}} detected{{end}}">{{.Status}}{{if .HasFindings}} · detected{{end}}</td><td>{{.Findings}}</td></tr>
{{end}}
</table>
</section>
{{if .Sections}}
{{range .Sections}}
<section>
<h2 class="{{.Class}}">{{.Severity}} · {{len .Findings}}</h2>
{{range .Findings}}
<article class="card {{.SevClass}}">
<div class="card-head">
<span class="tool">{{.TargetTool}}</span>
<span class="badge {{.StatusClass}}">{{.StatusLabel}}</span>
</div>
<div class="row"><span class="k">Rule</span><span class="rule">{{.RuleID}}</span></div>
<div class="row"><span class="k">Path</span><span class="path">{{.ParamPath}}</span></div>
{{if .OwaspMcp}}<div class="row"><span class="k">OWASP</span><span class="path">{{.OwaspMcp}}</span></div>{{end}}
{{if .Verification}}<div class="row"><span class="k">Proof</span><span class="path">{{.Verification}}</span></div>{{end}}
<p class="desc">{{.Description}}</p>
{{if .Remediation}}
<p class="remediation"><span class="k">Fix:</span> {{.Remediation}}</p>
{{end}}
{{if .Evidence}}
<p class="evidence">Evidence: {{.Evidence}}</p>
{{end}}
</article>
{{end}}
</section>
{{end}}
{{else}}
<div class="empty">No vulnerabilities found.</div>
{{end}}
<footer>
<p class="author">Designed and developed by <span>kodivante</span></p>
<p>MCPwn v{{.Version}} — for authorized security auditing only. Report generated locally, no data leaves your machine.</p>
</footer>
</div>
</body>
</html>
`
