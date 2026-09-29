package httpthreat

import (
	"fmt"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
)

func (e *Engine) Probe() []auditor.Finding {
	var findings []auditor.Finding
	findings = append(findings, e.probeAuthBypass()...)
	findings = append(findings, e.probeSessionValidation()...)
	findings = append(findings, e.probeOrigin()...)
	findings = append(findings, e.probeBatch()...)
	return findings
}

func (e *Engine) probeAuthBypass() []auditor.Finding {
	initResp, err := e.post(initializePayload(1), map[string]string{})
	if err != nil || !initResp.hasMessage || initResp.message.Error != nil {
		return nil
	}
	headers := map[string]string{}
	if initResp.sessionID != "" {
		headers["Mcp-Session-Id"] = initResp.sessionID
	}
	listResp, err := e.post(toolsListPayload(2), headers)
	if err != nil || !listResp.hasMessage || listResp.message.Error != nil {
		return nil
	}
	severity := auditor.SeverityMedium
	if e.authHeader != "" {
		severity = auditor.SeverityHigh
	}
	return []auditor.Finding{{
		Severity:    severity,
		RuleID:      "HttpAuthBypass01",
		TargetTool:  "server",
		ParamPath:   "http",
		Description: "MCP HTTP endpoint accepts unauthenticated sessions and serves tool listings without credentials",
		Remediation: "Enforce authentication middleware on the MCP endpoint and reject unauthenticated requests with 401.",
		Confirmed:   true,
		Evidence: fmt.Sprintf("initialize (status %d) and tools/list (status %d) succeeded without an Authorization header",
			initResp.statusCode, listResp.statusCode),
	}}
}

func (e *Engine) probeSessionValidation() []auditor.Finding {
	initResp, err := e.post(initializePayload(3), e.authHeaders())
	if err != nil || !initResp.hasMessage || initResp.message.Error != nil {
		return nil
	}
	if initResp.sessionID == "" {
		return nil
	}
	headers := e.authHeaders()
	headers["Mcp-Session-Id"] = "mcpwn-invalid-session"
	listResp, err := e.post(toolsListPayload(4), headers)
	if err != nil || !listResp.hasMessage || listResp.message.Error != nil {
		return nil
	}
	return []auditor.Finding{{
		Severity:    auditor.SeverityMedium,
		RuleID:      "HttpSession01",
		TargetTool:  "server",
		ParamPath:   "http.session",
		Description: "Server accepts invalid Mcp-Session-Id values, allowing session state to be spoofed",
		Remediation: "Validate the Mcp-Session-Id header on every request and respond 404 when the session is unknown.",
		Confirmed:   true,
		Evidence: fmt.Sprintf("tools/list succeeded with a fabricated session id (initialize status %d, tools/list status %d)",
			initResp.statusCode, listResp.statusCode),
	}}
}

func (e *Engine) probeOrigin() []auditor.Finding {
	headers := e.authHeaders()
	headers["Origin"] = "https://mcpwn-origin-probe.example"
	initResp, err := e.post(initializePayload(5), headers)
	if err != nil || !initResp.hasMessage || initResp.message.Error != nil {
		return nil
	}
	return []auditor.Finding{{
		Severity:    auditor.SeverityMedium,
		RuleID:      "HttpOrigin01",
		TargetTool:  "server",
		ParamPath:   "http.origin",
		Description: "MCP HTTP endpoint accepts requests with a foreign Origin header, exposing browser-reachable deployments to CSRF and DNS rebinding",
		Remediation: "Validate the Origin and Host headers on every request and reject cross-origin calls at the HTTP layer.",
		Confirmed:   true,
		Evidence: fmt.Sprintf("initialize succeeded with hostile Origin header (status %d)",
			initResp.statusCode),
	}}
}

func (e *Engine) probeBatch() []auditor.Finding {
	body := []byte(`[{"jsonrpc":"2.0","id":9,"method":"tools/list"}]`)
	resp, err := e.post(body, e.authHeaders())
	if err != nil || !resp.hasMessage || resp.message.Error != nil || resp.message.Result == nil {
		return nil
	}
	return []auditor.Finding{{
		Severity:    auditor.SeverityLow,
		RuleID:      "HttpBatch01",
		TargetTool:  "server",
		ParamPath:   "http.batch",
		Description: "Server accepts JSON-RPC batch arrays, which are outside MCP protocol semantics",
		Remediation: "Reject JSON-RPC batch payloads and respond with a protocol error, per the MCP specification.",
		Confirmed:   true,
		Evidence: fmt.Sprintf("batched tools/list returned a result (status %d)",
			resp.statusCode),
	}}
}
