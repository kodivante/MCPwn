package authaudit

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
)

const (
	defaultTimeout    = 10 * time.Second
	metadataRuleID    = "OAuthMetadata01"
	pkceRuleID        = "OAuthPkce01"
	passthroughRuleID = "TokenPassthrough01"
)

type Options struct {
	Timeout time.Duration
}

type Engine struct {
	url             string
	authHeaderValue string
	client          *http.Client
}

func NewEngine(url string, authHeaderValue string, options Options) *Engine {
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &Engine{url: url, authHeaderValue: authHeaderValue, client: &http.Client{Timeout: timeout}}
}

func (e *Engine) Probe() []auditor.Finding {
	challenge, ok := e.unauthenticatedChallenge()
	if !ok {
		return nil
	}
	metadata, found := e.fetchMetadata(challenge)
	var findings []auditor.Finding
	if !found {
		findings = append(findings, missingMetadataFinding())
		return append(findings, e.passthroughFindings()...)
	}
	if !requiresPKCE(metadata) {
		findings = append(findings, pkceFinding(metadata.AuthorizationEndpoint))
	}
	return append(findings, e.passthroughFindings()...)
}

type authChallenge struct {
	metadataURL string
}

func (e *Engine) unauthenticatedChallenge() (authChallenge, bool) {
	req, err := http.NewRequest(http.MethodPost, e.url, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"MCPwn auth probe","version":"1.0.0"}}}`))
	if err != nil {
		return authChallenge{}, false
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.client.Do(req)
	if err != nil {
		return authChallenge{}, false
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusUnauthorized {
		return authChallenge{}, false
	}
	return parseChallenge(resp.Header.Get("WWW-Authenticate")), true
}

func parseChallenge(header string) authChallenge {
	if header == "" {
		return authChallenge{}
	}
	for _, part := range strings.Split(header, ",") {
		trimmed := strings.TrimSpace(part)
		if strings.HasPrefix(trimmed, "resource_metadata=") {
			return authChallenge{metadataURL: strings.Trim(strings.TrimPrefix(trimmed, "resource_metadata="), `"`)}
		}
	}
	for _, part := range strings.Split(header, " ") {
		if strings.HasPrefix(part, "realm=") {
			return authChallenge{metadataURL: strings.Trim(strings.TrimPrefix(part, "realm="), `"`)}
		}
	}
	return authChallenge{}
}

type authorizationMetadata struct {
	AuthorizationEndpoint         string   `json:"authorization_endpoint"`
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
}

func (e *Engine) fetchMetadata(challenge authChallenge) (authorizationMetadata, bool) {
	endpoints := []string{challenge.metadataURL}
	if parsed, err := url.Parse(e.url); err == nil {
		endpoints = append(endpoints, parsed.Scheme+"://"+parsed.Host+"/.well-known/oauth-authorization-server")
	}
	for _, endpoint := range endpoints {
		if endpoint == "" {
			continue
		}
		req, err := http.NewRequest(http.MethodGet, endpoint, nil)
		if err != nil {
			continue
		}
		resp, err := e.client.Do(req)
		if err != nil {
			continue
		}
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil || resp.StatusCode != http.StatusOK {
			continue
		}
		var metadata authorizationMetadata
		if err := unmarshalStrict(body, &metadata); err != nil {
			continue
		}
		return metadata, true
	}
	return authorizationMetadata{}, false
}

func unmarshalStrict(data []byte, target *authorizationMetadata) error {
	return json.Unmarshal(data, target)
}

func requiresPKCE(metadata authorizationMetadata) bool {
	for _, method := range metadata.CodeChallengeMethodsSupported {
		if strings.EqualFold(method, "S256") {
			return true
		}
	}
	return false
}

func (e *Engine) passthroughFindings() []auditor.Finding {
	if e.authHeaderValue == "" {
		return nil
	}
	req, err := http.NewRequest(http.MethodPost, e.url, strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer mcpwn-passthrough-probe")
	resp, err := e.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusUnauthorized {
		return []auditor.Finding{{
			Severity:    auditor.SeverityHigh,
			RuleID:      passthroughRuleID,
			TargetTool:  "server",
			ParamPath:   "http.authorization",
			Description: "Server accepts arbitrary bearer tokens without validating them",
			Remediation: "Validate the token audience, issuer and signature on every request; a token from another system must never grant access here.",
			Confirmed:   true,
			Evidence:    fmt.Sprintf("tools/list answered with a fabricated bearer token (status %d)", resp.StatusCode),
		}}
	}
	return nil
}

func missingMetadataFinding() auditor.Finding {
	return auditor.Finding{
		Severity:    auditor.SeverityMedium,
		RuleID:      metadataRuleID,
		TargetTool:  "server",
		ParamPath:   "http.oauth",
		Description: "OAuth-protected resource does not publish authorization server metadata",
		Remediation: "Publish RFC 9728 protected-resource metadata so clients can discover the authorization server and validate tokens correctly.",
		Evidence:    "401 challenge present but /.well-known/oauth-authorization-server is unreachable",
	}
}

func pkceFinding(authorizationEndpoint string) auditor.Finding {
	return auditor.Finding{
		Severity:    auditor.SeverityMedium,
		RuleID:      pkceRuleID,
		TargetTool:  "server",
		ParamPath:   "http.oauth.pkce",
		Description: "Authorization server does not advertise S256 PKCE support",
		Remediation: "Require PKCE with the S256 challenge method on every authorization request to block authorization code interception.",
		Evidence:    fmt.Sprintf("code_challenge_methods_supported lacks S256 (authorization endpoint %q)", authorizationEndpoint),
	}
}
