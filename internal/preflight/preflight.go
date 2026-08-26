// Package preflight verifies, before the gateway serves anything, that it
// can actually work: the credentials mint a session token, the participant
// exists on the registry, the registry's encryption certificate is the one
// this gateway's private key opens, and — once the listener is up — the
// endpoint registered for the participant leads back to this gateway.
package preflight

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"nhcx-gateway/internal/abdm"
	"nhcx-gateway/internal/gateway"
	"nhcx-gateway/internal/keys"
	"nhcx-gateway/internal/probe"
)

// CertState is the verdict on the registry's certificate for this participant.
type CertState string

const (
	CertMatch    CertState = "match"    // registry certificate opens with our private key
	CertMismatch CertState = "mismatch" // registry has a different key
	CertMissing  CertState = "missing"  // registry has no usable certificate
	CertUnknown  CertState = "unknown"  // could not ask
)

// Check is one verified fact.
type Check struct {
	Name   string
	OK     bool
	Detail string
}

// Report is the outcome of Run.
type Report struct {
	Checks      []Check
	TokenErr    error
	Participant *abdm.Participant
	Cert        CertState
	RegistryPEM string
}

// Fatal reports whether serving is pointless: no session token means every
// outbound call and every certificate lookup fails.
func (r *Report) Fatal() bool { return r.TokenErr != nil }

// Healthy reports whether everything checked out.
func (r *Report) Healthy() bool {
	for _, c := range r.Checks {
		if !c.OK {
			return false
		}
	}
	return true
}

func (r *Report) add(name string, ok bool, detail string) {
	r.Checks = append(r.Checks, Check{Name: name, OK: ok, Detail: detail})
}

// Run performs the network checks. It never panics and never blocks longer
// than the ABDM client's timeout per call.
func Run(ctx context.Context, gw *gateway.Gateway) *Report {
	r := &Report{Cert: CertUnknown}
	cfg := gw.Config()
	client := gw.ABDM()

	if _, err := client.RefreshToken(ctx); err != nil {
		r.TokenErr = err
		r.add("session token", false, explain(err)+" — check participant.clientId / clientSecret, auth.mode and urls.sessions")
		return r
	}
	r.add("session token", true, fmt.Sprintf("issued by %s", cfg.URLs.Sessions))

	p, err := client.FetchParticipant(ctx, cfg.Participant.ParticipantID)
	if err != nil {
		r.add("participant record", false, explain(err))
	} else {
		r.Participant = p
		detail := p.Code
		if p.Name != "" {
			detail += " · " + p.Name
		}
		if p.Status != "" {
			detail += " · " + p.Status
		}
		if p.EndpointURL != "" {
			detail += " · endpoint " + p.EndpointURL
		} else {
			detail += " · no endpoint_url registered"
		}
		r.add("participant record", true, detail)
	}

	_, pem, err := client.FetchCertificate(ctx, cfg.Participant.ParticipantID)
	switch {
	case err == nil:
		r.RegistryPEM = pem
		pub, perr := keys.ParsePublicKey(pem)
		if perr != nil {
			r.Cert = CertMissing
			r.add("encryption certificate", false, "registry certificate is unreadable: "+perr.Error())
		} else if client.OwnKey() != nil && client.OwnKey().Equal(pub) {
			r.Cert = CertMatch
			r.add("encryption certificate", true, "registry certificate matches participant.privateKey")
		} else {
			r.Cert = CertMismatch
			r.add("encryption certificate", false, "registry certificate does NOT match participant.privateKey — inbound messages could not be decrypted")
		}
	default:
		e := abdm.AsError(err)
		if e.Code == "CERT_NOT_FOUND" {
			r.Cert = CertMissing
			r.add("encryption certificate", false, "registry has no encryption certificate for "+cfg.Participant.ParticipantID)
		} else {
			r.add("encryption certificate", false, explain(err))
		}
	}
	return r
}

// TestEndpoint checks that the endpoint_url registered for the participant
// leads to a gateway running with this configuration: it POSTs
// {"probe": nonce} to <endpoint>/healthz and verifies the "probe_ack" in
// the JSON answer — an HMAC only a gateway with the same key can produce.
// key comes from probe.Key(cfg). Call it after the listener is up.
func TestEndpoint(ctx context.Context, endpointURL string, key []byte) Check {
	const name = "registered endpoint"
	endpointURL = strings.TrimRight(strings.TrimSpace(endpointURL), "/")
	if endpointURL == "" {
		return Check{Name: name, OK: false, Detail: "no endpoint_url on the registry record — NHCX has nowhere to deliver callbacks"}
	}
	u := endpointURL + "/healthz"
	nonce, err := probe.Nonce()
	if err != nil {
		return Check{Name: name, OK: false, Detail: "cannot generate probe nonce: " + err.Error()}
	}
	body, _ := json.Marshal(probe.Request{Probe: nonce})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return Check{Name: name, OK: false, Detail: fmt.Sprintf("%s: %v", u, err)}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	// No compression on the probe: some proxies buffer or rewrite encoded
	// responses, and Go would otherwise advertise gzip on its own.
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("User-Agent", "nhcx-gateway-check")
	resp, err := (&http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{DisableCompression: true, Proxy: http.ProxyFromEnvironment},
	}).Do(req)
	if err != nil {
		return Check{Name: name, OK: false, Detail: fmt.Sprintf("%s unreachable from here: %v", u, err)}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))

	who := ""
	if srv := resp.Header.Get("Server"); srv != "" {
		who = " (Server: " + srv + ")"
	}
	var ans probe.Response
	_ = json.Unmarshal(raw, &ans)
	switch {
	case ans.ProbeAck == "":
		excerpt := strings.Join(strings.Fields(string(raw)), " ")
		if len(excerpt) > 120 {
			excerpt = excerpt[:120] + "…"
		}
		if excerpt != "" {
			excerpt = " — body: " + excerpt
		}
		return Check{Name: name, OK: false, Detail: fmt.Sprintf("%s answered %d%s without a probe acknowledgement%s — the proxy at that URL is not forwarding to this gateway's listen address", u, resp.StatusCode, who, excerpt)}
	case !probe.Verify(key, nonce, ans.ProbeAck):
		return Check{Name: name, OK: false, Detail: u + " is an nhcx-gateway, but not one running with this configuration (different participant or credentials)"}
	case resp.StatusCode != http.StatusOK:
		return Check{Name: name, OK: false, Detail: fmt.Sprintf("%s reaches this gateway but answered %d", u, resp.StatusCode)}
	}
	return Check{Name: name, OK: true, Detail: u + " reaches this gateway (probe acknowledged)"}
}

// explain renders an error for an operator: code, message, and the
// upstream body when there is one.
func explain(err error) string {
	var e *abdm.Error
	if !errors.As(err, &e) {
		return err.Error()
	}
	s := e.Code + ": " + e.Message
	if e.Body != "" {
		b := strings.TrimSpace(e.Body)
		if len(b) > 200 {
			b = b[:200] + "…"
		}
		s += " (" + b + ")"
	} else if e.Err != nil {
		s += ": " + e.Err.Error()
	}
	return s
}
