// Package nhcx holds the protocol-level rules of the NHCX exchange: the JWE
// protected headers every message carries, how they are completed, and the
// JWE encryption the payload travels under.
package nhcx

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Protected header keys carried in the JWE header of every NHCX message.
const (
	HdrAPICallID     = "x-hcx-api_call_id"
	HdrRequestID     = "x-hcx-request_id"
	HdrCorrelationID = "x-hcx-correlation_id"
	HdrTimestamp     = "x-hcx-timestamp"
	HdrStatus        = "x-hcx-status"
	HdrSender        = "x-hcx-sender_code"
	HdrRecipient     = "x-hcx-recipient_code"
	HdrWorkflowID    = "x-hcx-workflow_id"
)

// TimestampLayout is the x-hcx-timestamp format: RFC3339 with a colon-less
// zone offset, e.g. "2023-11-06T13:22:06+0530".
const TimestampLayout = "2006-01-02T15:04:05-0700"

// Timestamp returns the current local time in the NHCX header format.
func Timestamp() string { return time.Now().Format(TimestampLayout) }

// AckTimestamp formats t the way the 202 acceptance body wants it:
// "DD/MM/YYYY hh:mm:ss:sss".
func AckTimestamp(t time.Time) string {
	return fmt.Sprintf("%s:%03d", t.Format("02/01/2006 15:04:05"), t.Nanosecond()/1e6)
}

// NewID returns a fresh UUID for the id headers.
func NewID() string { return uuid.New().String() }

// IsID reports whether s is a plain 8-4-4-4-12 UUID, the only spelling NHCX
// accepts for api_call_id, request_id and correlation_id.
func IsID(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) != 36 {
		return false
	}
	_, err := uuid.Parse(s)
	return err == nil
}

// EnsureID returns s when it is a UUID, otherwise a fresh one.
func EnsureID(s string) string {
	if IsID(s) {
		return strings.TrimSpace(s)
	}
	return NewID()
}

// NormalizeCode appends the "@hcx" suffix participant codes carry on the wire.
func NormalizeCode(code string) string {
	code = strings.TrimSpace(code)
	if code == "" || strings.HasSuffix(code, "@hcx") {
		return code
	}
	return code + "@hcx"
}

// SameCode compares two participant codes in either spelling.
func SameCode(a, b string) bool {
	return strings.EqualFold(NormalizeCode(a), NormalizeCode(b))
}

// CleanPath trims slashes off an NHCX API path: "/v1/preauth/submit/" →
// "v1/preauth/submit".
func CleanPath(path string) string { return strings.Trim(strings.TrimSpace(path), "/") }

// IsResponsePath reports whether an NHCX path is a response ("on_") API —
// v1/preauth/on_submit, v1/coverageeligibility/on_check, v1/on_status ...
func IsResponsePath(path string) bool {
	segs := strings.Split(CleanPath(path), "/")
	return strings.HasPrefix(segs[len(segs)-1], "on_")
}

// DefaultStatus is the x-hcx-status to use when the caller did not supply one.
func DefaultStatus(path string) string {
	if IsResponsePath(path) {
		return "response.complete"
	}
	return "request.initiated"
}

// EntityType maps an API path to the entity_type the acceptance body names:
// v1/preauth/on_submit → preauth, v1/paymentnotice/request → payment,
// v1/on_status → status.
func EntityType(path string) string {
	segs := strings.Split(CleanPath(path), "/")
	var entity string
	switch len(segs) {
	case 0:
		return ""
	case 1:
		entity = segs[0]
	default:
		entity = segs[len(segs)-2]
		if entity == "v1" { // v1/on_status, v1/status, v1/error
			entity = segs[len(segs)-1]
		}
	}
	entity = strings.TrimPrefix(entity, "on_")
	if entity == "paymentnotice" {
		return "payment"
	}
	return entity
}

// GetString reads a string header value, tolerating a nil map.
func GetString(headers map[string]any, key string) string {
	if headers == nil {
		return ""
	}
	s, _ := headers[key].(string)
	return strings.TrimSpace(s)
}

// BuildProtectedHeaders returns the complete protected header set for a
// message bound for path. Caller values win, except the three id headers,
// which are replaced unless they are UUIDs; whatever the gateway requires
// but the caller omitted is generated. Empty values are dropped.
func BuildProtectedHeaders(in map[string]any, path string) map[string]any {
	out := make(map[string]any, len(in)+6)
	for k, v := range in {
		if s, ok := v.(string); ok {
			if s = strings.TrimSpace(s); s != "" {
				out[k] = s
			}
			continue
		}
		if v != nil {
			out[k] = v
		}
	}
	for _, k := range []string{HdrSender, HdrRecipient} {
		if c := NormalizeCode(GetString(out, k)); c != "" {
			out[k] = c
		} else {
			delete(out, k)
		}
	}
	out[HdrCorrelationID] = EnsureID(GetString(out, HdrCorrelationID))
	out[HdrRequestID] = EnsureID(GetString(out, HdrRequestID))
	out[HdrAPICallID] = EnsureID(GetString(out, HdrAPICallID))
	if GetString(out, HdrStatus) == "" {
		out[HdrStatus] = DefaultStatus(path)
	}
	if GetString(out, HdrTimestamp) == "" {
		out[HdrTimestamp] = Timestamp()
	}
	if GetString(out, HdrWorkflowID) == "" {
		delete(out, HdrWorkflowID)
	}
	return out
}

// TargetURL joins the NHCX gateway base with an API path, tolerating a
// "/v1" suffix on the base and a "v1/" prefix on the path.
func TargetURL(base, path string) string {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	path = CleanPath(path)
	if path == "" {
		return base
	}
	if strings.HasSuffix(base, "/v1") && strings.HasPrefix(path, "v1/") {
		base = strings.TrimSuffix(base, "/v1")
	}
	return base + "/" + path
}
