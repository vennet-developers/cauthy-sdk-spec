// Package verify is the reference verifier of a Cauthy access token: the
// executable form of verification/rules.md. Every vector in vectors/ runs
// against it. It uses the standard library only.
package verify

import "fmt"

// Reason says why a token was refused. The list is closed: rules.md names
// every reason, and no vector uses another.
type Reason string

const (
	TooLarge          Reason = "too_large"
	Malformed         Reason = "malformed"
	AlgNotAllowed     Reason = "alg_not_allowed"
	UnsupportedHeader Reason = "unsupported_header"
	MissingKid        Reason = "missing_kid"
	UnknownKid        Reason = "unknown_kid"
	WeakKey           Reason = "weak_key"
	BadSignature      Reason = "bad_signature"
	MissingClaim      Reason = "missing_claim"
	InvalidClaim      Reason = "invalid_claim"
	WrongIssuer       Reason = "wrong_issuer"
	WrongAudience     Reason = "wrong_audience"
	Expired           Reason = "expired"
	NotYetValid       Reason = "not_yet_valid"
	IssuedInFuture    Reason = "issued_in_future"
	WrongTenant       Reason = "wrong_tenant"
	SystemToken       Reason = "system_token"
	ClientToken       Reason = "client_token"
	AnonymousToken    Reason = "anonymous_token"
	WrongClient       Reason = "wrong_client"
)

// Reasons is every reason, in the order the checks run.
var Reasons = []Reason{
	TooLarge, Malformed, AlgNotAllowed, UnsupportedHeader, MissingKid, UnknownKid, WeakKey,
	BadSignature, MissingClaim, InvalidClaim, WrongIssuer, WrongAudience, Expired, NotYetValid,
	IssuedInFuture, WrongTenant, SystemToken, ClientToken, AnonymousToken, WrongClient,
}

// Error is a refused token: the reason and a detail for logs. The detail
// never quotes the token.
type Error struct {
	Reason Reason
	Detail string
}

func (e *Error) Error() string { return fmt.Sprintf("token refused: %s: %s", e.Reason, e.Detail) }

func refuse(r Reason, format string, a ...any) *Error {
	return &Error{Reason: r, Detail: fmt.Sprintf(format, a...)}
}
