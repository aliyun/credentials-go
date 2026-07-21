package providers

import "time"

const (
	// SessionStaleTimeSeconds is the remaining-lifetime threshold (seconds) at which
	// session credentials are treated as stale and refreshed.
	// Aligns with Python / Java / Node.js / PHP / C# / C++ (expiration - 15*60).
	SessionStaleTimeSeconds int64 = 15 * 60

	// ExternalExpirationSlotSeconds is the remaining-lifetime threshold for External
	// process credentials. Intentionally 180 across languages (Python/Java/Node/PHP/C#).
	ExternalExpirationSlotSeconds int64 = 180

	// EcsPrefetchTimeSeconds is how soon after a successful IMDS fetch the ECS provider
	// may initiate an async prefetch refresh (every 1 hour), matching Python/Java/Node.
	EcsPrefetchTimeSeconds int64 = 60 * 60
)

// ecsAsyncCheckInterval is the background check interval for ECS IMDS credentials
// (default 1 minute). Overridable in tests to exercise the async checker quickly.
var ecsAsyncCheckInterval = time.Minute

// isSessionCredentialStale reports whether the credential should be refreshed based on
// the shared 15-minute stale window.
func isSessionCredentialStale(expirationTimestamp int64) bool {
	if expirationTimestamp == 0 {
		return true
	}
	return expirationTimestamp-time.Now().Unix() <= SessionStaleTimeSeconds
}
