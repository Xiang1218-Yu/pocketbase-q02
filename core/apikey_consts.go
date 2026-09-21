package core

import "time"

// apiKeyLastUsedThrottle limits how often the lastUsedAt/lastUsedByIP
// fields of a single key are persisted.
const apiKeyLastUsedThrottle = 30 * time.Second
