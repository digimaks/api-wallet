// SPDX-License-Identifier: EUPL-1.2

package attestation

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// googleAttestationStatusURL serves Google's Android Key Attestation
// revocation status list.
const googleAttestationStatusURL = "https://android.googleapis.com/attestation/status" //nolint:unused

const revocationListTTL = 1 * time.Hour //nolint:unused

//nolint:unused
type revocationEntry struct {
	Status string `json:"status"`
	Reason string `json:"reason"`
}

//nolint:unused
type revocationList struct {
	Entries map[string]revocationEntry `json:"entries"`
}

// revocationChecker fetches and caches Google's attestation status list. A
// fetch failure fails open (logged, chain treated as not-revoked) so an
// outage of Google's endpoint cannot itself take down wallet enrollment; only
// a serial number explicitly present in a successfully fetched list is
// rejected.
//
//nolint:unused
type revocationChecker struct {
	client *http.Client

	mu        sync.Mutex
	fetchedAt time.Time
	list      *revocationList
}

func newRevocationChecker() *revocationChecker {
	return &revocationChecker{
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// revokedSerial returns the serial (lowercase hex, no leading zeros) that
// matched a revoked entry in the chain, or "" if none did or the list could
// not be fetched.
func (r *revocationChecker) revokedSerial(ctx context.Context, chain []*x509.Certificate) (string, error) { //nolint:unused
	list, err := r.currentList(ctx)
	if err != nil {
		return "", err
	}

	for _, cert := range chain {
		serial := strings.ToLower(strings.TrimLeft(cert.SerialNumber.Text(16), "0"))
		if serial == "" {
			serial = "0"
		}

		if entry, ok := list.Entries[serial]; ok && entry.Status != "" {
			return serial, nil
		}
	}

	return "", nil
}

func (r *revocationChecker) currentList(ctx context.Context) (*revocationList, error) { //nolint:unused
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.list != nil && time.Since(r.fetchedAt) < revocationListTTL {
		return r.list, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, googleAttestationStatusURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch status list: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch status list: unexpected status %d", resp.StatusCode)
	}

	list := &revocationList{}
	if err := json.NewDecoder(resp.Body).Decode(list); err != nil {
		return nil, fmt.Errorf("decode status list: %w", err)
	}

	r.list = list
	r.fetchedAt = time.Now()

	return r.list, nil
}
