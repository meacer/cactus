package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/letsencrypt/cactus/cert"
	"github.com/letsencrypt/cactus/mirror"
	"github.com/letsencrypt/cactus/storage"
	"github.com/letsencrypt/cactus/tlogx"

	"golang.org/x/mod/sumdb/tlog"
)

// sha256Sum is just sha256.Sum256, kept short for the helper above.
func sha256Sum(b []byte) [32]byte { return sha256.Sum256(b) }

// TestMirrorSignSubtreeHappyPath: stand up a CA + a follower, advance
// the follower, then send a well-formed sign-subtree request to the
// mirror's server and confirm the returned cosignature verifies.
func TestMirrorSignSubtreeHappyPath(t *testing.T) {
	ca := bringUp(t, t.TempDir())
	defer ca.close()

	for i := 0; i < 5; i++ {
		if _, err := acmeIssueOne(ca.acmeBase, fmt.Sprintf("ms%d.test", i)); err != nil {
			t.Fatal(err)
		}
	}

	mfs, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	follower, err := mirror.NewFollower(mirror.FollowerConfig{
		Upstream: mirror.Upstream{
			TileURL: ca.tileBase, LogID: ca.logID,
			CACosignerID:  ca.cosigner,
			CACosignerKey: ca.signer.PublicKey(),
		},
		FS: mfs, PollInterval: 25 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startFollower(t, ctx, follower)
	caSize := waitFollowerCatchUp(t, follower, ca.log.CurrentCheckpoint().Size, 3*time.Second)

	// Mirror's own cosigner key (different from the CA's). The witness
	// path is ML-DSA-44 only.
	mirrorID := cert.TrustAnchorID("32473.21")
	mSigner, mKey := mldsaCosigner(t, mirrorID, 0xCC)

	srv, err := mirror.NewServer(mirror.ServerConfig{
		Follower:                    follower,
		Signer:                      mSigner,
		CosignerID:                  mirrorID,
		RequireCASignatureOnSubtree: false, // off so we don't have to forge a CA sig on the subtree
	})
	if err != nil {
		t.Fatal(err)
	}
	hSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/sign-subtree" {
			srv.Handler().ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	}))
	defer hSrv.Close()

	// Pick a subtree the mirror can verify. [0, 1) (just the null entry).
	subtreeStart, subtreeEnd := uint64(0), uint64(1)
	subtreeHash, err := follower.SubtreeHash(subtreeStart, subtreeEnd)
	if err != nil {
		t.Fatal(err)
	}

	// Fetch the CA's current signed checkpoint as the cosigned-checkpoint
	// section of our request. The mirror's stateful check requires
	// (size, root) to match its current view, which equals the CA's
	// signed checkpoint that the follower just verified.
	cpResp, err := http.Get(ca.tileBase + "/checkpoint")
	if err != nil {
		t.Fatal(err)
	}
	cpBody, _ := io.ReadAll(cpResp.Body)
	cpResp.Body.Close()

	// Build the consistency proof from [start, end) up to the CA's
	// current size + root, using the CA's stored hashes.
	hashes, _, err := loadAllStoredHashes(ca.tileBase, caSize)
	if err != nil {
		t.Fatal(err)
	}
	hr := hashReaderFromSlice(hashes)
	proof, err := tlogx.GenerateConsistencyProof(
		sha256Hash, subtreeStart, subtreeEnd, caSize,
		func(i uint64) (tlogx.Hash, error) {
			// Look up leaf hash directly: stored index for level 0, n=i.
			hs, err := hr.ReadHashes([]int64{tlog.StoredHashIndex(0, int64(i))})
			if err != nil {
				return tlogx.Hash{}, err
			}
			return tlogx.Hash(hs[0]), nil
		})
	if err != nil {
		t.Fatal(err)
	}

	// Build the request body.
	body := buildSignSubtreeRequest(t, subtreeStart, subtreeEnd, subtreeHash, cpBody, proof)
	req, _ := http.NewRequest("POST", hSrv.URL+"/sign-subtree", bytes.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, body=%s", resp.StatusCode, respBody)
	}

	// The body is one signature line:
	// "— oid/<mirrorID> base64(keyID || timestamped_signature)\n".
	line := strings.TrimRight(string(respBody), "\n")
	wantPrefix := "— " + cert.OIDName(mirrorID) + " "
	if !strings.HasPrefix(line, wantPrefix) {
		t.Fatalf("response missing expected prefix: %q", line)
	}
	rawWithKeyID, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(line, wantPrefix))
	if err != nil {
		t.Fatal(err)
	}
	if len(rawWithKeyID) < 5 {
		t.Fatalf("sig too short: %d", len(rawWithKeyID))
	}
	_, rawSig, err := cert.ParseTimestampedSignature(rawWithKeyID[4:])
	if err != nil {
		t.Fatalf("parse timestamped_signature: %v", err)
	}
	// Verify the signature against CosignedMessage.
	subtree := &cert.MTCSubtree{
		LogID: ca.logID,
		Start: subtreeStart, End: subtreeEnd, Hash: subtreeHash,
	}
	msg, err := cert.MarshalSignatureInput(mirrorID, subtree)
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.VerifyMTCSignature(mKey,
		cert.MTCSignature{CosignerID: mirrorID, Signature: rawSig}, msg); err != nil {
		t.Errorf("mirror cosignature verify: %v", err)
	}
}

// TestMirrorSignSubtreeRejectsStaleCheckpoint: when the requester
// sends a checkpoint that doesn't match our verified state, return 409.
func TestMirrorSignSubtreeRejectsStaleCheckpoint(t *testing.T) {
	ca := bringUp(t, t.TempDir())
	defer ca.close()
	for i := 0; i < 3; i++ {
		_, _ = acmeIssueOne(ca.acmeBase, fmt.Sprintf("stale%d.test", i))
	}
	mfs, _ := storage.New(t.TempDir())
	follower, _ := mirror.NewFollower(mirror.FollowerConfig{
		Upstream: mirror.Upstream{
			TileURL: ca.tileBase, LogID: ca.logID,
			CACosignerID: ca.cosigner, CACosignerKey: ca.signer.PublicKey(),
		},
		FS: mfs, PollInterval: 25 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startFollower(t, ctx, follower)
	waitFollowerCatchUp(t, follower, ca.log.CurrentCheckpoint().Size, 2*time.Second)

	mSigner, _ := mldsaCosigner(t, cert.TrustAnchorID("32473.21"), 0x00)
	srv, _ := mirror.NewServer(mirror.ServerConfig{
		Follower: follower, Signer: mSigner,
		CosignerID: cert.TrustAnchorID("32473.21"),
	})
	hSrv := httptest.NewServer(srv.Handler())
	defer hSrv.Close()

	// Build a request whose reference checkpoint has the right origin but
	// the wrong size/root, so we pass the origin (404) and range (400)
	// checks but fail the stateful checkpoint comparison (409). The
	// checkpoint is a zero-signature note: body + a trailing blank line.
	bogusCP := []byte(cert.OIDName(ca.logID) + "\n9999\n" +
		base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n\n")
	body := buildSignSubtreeRequest(t, 0, 1, tlogx.Hash{}, bogusCP, nil)

	req, _ := http.NewRequest("POST", hSrv.URL, bytes.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("status = %d, want 409", resp.StatusCode)
	}
}

func sha256Hash(b []byte) tlogx.Hash {
	return tlogx.Hash(sha256Sum(b))
}

func waitFollowerCatchUp(t *testing.T, f *mirror.Follower, want uint64, dur time.Duration) uint64 {
	t.Helper()
	deadline := time.Now().Add(dur)
	for time.Now().Before(deadline) {
		got, _, _ := f.Current()
		if got == want {
			return got
		}
		time.Sleep(20 * time.Millisecond)
	}
	got, _, _ := f.Current()
	t.Fatalf("follower never caught up: have %d want %d", got, want)
	return 0
}

// TestMirrorCheckpointEndpoint: stand up a CA + a follower, advance
// the follower, then request the mirror's own checkpoint endpoint
// and verify the returned checkpoint and signatures.
func TestMirrorCheckpointEndpoint(t *testing.T) {
	ca := bringUp(t, t.TempDir())
	defer ca.close()

	for i := 0; i < 3; i++ {
		if _, err := acmeIssueOne(ca.acmeBase, fmt.Sprintf("cp%d.test", i)); err != nil {
			t.Fatal(err)
		}
	}

	mfs, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	follower, err := mirror.NewFollower(mirror.FollowerConfig{
		Upstream: mirror.Upstream{
			TileURL: ca.tileBase, LogID: ca.logID,
			CACosignerID:  ca.cosigner,
			CACosignerKey: ca.signer.PublicKey(),
		},
		FS: mfs, PollInterval: 25 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startFollower(t, ctx, follower)
	caSize := waitFollowerCatchUp(t, follower, ca.log.CurrentCheckpoint().Size, 3*time.Second)

	// Mirror's own cosigner key.
	mirrorID := cert.TrustAnchorID("32473.21")
	mSigner, mKey := mldsaCosigner(t, mirrorID, 0xCC)

	srv, err := mirror.NewServer(mirror.ServerConfig{
		Follower:                    follower,
		Signer:                      mSigner,
		CosignerID:                  mirrorID,
		RequireCASignatureOnSubtree: false,
	})
	if err != nil {
		t.Fatal(err)
	}

	origin := cert.OIDName(ca.logID)
	checkpointPath := "/" + origin + "/checkpoint"

	mux := http.NewServeMux()
	mux.Handle("GET "+checkpointPath, srv.HandlerCheckpoint())
	hSrv := httptest.NewServer(mirror.UnescapeSlashMiddleware(mux))
	defer hSrv.Close()

	// Test three path variations (standard, %2F, and %2f) to verify that the
	// UnescapeSlashMiddleware correctly normalizes percent-encoded slashes.
	pathsToTest := []string{
		checkpointPath,
		"/" + strings.ReplaceAll(checkpointPath[1:], "/", "%2F"),
		"/" + strings.ReplaceAll(checkpointPath[1:], "/", "%2f"),
	}

	var firstBody []byte
	for _, p := range pathsToTest {
		resp, err := http.Get(hSrv.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != 200 {
			t.Fatalf("path %q: status = %d, body = %s", p, resp.StatusCode, body)
		}

		if firstBody == nil {
			firstBody = body
		} else if !bytes.Equal(firstBody, body) {
			t.Errorf("path %q returned different body from first path", p)
		}
	}

	// The checkpoint must be a signed note. Let's parse it and verify
	// the signatures.
	// The body should contain the CA's signature and the mirror's signature.
	size, root, sigs, err := testParseSignedNote(firstBody)
	if err != nil {
		t.Fatalf("testParseSignedNote failed: %v", err)
	}
	if size != caSize {
		t.Errorf("got size %d, want %d", size, caSize)
	}

	// Expect exactly 2 signatures: one from CA, one from the mirror.
	if len(sigs) != 2 {
		t.Fatalf("got %d signatures, want 2", len(sigs))
	}

	// Verify both signatures.
	caKey := cert.CosignerKey{
		ID: ca.cosigner, Algorithm: cert.AlgMLDSA44, PublicKey: ca.signer.PublicKey(),
	}
	mirrorKey := cert.CosignerKey{
		ID: mirrorID, Algorithm: cert.AlgMLDSA44, PublicKey: mKey.PublicKey,
	}

	// The signed message is the CosignedMessage for [0, size)
	subtree := &cert.MTCSubtree{
		LogID: ca.logID,
		Start: 0, End: size, Hash: root,
	}
	msg, err := cert.MarshalSignatureInput(ca.cosigner, subtree)
	if err != nil {
		t.Fatal(err)
	}
	mirrorMsg, err := cert.MarshalSignatureInput(mirrorID, subtree)
	if err != nil {
		t.Fatal(err)
	}

	var verifiedCA, verifiedMirror bool
	for _, s := range sigs {
		if s.keyName == cert.OIDName(ca.cosigner) {
			sig := cert.MTCSignature{CosignerID: ca.cosigner, Signature: s.sig}
			if err := cert.VerifyMTCSignature(caKey, sig, msg); err != nil {
				t.Errorf("CA signature verification failed: %v", err)
			} else {
				verifiedCA = true
			}
		} else if s.keyName == cert.OIDName(mirrorID) {
			sig := cert.MTCSignature{CosignerID: mirrorID, Signature: s.sig}
			if err := cert.VerifyMTCSignature(mirrorKey, sig, mirrorMsg); err != nil {
				t.Errorf("mirror signature verification failed: %v", err)
			} else {
				verifiedMirror = true
			}
		} else {
			t.Errorf("unexpected signature key name %q", s.keyName)
		}
	}

	if !verifiedCA {
		t.Error("CA signature not found or not verified")
	}
	if !verifiedMirror {
		t.Error("mirror signature not found or not verified")
	}
}

type testNoteSig struct {
	keyName string
	sig     []byte
}

func testParseSignedNote(data []byte) (uint64, tlogx.Hash, []testNoteSig, error) {
	parts := strings.SplitN(string(data), "\n\n", 2)
	if len(parts) < 2 {
		return 0, tlogx.Hash{}, nil, fmt.Errorf("missing separator")
	}
	bodyLines := strings.Split(strings.TrimRight(parts[0], "\n"), "\n")
	if len(bodyLines) != 3 {
		return 0, tlogx.Hash{}, nil, fmt.Errorf("bad body lines: %d", len(bodyLines))
	}
	size, err := strconv.ParseUint(bodyLines[1], 10, 64)
	if err != nil {
		return 0, tlogx.Hash{}, nil, err
	}
	rootBytes, err := base64.StdEncoding.DecodeString(bodyLines[2])
	if err != nil {
		return 0, tlogx.Hash{}, nil, err
	}
	var root tlogx.Hash
	copy(root[:], rootBytes)

	var sigs []testNoteSig
	for _, line := range strings.Split(strings.TrimRight(parts[1], "\n"), "\n") {
		if line == "" {
			continue
		}
		rest, ok := strings.CutPrefix(line, "— ")
		if !ok {
			return 0, tlogx.Hash{}, nil, fmt.Errorf("bad sig line: %q", line)
		}
		fields := strings.SplitN(rest, " ", 2)
		if len(fields) != 2 {
			return 0, tlogx.Hash{}, nil, fmt.Errorf("bad sig format: %q", line)
		}
		raw, err := base64.StdEncoding.DecodeString(fields[1])
		if err != nil {
			return 0, tlogx.Hash{}, nil, err
		}
		if len(raw) < 5 {
			return 0, tlogx.Hash{}, nil, fmt.Errorf("sig too short")
		}
		_, sig, err := cert.ParseTimestampedSignature(raw[4:])
		if err != nil {
			return 0, tlogx.Hash{}, nil, err
		}
		sigs = append(sigs, testNoteSig{
			keyName: fields[0],
			sig:     sig,
		})
	}
	return size, root, sigs, nil
}

// TestMirrorConfigEndpoint verifies that the /config endpoint correctly
// returns the mirror's public key (PEM and raw) and the list of upstream logs.
func TestMirrorConfigEndpoint(t *testing.T) {
	mfs, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	upstreamTileURL := "http://127.0.0.1:14080/1"
	upstreamLogID := cert.TrustAnchorID("44363.47.1.99.0.1")
	upstreamCACosignerID := cert.TrustAnchorID("44363.47.1.99")

	// CA cosigner key doesn't need to be real for config test, just non-empty
	caKey := []byte("fake-ca-key-fake-ca-key-fake-ca-key-fake-ca-key")

	follower, err := mirror.NewFollower(mirror.FollowerConfig{
		Upstream: mirror.Upstream{
			TileURL:       upstreamTileURL,
			LogID:         upstreamLogID,
			CACosignerID:  upstreamCACosignerID,
			CACosignerKey: caKey,
		},
		FS:           mfs,
		PollInterval: 25 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	mirrorID := cert.TrustAnchorID("32473.21")
	mSigner, _ := mldsaCosigner(t, mirrorID, 0xCC)

	srv, err := mirror.NewServer(mirror.ServerConfig{
		Follower:   follower,
		Signer:     mSigner,
		CosignerID: mirrorID,
	})
	if err != nil {
		t.Fatal(err)
	}

	hSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/config" {
			srv.HandlerConfig().ServeHTTP(w, r)
			return
		}
		if r.URL.Path == "/" {
			srv.HandlerIndex().ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	}))
	defer hSrv.Close()

	// Test GET /
	dashboardResp, err := http.Get(hSrv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer dashboardResp.Body.Close()

	if dashboardResp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200 for dashboard, got %d", dashboardResp.StatusCode)
	}
	dashboardCT := dashboardResp.Header.Get("Content-Type")
	if !strings.Contains(dashboardCT, "text/html") {
		t.Errorf("expected text/html for dashboard, got %q", dashboardCT)
	}
	dashboardBody, err := io.ReadAll(dashboardResp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(dashboardBody), "cactus mirror") {
		t.Errorf("expected dashboard body to contain title, got: %s", string(dashboardBody))
	}

	// Test GET /config
	resp, err := http.Get(hSrv.URL + "/config")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	var jsonResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&jsonResp); err != nil {
		t.Fatal(err)
	}

	// Verify public key is returned
	pubPEM, ok := jsonResp["public_key_pem"].(string)
	if !ok || !strings.Contains(pubPEM, "-----BEGIN PUBLIC KEY-----") {
		t.Errorf("missing or invalid public_key_pem in response: %v", jsonResp["public_key_pem"])
	}

	pubBytesBase64, ok := jsonResp["public_key"].(string)
	if !ok || len(pubBytesBase64) == 0 {
		t.Errorf("missing or invalid public_key in response: %v", jsonResp["public_key"])
	}

	// Verify cosigner_id and algorithm are returned
	cosignerID, ok := jsonResp["cosigner_id"].(string)
	if !ok || cosignerID != string(mirrorID) {
		t.Errorf("expected cosigner_id %q, got %v", mirrorID, jsonResp["cosigner_id"])
	}

	alg, ok := jsonResp["algorithm"].(string)
	if !ok || alg != "mldsa-44" {
		t.Errorf("expected algorithm %q, got %v", "mldsa-44", jsonResp["algorithm"])
	}


	// Verify upstreams list
	upstreams, ok := jsonResp["upstreams"].([]interface{})
	if !ok || len(upstreams) != 1 {
		t.Fatalf("expected 1 upstream log, got %d in response: %v", len(upstreams), jsonResp["upstreams"])
	}

	u := upstreams[0].(map[string]interface{})
	if u["tile_url"] != upstreamTileURL {
		t.Errorf("expected tile_url %q, got %q", upstreamTileURL, u["tile_url"])
	}
	if u["log_id"] != string(upstreamLogID) {
		t.Errorf("expected log_id %q, got %q", upstreamLogID, u["log_id"])
	}
	if u["ca_cosigner_id"] != string(upstreamCACosignerID) {
		t.Errorf("expected ca_cosigner_id %q, got %q", upstreamCACosignerID, u["ca_cosigner_id"])
	}
}
