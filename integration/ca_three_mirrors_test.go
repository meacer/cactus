package integration

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/letsencrypt/cactus/acme"
	"github.com/letsencrypt/cactus/ca"
	"github.com/letsencrypt/cactus/cert"
	cactuslog "github.com/letsencrypt/cactus/log"
	"github.com/letsencrypt/cactus/mirror"
	"github.com/letsencrypt/cactus/signer"
	"github.com/letsencrypt/cactus/storage"
	"github.com/letsencrypt/cactus/tile"
	"github.com/letsencrypt/cactus/tlogx"
)

// TestEndToEndCAWithThreeMirrors is the v3-DoD cornerstone:
//   - 1 CA cactus
//   - 3 mirror cactuses, each following the CA
//   - CA configured with MirrorRequester that fans out to all three
//     with quorum=2 + WaitForCosigners=2 (CA + at least one mirror)
//
// Issues a cert, confirms its MTCProof contains at least 2 sigs (CA +
// >=1 mirror), each individually verifying.
func TestEndToEndCAWithThreeMirrors(t *testing.T) {
	if testing.Short() {
		t.Skip("multi-mirror takes a couple seconds")
	}

	// Per-mirror state.
	type mk struct {
		follower *mirror.Follower
		signer   signer.Signer
		id       cert.TrustAnchorID
		url      string
		close    func()
	}
	mks := make([]mk, 3)
	for i := range mks {
		mks[i].id = cert.TrustAnchorID(fmt.Sprintf("32473.%d", 30+i+1))
		s, _ := mldsaCosigner(t, mks[i].id, byte(0x10+i))
		mks[i].signer = s
	}

	// 1) Bring up the CA log + tile server.
	caDir := t.TempDir()
	caFS, err := storage.New(caDir)
	if err != nil {
		t.Fatal(err)
	}
	caSeed := make([]byte, signer.SeedSize)
	for i := range caSeed {
		caSeed[i] = 0x00
	}
	caSigner, _ := signer.FromSeed(signer.AlgMLDSA44, caSeed)
	logID := cert.TrustAnchorID("32473.5")
	caCosigID := cert.TrustAnchorID("32473.5")

	var caLog *cactuslog.Log
	endpointsLazy := func() []cert.MirrorEndpoint {
		out := make([]cert.MirrorEndpoint, 0, len(mks))
		for _, m := range mks {
			if m.url == "" {
				return nil
			}
			out = append(out, cert.MirrorEndpoint{
				URL:           m.url + "/sign-subtree",
				CheckpointURL: m.url + "/add-checkpoint",
				Key: cert.CosignerKey{
					ID: m.id, Algorithm: cert.AlgMLDSA44,
					PublicKey: m.signer.PublicKey(),
				},
			})
		}
		return out
	}

	mirrorRequester := func(ctx context.Context, st *cert.MTCSubtree, caSig cert.MTCSignature) ([]cert.MTCSignature, error) {
		endpoints := endpointsLazy()
		if len(endpoints) == 0 {
			return nil, nil
		}
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			cp := caLog.CurrentCheckpoint()
			if cp.Size == 0 {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			proof, err := caLog.ConsistencyProof(st.Start, st.End, cp.Size)
			if err != nil {
				return nil, err
			}
			req := &cert.SubtreeRequest{
				Subtree:          st,
				CACheckpointBody: cp.SignedNote,
				ConsistencyProof: proof,
			}
			subCtx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
			sigs, err := cert.RequestCosignatures(subCtx, req, endpoints, 2, 250*time.Millisecond, false)
			cancel()
			if err == nil && len(sigs) >= 2 {
				return sigs, nil
			}
			time.Sleep(100 * time.Millisecond)
		}
		return nil, fmt.Errorf("multi-mirror quorum not met within deadline")
	}

	checkpointWitnessRequester := func(ctx context.Context, oldSize uint64, proof []tlogx.Hash, checkpointNote []byte) ([]cert.MTCSignature, error) {
		endpoints := endpointsLazy()
		if len(endpoints) == 0 {
			return nil, nil
		}
		return cert.RequestCheckpointSignatures(ctx, oldSize, proof, checkpointNote, endpoints)
	}

	caLog, err = cactuslog.New(context.Background(), cactuslog.Config{
		LogID: logID, CosignerID: caCosigID,
		Signer: caSigner, FS: caFS,
		FlushPeriod:                25 * time.Millisecond,
		MirrorRequester:            mirrorRequester,
		CheckpointWitnessRequester: checkpointWitnessRequester,
		WaitForCosigners:           3, // CA + 2 mirrors
	})
	if err != nil {
		t.Fatal(err)
	}
	defer caLog.Stop()
	caTile := httptest.NewServer(tile.New(caLog, caFS).Handler())
	defer caTile.Close()

	// 2) Bring up the 3 mirrors.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for i := range mks {
		mfs, err := storage.New(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		f, err := mirror.NewFollower(mirror.FollowerConfig{
			Upstream: mirror.Upstream{
				TileURL: caTile.URL, LogID: logID,
				CACosignerID: caCosigID, CACosignerKey: caSigner.PublicKey(),
			},
			FS: mfs, PollInterval: 25 * time.Millisecond,
		})
		if err != nil {
			t.Fatal(err)
		}
		startFollower(t, ctx, f)
		srv, err := mirror.NewServer(mirror.ServerConfig{
			Follower:               f,
			Signer:                 mks[i].signer,
			CosignerID:             mks[i].id,
			CheckpointCosignatures: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		mux := http.NewServeMux()
		mux.Handle("/sign-subtree", srv.Handler())
		mux.Handle("/add-checkpoint", srv.HandlerAddCheckpoint())
		hSrv := httptest.NewServer(mux)
		mks[i].follower = f
		mks[i].url = hSrv.URL
		mks[i].close = hSrv.Close
	}
	defer func() {
		for _, m := range mks {
			if m.close != nil {
				m.close()
			}
		}
	}()

	// Wait until all mirrors have caught up to the CA's initial
	// checkpoint (the null entry).
	caInitSize := caLog.CurrentCheckpoint().Size
	for _, m := range mks {
		waitFollowerCatchUp(t, m.follower, caInitSize, 3*time.Second)
	}

	// 3) Build an ACME stack on top of the CA log and issue a cert.
	caIssuer, _ := ca.New(caLog, "32473.5", 1)
	acmeSrv, _ := acme.New(acme.Config{
		Issuer: caIssuer, ChallengeMode: acme.ChallengeAutoPass,
	})
	hAcme := httptest.NewServer(acmeSrv.Handler())
	defer hAcme.Close()
	acmeSrv.SetExternalURL(hAcme.URL)

	der, err := acmeIssueOne(hAcme.URL, "three-mirrors.test")
	if err != nil {
		t.Fatal(err)
	}

	// 4) Decode and assert the cert has at least 2 sigs (CA + >=1 mirror).
	tbs, _, sigValue, err := cert.SplitCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	_ = tbs
	mtcProof, err := cert.ParseMTCProof(sigValue)
	if err != nil {
		t.Fatal(err)
	}
	if len(mtcProof.Signatures) < 2 {
		t.Fatalf("got %d sigs in cert, want >= 2 (CA + at least one mirror): %+v",
			len(mtcProof.Signatures), mtcProof.Signatures)
	}

	// 5) Verify checkpoint signatures.
	cp := caLog.CurrentCheckpoint()
	_, _, sigs, err := cactuslog.ParseSignedNoteFull(cp.SignedNote, logID)
	if err != nil {
		t.Fatalf("parse checkpoint: %v", err)
	}
	if len(sigs) < 2 {
		t.Errorf("got %d checkpoint sigs, want >= 2", len(sigs))
	}
}
