package main

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/letsencrypt/cactus/signer"
)

func main() {
	configPath := "config.json"
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		log.Fatalf("Failed to read config: %v", err)
	}

	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Fatalf("Failed to parse config: %v", err)
	}

	dataDir, _ := cfg["data_dir"].(string)
	if dataDir == "" {
		dataDir = "/var/lib/cactus"
	}

	// Get CA public key and write PEM file relative to dataDir.
	caCosigner, _ := cfg["ca_cosigner"].(map[string]interface{})
	caSeedPath, _ := caCosigner["seed_path"].(string)
	caAlg, _ := caCosigner["algorithm"].(string)

	caPEMRel := writePEM(dataDir, caSeedPath, caAlg)
	fmt.Printf("Wrote CA public key: %s\n", filepath.Join(dataDir, caPEMRel))

	// Get Mirror public key and write PEM file relative to dataDir.
	mirror, _ := cfg["mirror"].(map[string]interface{})
	mirrorSeedPath, _ := mirror["seed_path"].(string)
	mirrorAlg, _ := mirror["algorithm"].(string)

	mirrorPEMRel := writePEM(dataDir, mirrorSeedPath, mirrorAlg)
	fmt.Printf("Wrote mirror public key: %s\n", filepath.Join(dataDir, mirrorPEMRel))

	// Update config
	// 1. mirror.upstream.ca_cosigner_key_path
	upstream, _ := mirror["upstream"].(map[string]interface{})
	upstream["ca_cosigner_key_path"] = caPEMRel

	// 2. ca_cosigner_quorum.mirrors[0].public_key_path
	caQuorum, _ := cfg["ca_cosigner_quorum"].(map[string]interface{})
	mirrors, _ := caQuorum["mirrors"].([]interface{})
	if len(mirrors) > 0 {
		m0, _ := mirrors[0].(map[string]interface{})
		m0["public_key_path"] = mirrorPEMRel
	}

	// Write back
	updatedData, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal config: %v", err)
	}

	if err := os.WriteFile(configPath, updatedData, 0644); err != nil {
		log.Fatalf("Failed to write config: %v", err)
	}

	fmt.Println("Updated config.json successfully.")
}

// writePEM derives the public key from seedPath (relative to dataDir), writes
// it to a .pem file alongside the seed, and returns the relative path of the
// PEM file so it can be stored in config fields like ca_cosigner_key_path.
func writePEM(dataDir, seedPath, algStr string) string {
	fullSeedPath := filepath.Join(dataDir, seedPath)
	seed, err := os.ReadFile(fullSeedPath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("Seed file %q does not exist. Generating...\n", fullSeedPath)
			if err := os.MkdirAll(filepath.Dir(fullSeedPath), 0755); err != nil {
				log.Fatalf("Failed to create directory for %q: %v", fullSeedPath, err)
			}
			if err := signer.WriteSeed(fullSeedPath); err != nil {
				log.Fatalf("Failed to write seed: %v", err)
			}
			seed, err = os.ReadFile(fullSeedPath)
			if err != nil {
				log.Fatalf("Failed to read generated seed: %v", err)
			}
		} else {
			log.Fatalf("Failed to read seed file %q: %v", fullSeedPath, err)
		}
	}

	alg, err := signer.ParseAlgorithm(algStr)
	if err != nil {
		log.Fatalf("Failed to parse algorithm: %v", err)
	}

	sgn, err := signer.FromSeed(alg, seed)
	if err != nil {
		log.Fatalf("Failed to create signer: %v", err)
	}

	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: sgn.PublicKey(),
	})

	pemRel := strings.TrimSuffix(seedPath, filepath.Ext(seedPath)) + ".pem"
	fullPEMPath := filepath.Join(dataDir, pemRel)
	if err := os.MkdirAll(filepath.Dir(fullPEMPath), 0755); err != nil {
		log.Fatalf("Failed to create directory for %q: %v", fullPEMPath, err)
	}
	if err := os.WriteFile(fullPEMPath, pubPEM, 0644); err != nil {
		log.Fatalf("Failed to write public key PEM %q: %v", fullPEMPath, err)
	}
	return pemRel
}
