package main

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"

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

	// Get CA public key
	caCosigner, _ := cfg["ca_cosigner"].(map[string]interface{})
	caSeedPath, _ := caCosigner["seed_path"].(string)
	caAlg, _ := caCosigner["algorithm"].(string)
	
	caPEM := getPEM(dataDir, caSeedPath, caAlg)
	fmt.Printf("CA Public Key PEM:\n%s\n", caPEM)

	// Get Mirror public key
	mirror, _ := cfg["mirror"].(map[string]interface{})
	mirrorSeedPath, _ := mirror["seed_path"].(string)
	mirrorAlg, _ := mirror["algorithm"].(string)
	
	mirrorPEM := getPEM(dataDir, mirrorSeedPath, mirrorAlg)
	fmt.Printf("Mirror Public Key PEM:\n%s\n", mirrorPEM)

	// Update config
	// 1. mirror.upstream.ca_cosigner_key_pem
	upstream, _ := mirror["upstream"].(map[string]interface{})
	upstream["ca_cosigner_key_pem"] = caPEM

	// 2. ca_cosigner_quorum.mirrors[0].public_key_pem
	caQuorum, _ := cfg["ca_cosigner_quorum"].(map[string]interface{})
	mirrors, _ := caQuorum["mirrors"].([]interface{})
	if len(mirrors) > 0 {
		m0, _ := mirrors[0].(map[string]interface{})
		m0["public_key_pem"] = mirrorPEM
	}

	// Write back
	updatedData, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal config: %v", err)
	}

	err = os.WriteFile(configPath, updatedData, 0644)
	if err != nil {
		log.Fatalf("Failed to write config: %v", err)
	}

	fmt.Println("Updated config.json successfully.")
}

func getPEM(dataDir, seedPath, algStr string) string {
	fullPath := filepath.Join(dataDir, seedPath)
	seed, err := os.ReadFile(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("Seed file %q does not exist. Generating...\n", fullPath)
			dir := filepath.Dir(fullPath)
			if err := os.MkdirAll(dir, 0755); err != nil {
				log.Fatalf("Failed to create directory %q: %v", dir, err)
			}
			if err := signer.WriteSeed(fullPath); err != nil {
				log.Fatalf("Failed to write seed: %v", err)
			}
			// Read it back
			seed, err = os.ReadFile(fullPath)
			if err != nil {
				log.Fatalf("Failed to read generated seed: %v", err)
			}
		} else {
			log.Fatalf("Failed to read seed file %q: %v", fullPath, err)
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
	return string(pubPEM)
}
