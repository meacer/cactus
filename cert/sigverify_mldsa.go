//go:build mldsa

package cert

import (
	"fmt"

	"filippo.io/mldsa"
)

func init() {
	registerVerifier(AlgMLDSA44, verifyMLDSA44)
	registerVerifier(AlgMLDSA65, verifyMLDSA65)
}

func verifyMLDSA44(key CosignerKey, sig MTCSignature, msg []byte) error {
	pub, err := mldsa.NewPublicKey(mldsa.MLDSA44(), key.PublicKey)
	if err != nil {
		return fmt.Errorf("cert: mldsa44: parse public key: %w", err)
	}
	if err := mldsa.Verify(pub, msg, sig.Signature, nil); err != nil {
		return fmt.Errorf("cert: mldsa44: %w", err)
	}
	return nil
}

func verifyMLDSA65(key CosignerKey, sig MTCSignature, msg []byte) error {
	pub, err := mldsa.NewPublicKey(mldsa.MLDSA65(), key.PublicKey)
	if err != nil {
		return fmt.Errorf("cert: mldsa65: parse public key: %w", err)
	}
	if err := mldsa.Verify(pub, msg, sig.Signature, nil); err != nil {
		return fmt.Errorf("cert: mldsa65: %w", err)
	}
	return nil
}
