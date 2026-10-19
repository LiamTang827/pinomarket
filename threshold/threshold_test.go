package threshold

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

func fixture(t *testing.T) (PublicConfig, []SecretShare, Ciphertext, []DecryptionShare, []byte) {
	t.Helper()
	config, secrets, err := RunLocalDKG(401, 4, 3)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("32-byte symmetric session key!!!!")
	ct, err := Encrypt(config, []byte("round=7;input=alice;payload-hash=123"), plaintext)
	if err != nil {
		t.Fatal(err)
	}
	shares := make([]DecryptionShare, len(secrets))
	for i, secret := range secrets {
		shares[i], err = CreateDecryptionShare(config, secret, ct)
		if err != nil {
			t.Fatal(err)
		}
	}
	return config, secrets, ct, shares, plaintext
}

func clone[T any](t *testing.T, value T) T {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var copy T
	if err := json.Unmarshal(b, &copy); err != nil {
		t.Fatal(err)
	}
	return copy
}

func TestThresholdAllSubsetsAndWireRoundTrip(t *testing.T) {
	config, _, ct, shares, plaintext := fixture(t)
	config, ct, shares = clone(t, config), clone(t, ct), clone(t, shares)
	for excluded := range shares {
		var subset []DecryptionShare
		for i, share := range shares {
			if i != excluded {
				subset = append(subset, share)
			}
		}
		actual, err := Decrypt(config, ct, subset)
		if err != nil || !bytes.Equal(actual, plaintext) {
			t.Fatalf("exclude %d: plaintext=%q error=%v", excluded, actual, err)
		}
	}
	if _, err := Decrypt(config, ct, shares[:2]); !errors.Is(err, ErrInsufficientShares) {
		t.Fatalf("t-1 shares must fail, got %v", err)
	}
	if _, err := Decrypt(config, ct, shares); err != nil {
		t.Fatalf("more than threshold distinct valid shares must work: %v", err)
	}
}

func TestInvalidSharesAreRejectedBeforeCombination(t *testing.T) {
	config, _, ct, shares, _ := fixture(t)
	bad := clone(t, shares)
	bad[0].Value = bytes.Clone(bad[1].Value) // Valid curve point, wrong party.
	if err := VerifyDecryptionShare(config, ct, bad[0]); !errors.Is(err, ErrInvalidShare) {
		t.Fatalf("wrong-party point accepted: %v", err)
	}
	if _, err := Decrypt(config, ct, bad); !errors.Is(err, ErrInvalidShare) {
		t.Fatalf("invalid extra must not be silently discarded: %v", err)
	}
	if _, err := Decrypt(config, ct, []DecryptionShare{shares[0], shares[0], shares[1]}); !errors.Is(err, ErrInvalidShare) {
		t.Fatalf("duplicate participant counted toward threshold: %v", err)
	}
	bad[0].Index = -1
	if err := VerifyDecryptionShare(config, ct, bad[0]); err == nil {
		t.Fatal("negative share index accepted")
	}
	bad[0] = clone(t, shares[0])
	bad[0].Value = make([]byte, 48)
	if err := VerifyDecryptionShare(config, ct, bad[0]); err == nil {
		t.Fatal("malformed compressed point accepted")
	}
}

func TestIdentityAndCiphertextBinding(t *testing.T) {
	config, secrets, ct, shares, plaintext := fixture(t)
	other, err := Encrypt(config, ct.Label, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(other.Nonce, ct.Nonce) || bytes.Equal(other.Body, ct.Body) || other.ID() == ct.ID() {
		t.Fatal("repeated encryption reused randomness")
	}
	if err := VerifyDecryptionShare(config, other, shares[0]); err == nil {
		t.Fatal("old share accepted for a second encryption")
	}
	// Updating the public envelope cannot rebind the pairing proof to another
	// randomly chosen identity.
	rebound := clone(t, shares[0])
	rebound.CiphertextID = other.ID()
	if err := VerifyDecryptionShare(config, other, rebound); !errors.Is(err, ErrInvalidShare) {
		t.Fatalf("pairing failed to bind identity: %v", err)
	}
	for _, name := range []string{"label", "nonce"} {
		changed := clone(t, ct)
		if name == "label" {
			changed.Label = append(changed.Label, 'x')
		} else {
			changed.Nonce[0] ^= 1
		}
		rebound.CiphertextID = changed.ID()
		if err := VerifyDecryptionShare(config, changed, rebound); !errors.Is(err, ErrInvalidShare) {
			t.Fatalf("%s change did not invalidate pairing: %v", name, err)
		}
	}
	changed := clone(t, ct)
	changed.Body[len(changed.Body)-1] ^= 1
	if err := VerifyDecryptionShare(config, changed, shares[0]); !errors.Is(err, ErrContextMismatch) {
		t.Fatalf("changed ciphertext accepted under original envelope: %v", err)
	}
	// The library authenticates ciphertext bytes even if an adversary rewrites
	// the unsigned digest metadata. The pairing proof authenticates the identity.
	reboundShares := clone(t, shares[:3])
	for i := range reboundShares {
		reboundShares[i].CiphertextID = changed.ID()
	}
	if _, err := Decrypt(config, changed, reboundShares); err == nil {
		t.Fatal("tampered ciphertext passed the library integrity check")
	}
	wrongSecret := secrets[0]
	wrongSecret.Index = 1
	if _, err := CreateDecryptionShare(config, wrongSecret, ct); err == nil {
		t.Fatal("secret scalar accepted for a different party")
	}
}

func TestMalformedConfigurationAndCiphertext(t *testing.T) {
	config, _, ct, shares, _ := fixture(t)
	badConfig := clone(t, config)
	badConfig.Threshold--
	if _, err := Decrypt(badConfig, ct, shares); err == nil {
		t.Fatal("modified config accepted")
	}
	for _, size := range []int{0, 1, 32, 128, len(ct.Body) - 1} {
		bad := clone(t, ct)
		bad.Body = bad.Body[:size]
		if err := ValidateCiphertext(config, bad); err == nil {
			t.Fatalf("truncated ciphertext size %d accepted", size)
		}
	}
	bad := clone(t, ct)
	copy(bad.Body[1:97], make([]byte, 96))
	if err := ValidateCiphertext(config, bad); err == nil {
		t.Fatal("invalid C1 curve point accepted")
	}
	if _, _, err := RunLocalDKG(1, 3, 4); err == nil {
		t.Fatal("threshold greater than n accepted")
	}
}

func TestOneOfOneEmptyPlaintext(t *testing.T) {
	config, secrets, err := RunLocalDKG(1, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := Encrypt(config, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	share, err := CreateDecryptionShare(config, secrets[0], ct)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := Decrypt(config, ct, []DecryptionShare{share})
	if err != nil || len(plaintext) != 0 {
		t.Fatalf("empty plaintext round trip: %q, %v", plaintext, err)
	}
}
