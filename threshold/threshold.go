// Package threshold adapts Shutter's BLS12-381 identity based threshold
// encryption. DKG uses shlib/puredkg; encryption, pairing verification and
// interpolation use shlib/shcrypto. This adapter has not been audited.
package threshold

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"

	"github.com/shutter-network/shutter/shlib/shcrypto"
	blst "github.com/supranational/blst/bindings/go"
)

const Version = "pinocchio-shutter-bls12381-v1"

var (
	ErrInsufficientShares = errors.New("insufficient distinct decryption shares")
	ErrInvalidShare       = errors.New("invalid decryption share")
	ErrContextMismatch    = errors.New("threshold context mismatch")
)

// PublicConfig is the common public output of a successful DKG ceremony.
// Applications must agree on this complete configuration before using it.
type PublicConfig struct {
	Version          string   `json:"version"`
	Eon              uint64   `json:"eon"`
	N                int      `json:"n"`
	Threshold        int      `json:"threshold"`
	PublicKey        []byte   `json:"public_key"`
	VerificationKeys [][]byte `json:"verification_keys"`
	ID               string   `json:"id"`
}

// SecretShare is one participant's private DKG output. It must be stored only
// by that participant, with the same protection as any other private key.
// Neither a full secret key nor another participant's share is needed to use it.
type SecretShare struct {
	ConfigID string `json:"config_id"`
	Index    int    `json:"index"`
	Value    []byte `json:"value"`
}

// Ciphertext includes a random identity nonce so that releasing a key for one
// ciphertext does not release keys for other encryptions with the same label.
// The IBE identity commits to Version, ConfigID, Label and Nonce. Body is the
// established library's ciphertext, with its integrity check intact.
type Ciphertext struct {
	Version  string `json:"version"`
	ConfigID string `json:"config_id"`
	Label    []byte `json:"label"`
	Nonce    []byte `json:"nonce"`
	Body     []byte `json:"body"`
}

// DecryptionShare contains the epoch key share. Its correctness is publicly
// checked by a BLS pairing against the participant's verification key and the
// ciphertext identity. The envelope names the complete ciphertext digest.
// Applications authenticate the sender and release authorization separately.
type DecryptionShare struct {
	ConfigID     string `json:"config_id"`
	CiphertextID string `json:"ciphertext_id"`
	Index        int    `json:"index"`
	Value        []byte `json:"value"`
}

func parameters(n, threshold int) error {
	if n < 1 || n > 1024 || threshold < 1 || threshold > n {
		return fmt.Errorf("invalid threshold parameters: n=%d threshold=%d (require 1 <= threshold <= n <= 1024)", n, threshold)
	}
	return nil
}

func field(h hash.Hash, value []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	h.Write(length[:])
	h.Write(value)
}

func number(h hash.Hash, value uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], value)
	field(h, b[:])
}

func (c PublicConfig) computedID() string {
	h := sha256.New()
	field(h, []byte("pinocchio/threshold/config/v1"))
	field(h, []byte(c.Version))
	number(h, c.Eon)
	number(h, uint64(c.N))
	number(h, uint64(c.Threshold))
	field(h, c.PublicKey)
	for _, key := range c.VerificationKeys {
		field(h, key)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func p2(encoded []byte) (*blst.P2Affine, error) {
	if len(encoded) != blst.BLST_P2_COMPRESS_BYTES {
		return nil, errors.New("invalid compressed G2 length")
	}
	p := new(blst.P2Affine).Uncompress(encoded)
	if p == nil || !p.KeyValidate() || !bytes.Equal(encoded, p.Compress()) {
		return nil, errors.New("invalid, noncanonical or zero G2 point")
	}
	return p, nil
}

func p1(encoded []byte) (*blst.P1Affine, error) {
	if len(encoded) != blst.BLST_P1_COMPRESS_BYTES {
		return nil, errors.New("invalid compressed G1 length")
	}
	p := new(blst.P1Affine).Uncompress(encoded)
	if p == nil || !p.SigValidate(true) || !bytes.Equal(encoded, p.Compress()) {
		return nil, errors.New("invalid, noncanonical or zero G1 point")
	}
	return p, nil
}

// Validate rejects malformed points and accidental or adversarial modification
// of the agreed configuration. The ID is a digest, not a certificate that the
// caller ran DKG; that assurance comes from the authenticated ceremony.
func (c PublicConfig) Validate() error {
	if err := parameters(c.N, c.Threshold); err != nil {
		return err
	}
	if c.Version != Version || len(c.VerificationKeys) != c.N {
		return errors.New("invalid threshold configuration version or key count")
	}
	if c.ID != c.computedID() {
		return fmt.Errorf("%w: configuration digest", ErrContextMismatch)
	}
	if _, err := p2(c.PublicKey); err != nil {
		return fmt.Errorf("public key: %w", err)
	}
	for i, key := range c.VerificationKeys {
		if _, err := p2(key); err != nil {
			return fmt.Errorf("verification key %d: %w", i, err)
		}
	}
	return nil
}

// ID hashes all serialized ciphertext fields using length framing.
func (c Ciphertext) ID() string {
	h := sha256.New()
	field(h, []byte("pinocchio/threshold/ciphertext/v1"))
	field(h, []byte(c.Version))
	field(h, []byte(c.ConfigID))
	field(h, c.Label)
	field(h, c.Nonce)
	field(h, c.Body)
	return hex.EncodeToString(h.Sum(nil))
}

func (c Ciphertext) identity() []byte {
	h := sha256.New()
	field(h, []byte("pinocchio/threshold/identity/v1"))
	field(h, []byte(c.Version))
	field(h, []byte(c.ConfigID))
	field(h, c.Label)
	field(h, c.Nonce)
	return h.Sum(nil)
}

func validateCiphertext(config PublicConfig, ct Ciphertext) (*shcrypto.EncryptedMessage, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if ct.Version != Version || ct.ConfigID != config.ID || len(ct.Nonce) != 32 {
		return nil, fmt.Errorf("%w: ciphertext", ErrContextMismatch)
	}
	// Require at least one padded plaintext block. Validate C1 directly because
	// this shlib version's Unmarshal ignores the return value of Uncompress.
	if len(ct.Body) < 1+blst.BLST_P2_COMPRESS_BYTES+2*shcrypto.BlockSize {
		return nil, errors.New("truncated threshold ciphertext")
	}
	if _, err := p2(ct.Body[1 : 1+blst.BLST_P2_COMPRESS_BYTES]); err != nil {
		return nil, fmt.Errorf("ciphertext C1: %w", err)
	}
	msg := new(shcrypto.EncryptedMessage)
	if err := msg.Unmarshal(ct.Body); err != nil {
		return nil, fmt.Errorf("decode threshold ciphertext: %w", err)
	}
	if !bytes.Equal(msg.Marshal(), ct.Body) {
		return nil, errors.New("noncanonical threshold ciphertext")
	}
	return msg, nil
}

// ValidateCiphertext checks the configuration, envelope, canonical encoding,
// and C1 curve/subgroup membership. It cannot establish plaintext integrity or
// successful decryptability until threshold shares are combined.
func ValidateCiphertext(config PublicConfig, ct Ciphertext) error {
	_, err := validateCiphertext(config, ct)
	return err
}

// Encrypt encrypts plaintext to a fresh identity under the DKG public key.
// Callers normally encrypt a random symmetric session key here and use an
// authenticated symmetric cipher for the bulk payload.
func Encrypt(config PublicConfig, label, plaintext []byte) (Ciphertext, error) {
	if err := config.Validate(); err != nil {
		return Ciphertext{}, err
	}
	ct := Ciphertext{Version: Version, ConfigID: config.ID, Label: bytes.Clone(label), Nonce: make([]byte, 32)}
	if _, err := io.ReadFull(rand.Reader, ct.Nonce); err != nil {
		return Ciphertext{}, err
	}
	key, err := p2(config.PublicKey)
	if err != nil {
		return Ciphertext{}, err
	}
	sigma, err := shcrypto.RandomSigma(rand.Reader)
	if err != nil {
		return Ciphertext{}, err
	}
	// Shutter's padding appends to its argument; copy to avoid modifying the
	// caller's buffer when it has spare capacity.
	ct.Body = shcrypto.Encrypt(bytes.Clone(plaintext), (*shcrypto.EonPublicKey)(key), shcrypto.ComputeEpochID(ct.identity()), sigma).Marshal()
	return ct, nil
}

// CreateDecryptionShare derives one party's identity key share after the
// application authorizes release. No share from another party is used.
func CreateDecryptionShare(config PublicConfig, secret SecretShare, ct Ciphertext) (DecryptionShare, error) {
	if _, err := validateCiphertext(config, ct); err != nil {
		return DecryptionShare{}, err
	}
	if secret.ConfigID != config.ID || secret.Index < 0 || secret.Index >= config.N {
		return DecryptionShare{}, fmt.Errorf("%w: secret share", ErrContextMismatch)
	}
	if len(secret.Value) == 0 || len(secret.Value) > 32 {
		return DecryptionShare{}, errors.New("invalid secret scalar length")
	}
	scalar := new(shcrypto.EonSecretKeyShare)
	if err := scalar.Unmarshal(secret.Value); err != nil {
		return DecryptionShare{}, err
	}
	if (*big.Int)(scalar).Sign() == 0 || !bytes.Equal(scalar.Marshal(), secret.Value) {
		return DecryptionShare{}, errors.New("zero or noncanonical secret scalar")
	}
	share := DecryptionShare{
		ConfigID: config.ID, CiphertextID: ct.ID(), Index: secret.Index,
		Value: shcrypto.ComputeEpochSecretKeyShare(scalar, shcrypto.ComputeEpochID(ct.identity())).Marshal(),
	}
	if err := VerifyDecryptionShare(config, ct, share); err != nil {
		return DecryptionShare{}, fmt.Errorf("secret share does not match DKG verification key: %w", err)
	}
	return share, nil
}

// VerifyDecryptionShare verifies the BLS pairing proof, including the exact
// configuration, identity and participant index. Ciphertext integrity itself is
// checked when threshold decryption recovers the plaintext.
func VerifyDecryptionShare(config PublicConfig, ct Ciphertext, share DecryptionShare) error {
	if _, err := validateCiphertext(config, ct); err != nil {
		return err
	}
	if share.ConfigID != config.ID || share.CiphertextID != ct.ID() {
		return fmt.Errorf("%w: decryption share envelope", ErrContextMismatch)
	}
	if share.Index < 0 || share.Index >= config.N {
		return fmt.Errorf("%w: participant index", ErrInvalidShare)
	}
	value, err := p1(share.Value)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidShare, err)
	}
	key, err := p2(config.VerificationKeys[share.Index])
	if err != nil {
		return err
	}
	if !shcrypto.VerifyEpochSecretKeyShare((*shcrypto.EpochSecretKeyShare)(value), (*shcrypto.EonPublicKeyShare)(key), shcrypto.ComputeEpochID(ct.identity())) {
		return fmt.Errorf("%w: BLS pairing verification failed", ErrInvalidShare)
	}
	return nil
}

// Decrypt verifies every supplied share, rejects repeated participant indices,
// combines exactly Threshold valid shares using shcrypto, and checks ciphertext
// integrity before returning the plaintext. Invalid extras are never ignored.
func Decrypt(config PublicConfig, ct Ciphertext, shares []DecryptionShare) ([]byte, error) {
	msg, err := validateCiphertext(config, ct)
	if err != nil {
		return nil, err
	}
	if len(shares) < config.Threshold {
		return nil, ErrInsufficientShares
	}
	if len(shares) > config.N {
		return nil, errors.New("too many decryption shares")
	}
	indices := make([]int, 0, config.Threshold)
	values := make([]*shcrypto.EpochSecretKeyShare, 0, config.Threshold)
	seen := make(map[int]bool, len(shares))
	for _, share := range shares {
		if seen[share.Index] {
			return nil, fmt.Errorf("%w: repeated participant %d", ErrInvalidShare, share.Index)
		}
		if err := VerifyDecryptionShare(config, ct, share); err != nil {
			return nil, err
		}
		seen[share.Index] = true
		if len(indices) < config.Threshold {
			point, err := p1(share.Value)
			if err != nil {
				return nil, err
			}
			indices = append(indices, share.Index)
			values = append(values, (*shcrypto.EpochSecretKeyShare)(point))
		}
	}
	key, err := shcrypto.ComputeEpochSecretKey(indices, values, uint64(config.Threshold))
	if err != nil {
		return nil, err
	}
	plaintext, err := msg.Decrypt(key)
	if err != nil {
		return nil, fmt.Errorf("threshold ciphertext integrity: %w", err)
	}
	return plaintext, nil
}
