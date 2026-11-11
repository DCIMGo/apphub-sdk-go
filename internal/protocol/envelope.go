package protocol

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

const (
	AlgorithmEd25519 = "Ed25519"
	PurposeLicense   = "license"
	PurposeLease     = "lease"
	maxEnvelopeSize  = 4 << 20
	maxPayloadSize   = 2 << 20
)

type Envelope struct {
	SchemaVersion string          `json:"schemaVersion"`
	Purpose       string          `json:"purpose"`
	KeyID         string          `json:"keyId"`
	Algorithm     string          `json:"algorithm"`
	Payload       json.RawMessage `json:"payload"`
	Signature     string          `json:"signature"`
}
type SignFunc func(context.Context, []byte) ([]byte, error)

func SignLicense(ctx context.Context, payload Payload, keyID string, sign SignFunc) ([]byte, error) {
	if payload.SchemaVersion == "" {
		payload.SchemaVersion = SchemaVersionV1
	}
	if (payload.SchemaVersion == SchemaVersionV2 || payload.MachineBinding != nil) && !ValidMachineBinding(payload.SchemaVersion, payload.MachineID, payload.MachineBinding) {
		return nil, NewValidationError(ErrInvalidPayload, "machineBinding", nil)
	}
	return signPayload(ctx, PurposeLicense, payload.SchemaVersion, keyID, payload, sign)
}
func SignLease(ctx context.Context, payload LeasePayload, keyID string, sign SignFunc) ([]byte, error) {
	if payload.SchemaVersion == "" {
		payload.SchemaVersion = SchemaVersionV1
	}
	if (payload.SchemaVersion == SchemaVersionV2 || payload.MachineBinding != nil) && !ValidMachineBinding(payload.SchemaVersion, payload.MachineID, payload.MachineBinding) {
		return nil, NewValidationError(ErrInvalidPayload, "machineBinding", nil)
	}
	return signPayload(ctx, PurposeLease, payload.SchemaVersion, keyID, payload, sign)
}
func Ed25519SignFunc(privateKey ed25519.PrivateKey) (SignFunc, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid Ed25519 private key size")
	}
	key := append(ed25519.PrivateKey(nil), privateKey...)
	return func(_ context.Context, message []byte) ([]byte, error) { return ed25519.Sign(key, message), nil }, nil
}
func signPayload(ctx context.Context, purpose, schemaVersion, keyID string, payload any, sign SignFunc) ([]byte, error) {
	if sign == nil || !validKeyID(keyID) {
		return nil, NewValidationError(ErrInvalidPayload, "signer", nil)
	}
	rawPayload, err := json.Marshal(payload)
	if err != nil {
		return nil, NewValidationError(ErrInvalidPayload, "payload", err)
	}
	if len(rawPayload) > maxPayloadSize {
		return nil, NewValidationError(ErrInvalidPayload, "payloadSize", nil)
	}
	signature, err := sign(ctx, signatureInput(purpose, schemaVersion, keyID, rawPayload))
	if err != nil {
		return nil, fmt.Errorf("sign license envelope: %w", err)
	}
	if len(signature) != ed25519.SignatureSize {
		return nil, NewValidationError(ErrInvalidSignature, "signatureSize", nil)
	}
	content, err := json.Marshal(Envelope{SchemaVersion: schemaVersion, Purpose: purpose, KeyID: keyID, Algorithm: AlgorithmEd25519, Payload: rawPayload, Signature: base64.RawURLEncoding.EncodeToString(signature)})
	if err != nil {
		return nil, fmt.Errorf("marshal license envelope: %w", err)
	}
	return content, nil
}

type KeySet map[string]ed25519.PublicKey

func (keys KeySet) VerifyLicense(content []byte) (Payload, Envelope, error) {
	var payload Payload
	envelope, err := keys.verify(content, PurposeLicense)
	if err != nil {
		return payload, envelope, err
	}
	if err = json.Unmarshal(envelope.Payload, &payload); err != nil {
		return payload, envelope, NewValidationError(ErrInvalidPayload, "payload", err)
	}
	if payload.SchemaVersion != envelope.SchemaVersion ||
		(payload.SchemaVersion == SchemaVersionV2 || payload.MachineBinding != nil) &&
			!ValidMachineBinding(payload.SchemaVersion, payload.MachineID, payload.MachineBinding) {
		return payload, envelope, NewValidationError(ErrInvalidPayload, "schemaVersion", nil)
	}
	return payload, envelope, nil
}
func (keys KeySet) VerifyLease(content []byte) (LeasePayload, Envelope, error) {
	var payload LeasePayload
	envelope, err := keys.verify(content, PurposeLease)
	if err != nil {
		return payload, envelope, err
	}
	if err = json.Unmarshal(envelope.Payload, &payload); err != nil {
		return payload, envelope, NewValidationError(ErrInvalidPayload, "payload", err)
	}
	if payload.SchemaVersion != envelope.SchemaVersion ||
		(payload.SchemaVersion == SchemaVersionV2 || payload.MachineBinding != nil) &&
			!ValidMachineBinding(payload.SchemaVersion, payload.MachineID, payload.MachineBinding) {
		return payload, envelope, NewValidationError(ErrInvalidPayload, "schemaVersion", nil)
	}
	return payload, envelope, nil
}
func (keys KeySet) verify(content []byte, expectedPurpose string) (Envelope, error) {
	var envelope Envelope
	if len(content) == 0 || len(content) > maxEnvelopeSize {
		return envelope, NewValidationError(ErrInvalidPayload, "envelopeSize", nil)
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	if err := decoder.Decode(&envelope); err != nil {
		return envelope, NewValidationError(ErrInvalidPayload, "envelope", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return envelope, NewValidationError(ErrInvalidPayload, "envelope", nil)
	}
	if envelope.SchemaVersion != SchemaVersionV1 && envelope.SchemaVersion != SchemaVersionV2 {
		return envelope, NewValidationError(ErrUnsupportedFormat, "schemaVersion", nil)
	}
	if envelope.Purpose != expectedPurpose {
		return envelope, NewValidationError(ErrInvalidSignature, "purpose", nil)
	}
	if envelope.Algorithm != AlgorithmEd25519 || !validKeyID(envelope.KeyID) || len(envelope.Payload) == 0 || len(envelope.Payload) > maxPayloadSize {
		return envelope, NewValidationError(ErrInvalidPayload, "envelope", nil)
	}
	publicKey, exists := keys[envelope.KeyID]
	if !exists || len(publicKey) != ed25519.PublicKeySize {
		return envelope, NewValidationError(ErrUnknownKey, "keyId", nil)
	}
	signature, err := base64.RawURLEncoding.DecodeString(envelope.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return envelope, NewValidationError(ErrInvalidSignature, "signature", err)
	}
	if !ed25519.Verify(publicKey, signatureInput(envelope.Purpose, envelope.SchemaVersion, envelope.KeyID, envelope.Payload), signature) {
		return envelope, NewValidationError(ErrInvalidSignature, "signature", nil)
	}
	return envelope, nil
}
func signatureInput(purpose, schemaVersion, keyID string, payload []byte) []byte {
	digest := sha256.Sum256(payload)
	return []byte(strings.Join([]string{"DCIMGO-APPHUB-SIGNED-ENVELOPE", purpose, schemaVersion, keyID, hex.EncodeToString(digest[:])}, "\n"))
}
func validKeyID(keyID string) bool {
	if len(keyID) < 1 || len(keyID) > 128 {
		return false
	}
	for _, r := range keyID {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}
