package legit_verify_attestation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	dsselib "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
)

func attestationToEnvelope(attestation []byte) (*dsselib.Envelope, error) {
	var env dsselib.Envelope

	if err := json.Unmarshal(attestation, &env); err != nil {
		return nil, err
	}

	return &env, nil
}

func verifySig(envelope *dsselib.Envelope, ctx context.Context, keyRef string) error {
	sv, err := signature.PublicKeyFromKeyRef(ctx, keyRef)
	if err != nil {
		return fmt.Errorf("Failed to load pub key: %v\n", err)
	}

	dssev, err := dsselib.NewEnvelopeVerifier(&dsse.VerifierAdapter{SignatureVerifier: sv})
	if err != nil {
		return err
	}
	_, err = dssev.Verify(envelope)
	if err != nil {
		return fmt.Errorf("failed verify: %v\n", err)
	}

	return nil
}

func ExtractPayload(ctx context.Context, keyRef string, attestation []byte, skipSigVerification bool) ([]byte, error) {
	envelope, err := attestationToEnvelope(attestation)
	if err != nil {
		return nil, err
	}

	if !skipSigVerification {
		err = verifySig(envelope, ctx, keyRef)
		if err != nil {
			return nil, err
		}
	}

	decoded, err := base64.StdEncoding.DecodeString(string(envelope.Payload))
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %v", err)
	}

	return decoded, nil
}

func VerifiedPayload(ctx context.Context, keyRef string, attestation []byte) ([]byte, error) {
	return ExtractPayload(ctx, keyRef, attestation, false)
}

func UnverifiedPayload(ctx context.Context, keyRef string, attestation []byte) ([]byte, error) {
	return ExtractPayload(ctx, keyRef, attestation, true)
}
