package main

import (
	"context"
	"flag"
	"log"
	"os"

	"github.com/legit-labs/legit-attest/pkg/verify_attestation"
	"github.com/legit-labs/legit-verify-attestation/pkg/verify_attestation"
)

const (
	skipSigVerification = "SKIP_ATTESTATION_SIGNATURE_VERIFICATION"
	outputPayload       = "OUTPUT_PAYLOAD"
)

func shouldSkipVerification() bool {
	return os.Getenv(skipSigVerification) == "1"
}

func shouldOutputPayload() bool {
	return os.Getenv(outputPayload) == "1"
}

var (
	keyPath         string
	attestationPath string
)

func main() {
	flag.StringVar(&keyPath, "key", "", "The path of the public key")
	flag.StringVar(&attestationPath, "attestation", "", "The path of the attestation document")

	flag.Parse()

	if keyPath == "" {
		log.Panicf("please provide a public key path")
	} else if attestationPath == "" {
		log.Panicf("please provide an attestation path")
	}

	attestation, err := os.ReadFile(attestationPath)
	if err != nil {
		log.Panicf("failed to open attestation at %v: %v", attestationPath, err)
	}

	shouldSkip := shouldSkipVerification()
	payload, err := verify_attestation.ExtractPayload(context.Background(), keyPath, attestation, shouldSkip)
	if err != nil {
		log.Panicf("attestation verification failed: %v", err)
	}

	if !shouldSkip {
		log.Printf("attestation was verified successfully against the public key.")
	}

	if shouldOutputPayload() {
		_, err := os.Stdout.Write(payload)
		if err != nil {
			log.Printf("failed to print payload: %v", err)
		}
	}
}
