package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/legit-labs/legit-attestation/pkg/legit_attest"
)

var (
	keyPath      string
	payload      string
	payloadStdin bool
)

func main() {
	flag.StringVar(&keyPath, "key", "", "The path of the private key")
	flag.StringVar(&payload, "payload", "", "The payload to attest (json blob)")
	flag.BoolVar(&payloadStdin, "payload-stdin", false, "Read the json from stdin (overwrites -payload if provided)")

	flag.Parse()

	if keyPath == "" {
		log.Panicf("please provide a private key path")
	} else if !payloadStdin && payload == "" {
		log.Panicf("please provide a payload (or set -payload-stdin to read it from stdin)")
	}

	if payloadStdin {
		if payloadBytes, err := ioutil.ReadAll(os.Stdin); err != nil {
			log.Panicf("failed to read payload from stdin: %v", err)
		} else {
			payload = string(payloadBytes)
		}
	}

	attestation, err := legit_attest.Attest(context.Background(), keyPath, []byte(payload))
	if err != nil {
		log.Panicf("failed to attest: %v", err)
	}

	// Print the attestation as json output to stdout
	fmt.Printf("%v", string(attestation))
}
