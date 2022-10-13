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
	payloadPath  string
	payloadStdin bool
)

func main() {
	flag.StringVar(&keyPath, "key", "", "The path of the private key")
	flag.StringVar(&payloadPath, "payload-path", "", "The path to a file containing payload to attest")
	flag.BoolVar(&payloadStdin, "payload-stdin", false, "Read the json from stdin (overwrites -payload-path if provided)")

	flag.Parse()

	if keyPath == "" {
		log.Panicf("please provide a private key path")
	} else if !payloadStdin && payloadPath == "" {
		log.Panicf("please provide a payload (or set -payload-stdin to read it from stdin)")
	}

	var payload []byte
	var err error
	if payloadStdin {
		if payload, err = ioutil.ReadAll(os.Stdin); err != nil {
			log.Panicf("failed to read payload from stdin: %v", err)
		}
	} else {
		payload, err = os.ReadFile(payloadPath)
		if err != nil {
			log.Panicf("failed to open payload at %v: %v", payloadPath, err)
		}
	}

	attestation, err := legit_attest.Attest(context.Background(), keyPath, payload)
	if err != nil {
		log.Panicf("failed to attest: %v", err)
	}

	// Print the attestation as json output to stdout
	fmt.Printf("%v", string(attestation))
}
