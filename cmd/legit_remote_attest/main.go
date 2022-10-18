package main

import (
	"flag"
	"log"
	"os"

	"github.com/legit-labs/legit-attestation/pkg/legit_remote_attest"
)

var (
	subjectsBase64 string
	endpoint       legit_remote_attest.LegitEndpoint
)

func main() {
	flag.StringVar(&subjectsBase64, "subjects-base64", "", "The base64-encoded subjects in the sha256sum format")
	flag.StringVar(&endpoint.Url, "url", "", "The url of Legit server")
	flag.StringVar(&endpoint.ApiToken, "api-token", "", "The api-token to Legit")

	flag.Parse()

	if subjectsBase64 == "" {
		log.Panicf("missing subjects")
	} else if endpoint.Url == "" {
		log.Panicf("missing url")
	} else if endpoint.ApiToken == "" {
		log.Panicf("missing api token")
	}

	res, err := legit_remote_attest.Attest(subjectsBase64, endpoint)
	if err != nil {
		log.Panicf("failed to attest: %v", err)
	}

	if _, err := os.Stdout.Write(res); err != nil {
		log.Panicf("failed to output: %v", err)
	}
}
