package main

import (
	"encoding/json"
	"flag"
	"log"

	"github.com/legit-labs/legit-attestation/pkg/legit_remote_attest"
)

var (
	payload  string
	endpoint legit_remote_attest.LegitEndpoint
)

func main() {
	flag.StringVar(&payload, "payload", "", "The JSON payload of the attestation")
	flag.StringVar(&endpoint.Url, "url", "", "The url of Legit server")
	flag.StringVar(&endpoint.ApiToken, "api-token", "", "The api-token to Legit")

	flag.Parse()

	if payload == "" {
		log.Panicf("please provide a payload")
	}

	var data interface{}
	err := json.Unmarshal([]byte(payload), &data)
	if err != nil {
		log.Panicf("failed to unmarshal payload: %v", err)
	}

	legit_remote_attest.Attest(data, endpoint)
}
