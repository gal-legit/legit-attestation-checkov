package main

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"os"

	"github.com/legit-labs/legit-attestation/pkg/legit_remote_attest"
)

var (
	data         legit_remote_attest.RemoteAttestationData
	payloadPath  string
	payloadStdin bool
	endpoint     legit_remote_attest.LegitEndpoint
)

func main() {
	flag.StringVar(&payloadPath, "payload-path", "", "The path to a file containing environment needed for the attestation")
	flag.BoolVar(&payloadStdin, "payload-stdin", false, "Read the json from stdin (overwrites -payload-path if provided)")
	flag.StringVar(&data.SubjectsBase64, "subjects-base64", "", "The base64-encoded subjects in the sha256sum format")
	flag.StringVar(&endpoint.Url, "url", "", "The url of Legit server")
	flag.StringVar(&endpoint.ApiToken, "api-token", "", "The api-token to Legit")

	flag.Parse()

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

	data.Env = make(map[string]string)
	if err = json.Unmarshal(payload, &data.Env); err != nil {
		log.Panicf("failed to unmarshal payload: %v", err)
	}

	legit_remote_attest.Attest(data, endpoint)
}
