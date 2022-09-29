package legit_remote_attest

import "os"

const (
	LEGIT_ENDPOINT_URL = "LEGIT_ENDPOINT_URL"
	LEGIT_API_TOKEN    = "LEGIT_API_TOKEN"
)

func GetLegitApiToken() string {
	return os.Getenv(LEGIT_API_TOKEN)
}

func GetLegitEndpointUrl() string {
	return os.Getenv(LEGIT_ENDPOINT_URL)
}

type LegitEndpoint struct {
	Url      string
	ApiToken string
}
