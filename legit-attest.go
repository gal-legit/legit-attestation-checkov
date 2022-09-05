package legitattest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

const (
	REQ_TOKEN          = "ACTIONS_ID_TOKEN_REQUEST_TOKEN"
	REQ_URL            = "ACTIONS_ID_TOKEN_REQUEST_URL"
	REQ_AUDIENCE       = "Legit"
	LEGIT_ENDPOINT_URL = "LEGIT_ENDPOINT_URL"
	LEGIT_API_TOKEN    = "LEGIT_API_TOKEN"
)

func getActionsURL() string {
	return os.Getenv(REQ_URL)
}

func getBarrierHeader(token string) []string {
	return []string{
		"Authorization",
		"bearer " + token,
	}
}

func getActionsTokenHeader() []string {
	token := os.Getenv(REQ_TOKEN)
	return getBarrierHeader(token)
}

func getLegitTokenHeader() []string {
	token := os.Getenv(LEGIT_API_TOKEN)
	return getBarrierHeader(token)
}

func getLegitEndpointUrl() string {
	return os.Getenv(LEGIT_ENDPOINT_URL)
}

func GetToken() (string, error) {
	url := getActionsURL()
	request, err := http.NewRequest("GET", url, bytes.NewBuffer([]byte{}))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}
	token := getActionsTokenHeader()
	request.Header.Set(token[0], token[1])

	q := request.URL.Query()
	q.Add("audience", REQ_AUDIENCE)
	request.URL.RawQuery = q.Encode()

	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		panic(err)
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %v", err)
	}

	var result struct {
		Count int    `json:"count"`
		Value string `json:"value"`
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return result.Value, nil
}

func AttestWithToken(data interface{}, jwt string) ([]byte, error) {
	attBytes, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed marshalling json: %w", err)
	}

	httpposturl := getLegitEndpointUrl()

	request, err := http.NewRequest("POST", httpposturl, bytes.NewBuffer(attBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create signing request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json; charset=UTF-8")
	request.Header.Set("jwt", jwt)

	legitApiHeader := getLegitTokenHeader()
	request.Header.Set(legitApiHeader[0], legitApiHeader[1])

	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		panic(err)
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read signing response: %v", body)
	}

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad response from server (%v): %v\n", response.StatusCode, string(body))
	}

	return body, nil
}

func Attest(data interface{}) ([]byte, error) {
	token, err := GetToken()
	if err != nil {
		return nil, err
	}

	result, err := AttestWithToken(data, token)
	if err != nil {
		return nil, err
	}

	return result, nil
}
