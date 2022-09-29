package legit_remote_attest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

func AttestWithToken(data interface{}, endpoint LegitEndpoint, jwt string) ([]byte, error) {
	attBytes, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed marshalling json: %w", err)
	}

	request, err := http.NewRequest("POST", endpoint.Url, bytes.NewBuffer(attBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create signing request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json; charset=UTF-8")
	request.Header.Set("jwt", jwt)

	legitApiHeader := MakeBearerHeader(endpoint.ApiToken)
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

func Attest(data interface{}, endpoint LegitEndpoint) ([]byte, error) {
	token, err := GetJWTToken()
	if err != nil {
		return nil, err
	}

	result, err := AttestWithToken(data, endpoint, token)
	if err != nil {
		return nil, err
	}

	return result, nil
}
