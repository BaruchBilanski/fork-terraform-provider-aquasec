package client

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/terraform-provider-aquasec/consts"
	"github.com/parnurzeal/gorequest"
	"golang.org/x/net/http/httpproxy"
	"golang.org/x/time/rate"
	"log"
	neturl "net/url"
	"strconv"
	"time"
)

// Client - API client
type Client struct {
	url        string
	tokenUrl   string
	user       string
	password   string
	token      string
	name       string
	gorequest  *gorequest.SuperAgent
	clientType string
	limiter    *rate.Limiter
	api_key    string
	api_secret string
}

const Csp string = "csp"
const Saas = "saas"
const SaasDev = "saasDev"

// NewClient - initialize and return the Client
func NewClient(url, user, password string, apiKey string, apiSecret string, verifyTLS bool, caCertByte []byte) *Client {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: !verifyTLS,
	}

	roots := x509.NewCertPool()
	if len(caCertByte) > 0 {
		roots.AppendCertsFromPEM(caCertByte)

		if verifyTLS {
			tlsConfig = &tls.Config{
				RootCAs: roots,
			}
		}
	}

	c := &Client{
		url:        url,
		user:       user,
		password:   password,
		api_key:    apiKey,
		api_secret: apiSecret,
		gorequest:  gorequest.New().TLSClientConfig(tlsConfig),
		// we are setting rate limit for 10 connection per second
		limiter: rate.NewLimiter(10, 3),
	}

	// Determine if we need to use a proxy
	uURL, _ := neturl.Parse(c.url)
	proxy, _ := httpproxy.FromEnvironment().ProxyFunc()(uURL)
	if proxy != nil {
		c.gorequest.Proxy(proxy.String())
	}

	switch url {
	case consts.SaasUrl:
		c.clientType = Saas
		c.tokenUrl = consts.SaasTokenUrl
		break
	case consts.SaasEu1Url:
		c.clientType = Saas
		c.tokenUrl = consts.SaasEu1TokenUrl
		break
	case consts.SaasAsia1Url:
		c.clientType = Saas
		c.tokenUrl = consts.SaasAsia1TokenUrl
		break
	case consts.SaasAsia2Url:
		c.clientType = Saas
		c.tokenUrl = consts.SaasAsia2TokenUrl
		break
	case consts.SaasDevUrl:
		c.clientType = SaasDev
		c.tokenUrl = consts.SaasDevTokenUrl
		break
	default:
		c.clientType = Csp
		break
	}

	return c
}

func (cli *Client) SetAuthToken(token string) {
	cli.token = token
}

func (cli *Client) SetUrl(url string) {
	cli.url = url
}

func (cli *Client) GetAuthToken() (string, string, error) {
	var err error

	if cli.clientType == "csp" {
		_, err = cli.GetCspAuthToken()
	} else {
		_, _, err = cli.GetUSEAuthToken()
	}

	if err != nil {
		return "", "", err
	}
	return cli.token, cli.url, nil
}

// GetAuthToken - Connect to Aqua and return a JWT bearerToken (string)
func (cli *Client) GetCspAuthToken() (string, error) {
	resp, body, errs := cli.gorequest.Post(cli.url + "/api/v1/login").
		Send(`{"id":"` + cli.user + `", "password":"` + cli.password + `"}`).End()
	if errs != nil {
		return "", getMergedError(errs)
	}

	if resp.StatusCode == 200 {
		var raw map[string]interface{}
		_ = json.Unmarshal([]byte(body), &raw)
		cli.token = raw["token"].(string)
		return cli.token, nil
	}

	return "", fmt.Errorf("request failed. status: %s, response: %s", resp.Status, body)
}

// GetUSEAuthToken - Connect to Aqua SaaS solution and return a JWT bearerToken (string)
func (cli *Client) GetUSEAuthToken() (string, string, error) {
	var provUrl string

	switch cli.url {
	case consts.SaasUrl:
		provUrl = consts.SaasProvUrl
		break
	case consts.SaasEu1Url:
		provUrl = consts.SaasEu1ProvUrl
		break
	case consts.SaasAsia1Url:
		provUrl = consts.SaasAsia1ProvUrl
		break
	case consts.SaasAsia2Url:
		provUrl = consts.SaasAsia2ProvUrl
		break
	case consts.SaasDevUrl:
		provUrl = consts.SaasDevProvUrl
		break
	default:
		return "", "", fmt.Errorf(fmt.Sprintf("%v URL is not allowed USE url", cli.url))
	}

	if cli.user != "" && cli.password != "" {
		resp, body, errs := gorequest.New().Post(cli.tokenUrl + "/v2/signin").
			Send(`{"email":"` + cli.user + `", "password":"` + cli.password + `"}`).
			End()

		if errs != nil {
			return "", "", getMergedError(errs)
		}

		if resp.StatusCode == 200 {
			var raw map[string]interface{}
			_ = json.Unmarshal([]byte(body), &raw)
			data := raw["data"].(map[string]interface{})
			cli.token = data["token"].(string)
			//get the ese_url to make the API requests.
			request := cli.gorequest
			request.Set("Authorization", "Bearer "+cli.token)
			events, body, errs := request.Clone().Get(provUrl + "/v1/envs").End()

			if errs != nil {
				log.Println(events.StatusCode)
				err := fmt.Errorf("error calling %s", provUrl)
				return "", "", err
			}

			if events.StatusCode == 200 {
				var raw map[string]interface{}
				_ = json.Unmarshal([]byte(body), &raw)
				data := raw["data"].(map[string]interface{})
				cli.url = "https://" + data["ese_url"].(string)
			}

			return cli.token, cli.url, nil
		}
	}

	if cli.api_key != "" && cli.api_secret != "" {
		// Request body
		tokenCreationData := map[string]interface{}{
			"allowed_endpoints": []string{"DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "ANY"},
		}

		// Convert the request body to a JSON string
		tokenCreationDataJSON, err := json.Marshal(tokenCreationData)
		if err != nil {
			fmt.Errorf("%s", err)
			return "", "", err
		}
		// Generate timestamp
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)

		// Create signature
		stringToSign := timestamp + "POST" + "/v2/tokens" + string(tokenCreationDataJSON)
		stringToSign = fmt.Sprintf("%s", bytes.ReplaceAll([]byte(stringToSign), []byte(" "), []byte("")))

		hash := hmac.New(sha256.New, []byte(cli.api_secret))
		hash.Write([]byte(stringToSign))
		signature := fmt.Sprintf("%x", hash.Sum(nil))
		///
		// Make API request using gorequest
		request := gorequest.New().Post(cli.tokenUrl+"/v2/tokens").
			Send(tokenCreationData).
			Set("X-API-Key", cli.api_key).
			Set("X-Signature", signature).
			Set("X-Timestamp", timestamp).
			Set("Content-Type", "application/json")

		// Perform the API request
		resp, body, errs := request.End()
		if errs != nil {
			err := fmt.Errorf("%s", errs)
			return "", "", err
		}

		if resp.StatusCode == 200 {
			fmt.Println("trying api auth66")

			// Struct to capture the JSON response
			var jsonResponse struct {
				Status int    `json:"status"`
				Code   int    `json:"code"`
				Data   string `json:"data"`
			}

			// Unmarshal the JSON response
			if err := json.Unmarshal([]byte(body), &jsonResponse); err != nil {
				fmt.Println("Error unmarshaling JSON:", err)
				return "", "", err
			}

			// Accessing the token from the JSON response
			token := jsonResponse.Data

			// Set the token in cli
			cli.token = token

			// Get the ese_url to make the API requests.
			request := gorequest.New()
			request.Set("Authorization", "Bearer "+cli.token)

			events, body, errs := request.Clone().Get(provUrl + "/v1/envs").End()

			if errs != nil {
				log.Println(events.StatusCode)
				err := fmt.Errorf("error calling %s", provUrl)
				return "", "", err
			}

			if events.StatusCode == 200 {
				var raw map[string]interface{}
				_ = json.Unmarshal([]byte(body), &raw)
				data := raw["data"].(map[string]interface{})
				cli.url = "https://" + data["ese_url"].(string)
			}
			return cli.token, cli.url, nil
		}
	}

	return "", "", fmt.Errorf("internal error: couldn't get token")
}
