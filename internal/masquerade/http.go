package masquerade

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ehsanking/elahe-tunnel/internal/logger"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

// WrapInHttpRequest takes encrypted data and wraps it into an HTTP request that mimics a Google search.
// It will randomly choose between a GET and a POST request.
func WrapInHttpRequest(data []byte, host string) (*http.Request, error) {
	encodedData := base64.URLEncoding.EncodeToString(data)

	var req *http.Request
	var err error

	// Randomly choose between GET and POST
	randomQuery := getRandomSearchQuery()
	if rand.Float32() < 0.5 {
		logger.Info.Println("Masquerading as GET request")
		// --- Create GET request ---
		targetURL := "https://" + host + "/search"
		req, err = http.NewRequest("GET", targetURL, nil)
		if err != nil {
			return nil, err
		}

		// Add payload to query parameters
		q := req.URL.Query()
		q.Add("q", randomQuery) // Decoy query
		q.Add("oq", encodedData)                 // Payload
		q.Add("sourceid", "chrome")
		req.URL.RawQuery = q.Encode()
	} else {
		logger.Info.Println("Masquerading as POST request")
		// --- Create POST request ---
		form := url.Values{}
		form.Add("q", randomQuery) // A decoy query
		form.Add("oq", encodedData)            // Hide data in a less obvious param
		body := strings.NewReader(form.Encode())

		req, err = http.NewRequest("POST", "https://"+host+"/search", body)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	// Set common headers to mimic a real browser
	req.Header.Set("Host", host)
	req.Header.Set("User-Agent", getRandomUserAgent())
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Referer", "https://www.google.com/")

	return req, nil
}

// UnwrapFromHttpRequest extracts the base64 encoded data from either the query params (GET) or body (POST) of an HTTP request.
func UnwrapFromHttpRequest(r *http.Request) ([]byte, error) {
	var encodedData string

	switch r.Method {
	case "GET":
		encodedData = r.URL.Query().Get("oq")
	case "POST":
		if err := r.ParseForm(); err != nil {
			return nil, fmt.Errorf("error parsing form: %w", err)
		}
		encodedData = r.Form.Get("oq")
	default:
		return nil, fmt.Errorf("unsupported method: %s", r.Method)
	}

	if encodedData == "" {
		return nil, fmt.Errorf("payload 'oq' not found in request")
	}

	return base64.URLEncoding.DecodeString(encodedData)
}

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14.1; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Android 14; Mobile; rv:121.0) Gecko/121.0 Firefox/121.0",
}

var searchQueries = []string{
	"weather tomorrow",
	"best restaurants near me",
	"how to cook pasta",
	"translate english to spanish",
	"currency converter",
	"movies playing now",
	"stock market today",
	"calculator online",
	"periodic table of elements",
	"world cup schedule",
	"latest tech news",
	"python tutorial for beginners",
	"best travel destinations 2024",
	"healthy dinner recipes",
	"yoga for beginners",
	"top 10 movies of all time",
	"how to learn guitar",
	"best books to read",
	"history of the internet",
	"space exploration news",
}

func getRandomUserAgent() string {
	return userAgents[rand.Intn(len(userAgents))]
}

func getRandomSearchQuery() string {
	return searchQueries[rand.Intn(len(searchQueries))]
}

// RealisticGoogleSearchHTML is a more convincing fake Google search results page.
const RealisticGoogleSearchHTML = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Google</title><style>body{font-family:arial,sans-serif;}</style></head><body><div id="main"><div id="cnt"><div id="rcnt"><div id="center_col"><div id="res"><div id="search"><div id="ires"><div id="rso"><div class="g"><div data-hveid="CAgQAA"></div><div data-ved="2ahUKEwi_n5Xo_r_7AhV_j4kEHQ_XD4sQFSgAegQIARAB"><div class="V3FYCf"></div><div id="web" data-payload="%s"></div></div></div></div></div></div></div></div></div></div></div></body></html>`

// WrapInJsonResponse wraps data in a fake JSON API response.
func WrapInJsonResponse(data []byte) *http.Response {
	jsonBody := fmt.Sprintf(`{"status":"ok","data":{"results":["%s"],"session_id":"%s"}}`, getRandomSearchQuery(), base64.URLEncoding.EncodeToString(data))
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewBufferString(jsonBody)),
	}
	resp.Header.Set("Content-Type", "application/json")
	return resp
}

// WrapInTextResponse wraps data in a fake robots.txt file.
func WrapInTextResponse(data []byte) *http.Response {
	textBody := fmt.Sprintf("User-agent: *\nDisallow: /search\n\n# SessionData: %s", base64.URLEncoding.EncodeToString(data))
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewBufferString(textBody)),
	}
	resp.Header.Set("Content-Type", "text/plain")
	return resp
}

// WrapInRandomHttpResponse randomly chooses a response format (HTML, JSON, text) and wraps the data in it.
func WrapInRandomHttpResponse(data []byte) *http.Response {
	logger.Info.Println("Choosing random response format...")
	choice := rand.Intn(3)
	switch choice {
	case 0:
		logger.Info.Println("Masquerading as HTML response")
		return WrapInHtmlResponse(data)
	case 1:
		logger.Info.Println("Masquerading as JSON response")
		return WrapInJsonResponse(data)
	default:
		logger.Info.Println("Masquerading as Text response")
		return WrapInTextResponse(data)
	}
}

// WrapInHtmlResponse takes encrypted data and embeds it into a fake Google search results HTML page.
func WrapInHtmlResponse(data []byte) *http.Response {
	htmlBody := fmt.Sprintf(RealisticGoogleSearchHTML, base64.URLEncoding.EncodeToString(data))

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewBufferString(htmlBody)),
	}
	resp.Header.Set("Content-Type", "text/html; charset=utf-8")

	return resp
}

// UnwrapFromHttpResponse intelligently extracts data from an HTTP response, regardless of the masqueraded content type.
func UnwrapFromHttpResponse(resp *http.Response) ([]byte, error) {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	contentType := resp.Header.Get("Content-Type")

	var encodedData string

	switch {
	case strings.Contains(contentType, "text/html"):
		encodedData, err = unwrapFromHtml(body)
	case strings.Contains(contentType, "application/json"):
		encodedData, err = unwrapFromJson(body)
	case strings.Contains(contentType, "text/plain"):
		encodedData, err = unwrapFromText(body)
	default:
		err = fmt.Errorf("unsupported content type: %s", contentType)
	}

	if err != nil {
		return nil, err
	}

	return base64.URLEncoding.DecodeString(encodedData)
}

func unwrapFromHtml(body []byte) (string, error) {
	startTag := "<div id=\"web\" data-payload=\""
	endTag := "\"></div>"
	startIndex := strings.Index(string(body), startTag)
	if startIndex == -1 {
		return "", fmt.Errorf("html payload start tag not found")
	}
	startIndex += len(startTag)
	endIndex := strings.Index(string(body)[startIndex:], endTag)
	if endIndex == -1 {
		return "", fmt.Errorf("html payload end tag not found")
	}
	return string(body)[startIndex : startIndex+endIndex], nil
}

func unwrapFromJson(body []byte) (string, error) {
	startTag := `"session_id":"`
	endTag := `"}`
	startIndex := strings.Index(string(body), startTag)
	if startIndex == -1 {
		return "", fmt.Errorf("json payload start tag not found")
	}
	startIndex += len(startTag)
	endIndex := strings.Index(string(body)[startIndex:], endTag)
	if endIndex == -1 {
		return "", fmt.Errorf("json payload end tag not found")
	}
	return string(body)[startIndex : startIndex+endIndex], nil
}

func unwrapFromText(body []byte) (string, error) {
	prefix := "# SessionData: "
	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimPrefix(line, prefix), nil
		}
	}
	return "", fmt.Errorf("text payload prefix not found")
}
