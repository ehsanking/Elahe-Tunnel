package masquerade

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// WrapInHttpRequest takes encrypted data and wraps it into an HTTP POST request
// that mimics a Google search submission.
func WrapInHttpRequest(data []byte, host string) (*http.Request, error) {
	formData := url.Values{}
	formData.Set("q", base64.URLEncoding.EncodeToString(data))

	req, err := http.NewRequest("POST", fmt.Sprintf("https://%s/search", host), strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, err
	}

	// Set headers to mimic a real browser
	req.Header.Set("Host", host)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Origin", fmt.Sprintf("https://%s", host))
	req.Header.Set("Referer", fmt.Sprintf("https://%s/", host))

	return req, nil
}

// UnwrapFromHttpRequest extracts the base64 encoded data from the body of an HTTP request.
func UnwrapFromHttpRequest(r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	formData, err := url.ParseQuery(string(tbody))
	if err != nil {
		return nil, err
	}

	encodedData := formData.Get("q")
	if encodedData == "" {
		return nil, fmt.Errorf("form data 'q' not found in request")
	}

	return base64.URLEncoding.DecodeString(encodedData)
}

// DummyGoogleSearchHTML is a placeholder for a fake Google search results page.
const DummyGoogleSearchHTML = `<!DOCTYPE html><html lang="en"><head><title>Search Results</title></head><body><div id="web" style="display:none;">%s</div></body></html>`

// WrapInHttpResponse takes encrypted data and embeds it into a fake Google search results HTML page.
func WrapInHttpResponse(data []byte) *http.Response {
	htmlBody := fmt.Sprintf(DummyGoogleSearchHTML, base64.URLEncoding.EncodeToString(data))

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewBufferString(htmlBody)),
	}
	resp.Header.Set("Content-Type", "text/html; charset=utf-8")

	return resp
}

// UnwrapFromHttpResponse extracts data from the fake Google search results page.
func UnwrapFromHttpResponse(resp *http.Response) ([]byte, error) {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// A very simple and non-robust way to extract the data.
	// A real implementation should use a proper HTML parser.
	startTag := "<div id=\"web\" style=\"display:none;\">"
	endTag := "</div>"

	startIndex := strings.Index(string(tbody), startTag)
	if startIndex == -1 {
		return nil, fmt.Errorf("start tag not found in HTML response")
	}

	endIndex := strings.Index(string(tbody)[startIndex:], endTag)
	if endIndex == -1 {
		return nil, fmt.Errorf("end tag not found in HTML response")
	}

	encodedData := string(tbody)[startIndex+len(startTag) : startIndex+endIndex]
	return base64.URLEncoding.DecodeString(encodedData)
}
