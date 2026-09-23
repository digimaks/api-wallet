// SPDX-License-Identifier: EUPL-1.2

package wallet

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/digimaks/api-wallet/routes/request"
	"github.com/digimaks/api-wallet/routes/response"

	"azugo.io/azugo"
	"azugo.io/core/cache"
	"azugo.io/core/http"
	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/valyala/bytebufferpool"
	"github.com/valyala/fasthttp"
)

const sscCache = "digimaks-wallet-api-ssc"

var strContentTypeJSON = []byte("application/json")

type CacheProvider interface {
	Cache() *cache.Cache
}

type SimpleSignClient struct {
	url        string
	urlPublic  string
	apiKey     string
	ch         cache.Instance[string]
	mu         sync.RWMutex
	bufferPool bytebufferpool.Pool
}

func NewSimpleSignClient(app CacheProvider, url string, urlPublic string, apiKey string, signingTTL time.Duration) (*SimpleSignClient, error) {
	ssc := &SimpleSignClient{
		url:       url,
		urlPublic: urlPublic,
		apiKey:    apiKey,
	}

	var err error

	ssc.ch, err = cache.Create[string](app.Cache(), sscCache, cache.DefaultTTL(signingTTL))
	if err != nil {
		return nil, err
	}

	return ssc, nil
}

func (ssc *SimpleSignClient) Prepare(ctx *azugo.Context, reqJSON *request.EparakstsSignRequest, file *multipart.FileHeader, signType string) (*response.EparakstsSignResponse, error) {
	var (
		reqType, endpoint string
		createNewDoc      bool
	)

	if reqJSON.Asice {
		reqType = "hash"
		createNewDoc = false
	} else {
		reqType = "pdf"
	}

	prepareReq := &request.SimpleSignPrepareRequest{
		Requests: []request.SimpleSignRequest{
			{
				RequestID: reqJSON.RequestID,
				Type:      reqType,
				Files: []request.SimpleSignFile{
					{
						FileName: reqJSON.FileName,
					},
				},
			},
		},
		RedirectURL:   reqJSON.RedirectURL,
		RedirectError: reqJSON.RedirectError,
		ESealSID:      reqJSON.ESealSID,
		UserID:        reqJSON.UserID,
		CreateNewDoc:  createNewDoc,
		CrossDevice:   reqJSON.CrossDevice,
	}

	jsonBytes, err := json.Marshal(prepareReq)
	if err != nil {
		return nil, err
	}

	reqForm := multipart.Form{
		Value: map[string][]string{
			"json": {string(jsonBytes)},
		},
		File: map[string][]*multipart.FileHeader{
			reqJSON.FileName: {file},
		},
	}

	switch signType {
	case "sign":
		endpoint = "preparelarge"
	case "eseal":
		endpoint = "eseal"
	default:
		return nil, azugo.ParamInvalidError{Name: "type", Tag: "invalid"}
	}

	targetURL, err := url.JoinPath(ssc.url, "v2.0/mobile", endpoint)
	if err != nil {
		return nil, err
	}

	resByte, err := ssc.PostMultipartForm(ctx, targetURL, &reqForm)
	if err != nil {
		return nil, err
	}

	res := &response.EparakstsSignResponse{}

	err = json.Unmarshal(resByte, res)
	if err != nil {
		return nil, err
	}

	return res, nil
}

func (ssc *SimpleSignClient) GetFile(ctx *azugo.Context, sessionID string) ([]byte, string, string, error) {
	baseURL, err := url.JoinPath(ssc.url, "v2.0/file/get")
	if err != nil {
		return nil, "", "", err
	}

	targetURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, "", "", err
	}

	query := targetURL.Query()
	query.Set("sessionId", sessionID)

	targetURL.RawQuery = query.Encode()

	client := ctx.HTTPClient()
	req := client.NewRequest()

	defer client.ReleaseRequest(req)

	err = req.SetRequestURL(targetURL.String())
	if err != nil {
		return nil, "", "", err
	}

	req.Header.SetMethod(fasthttp.MethodGet)
	req.Header.Set("ApiKey", ssc.apiKey)

	resp := client.NewResponse()
	defer client.ReleaseResponse(resp)

	err = client.Do(req, resp)
	if err != nil {
		return nil, "", "", err
	}

	if resp.StatusCode() != fasthttp.StatusOK {
		return nil, "", "", fmt.Errorf("error retrieving file, status code: %d", resp.StatusCode())
	}

	file := resp.Body()
	contentType := string(resp.Header.Peek(fasthttp.HeaderContentType))
	contentDisposition := string(resp.Header.Peek(fasthttp.HeaderContentDisposition))

	return file, contentType, contentDisposition, nil
}

func (ssc *SimpleSignClient) ValidateFile(ctx *azugo.Context, reqJSON *request.ValidateRequest, file *multipart.FileHeader) ([]byte, error) {
	targetURL, err := url.JoinPath(ssc.url, "v2.0/file/validate")
	if err != nil {
		return nil, err
	}

	jsonBytes, err := json.Marshal(reqJSON)
	if err != nil {
		return nil, err
	}

	// validate pdf if it has any signatures
	if err = ValidatePDF(ctx, file, reqJSON.Files[0].FileName); err != nil {
		return nil, err
	}

	reqForm := multipart.Form{
		Value: map[string][]string{
			"json": {string(jsonBytes)},
		},
		File: map[string][]*multipart.FileHeader{
			reqJSON.Files[0].FileName: {file},
		},
	}

	resByte, err := ssc.PostMultipartForm(ctx, targetURL, &reqForm)
	if err != nil {
		return nil, err
	}

	return resByte, nil
}

func (ssc *SimpleSignClient) GetIdentitiesRedirect(redirectURL *string, crossDevice *string) (*response.EparakstsSignRedirectResponse, error) {
	baseURL, err := url.JoinPath(ssc.urlPublic, "v2/mobile/identities")
	if err != nil {
		return nil, err
	}

	targetURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}

	query := targetURL.Query()
	query.Set("type", "all")

	if redirectURL != nil {
		query.Set("redirecturl", *redirectURL)
	}

	if crossDevice != nil {
		query.Set("crossdevice", *crossDevice)
	}

	targetURL.RawQuery = query.Encode()

	return &response.EparakstsSignRedirectResponse{
		RedirectURL: targetURL.String(),
	}, nil
}

func (ssc *SimpleSignClient) GetIdentities(ctx *azugo.Context, ulid string) ([]byte, error) {
	targetURL, err := url.JoinPath(ssc.url, "v2/mobile/identities", ulid)
	if err != nil {
		return nil, err
	}

	resp, err := ctx.HTTPClient().Get(targetURL, http.WithHeader("ApiKey", ssc.apiKey))
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (ssc *SimpleSignClient) CloseSession(ctx *azugo.Context, sessionID string) error {
	targetURL, err := url.JoinPath(ssc.url, "v2.0/file/close")
	if err != nil {
		return err
	}

	payload, err := json.Marshal([]string{sessionID})
	if err != nil {
		return err
	}

	client := ctx.HTTPClient()
	req := client.NewRequest()

	defer client.ReleaseRequest(req)

	err = req.SetRequestURL(targetURL)
	if err != nil {
		return err
	}

	req.SetBody(payload)
	req.Header.SetMethod(fasthttp.MethodPost)
	req.Header.Set("ApiKey", ssc.apiKey)
	req.Header.Set(fasthttp.HeaderContentType, "application/json")

	resp := client.NewResponse()
	defer client.ReleaseResponse(resp)

	err = client.Do(req, resp)
	if err != nil {
		return err
	}

	if resp.StatusCode() != fasthttp.StatusOK {
		return fmt.Errorf("error closing session, status code: %d", resp.StatusCode())
	}

	return nil
}

func (ssc *SimpleSignClient) CacheSetSessionID(ctx *azugo.Context, requestID string, sessionID string) error {
	ssc.mu.Lock()
	defer ssc.mu.Unlock()

	cacheKey := requestID

	if err := ssc.ch.Set(ctx, cacheKey, sessionID); err != nil {
		return err
	}

	return nil
}

func (ssc *SimpleSignClient) CacheGetSessionID(ctx *azugo.Context, requestID string) (*string, error) {
	ssc.mu.RLock()
	defer ssc.mu.RUnlock()

	cacheKey := requestID

	value, err := ssc.ch.Get(ctx, cacheKey)
	if err != nil {
		return nil, err
	}

	return &value, nil
}

func (ssc *SimpleSignClient) CacheDeleteSessionID(ctx *azugo.Context, requestID string) error {
	ssc.mu.Lock()
	defer ssc.mu.Unlock()

	cacheKey := requestID

	err := ssc.ch.Delete(ctx, cacheKey)
	if err != nil {
		return err
	}

	return nil
}

func ValidatePDF(ctx *azugo.Context, file *multipart.FileHeader, fileName string) error {
	// don't validate if file is not pdf
	if !strings.HasSuffix(strings.ToLower(fileName), ".pdf") {
		return nil
	}

	src, err := file.Open()
	if err != nil {
		return fmt.Errorf("unable to open uploaded file: %w", err)
	}

	defer func() { _ = src.Close() }()

	api.DisableConfigDir()

	pdfInfo, err := api.PDFInfo(src, strings.ToLower(fileName), nil, false, nil)
	if err != nil {
		return azugo.BadRequestError{
			Description: "invalid pdf file",
			Err:         nil,
		}
	} else if pdfInfo != nil {
		isSigned := pdfInfo.Signatures

		if !isSigned {
			ctx.Log().Debug("Provided file " + fileName + " does not contain any signatures")
			// Log the message
			return azugo.BadRequestError{
				Description: "missing signature",
				Err:         nil,
			}
		}
	}

	return nil
}

// For handling simple sign errors

// PostMultipartForm performs a POST request to the specified URL with the specified multipart form values and files.
func (ssc *SimpleSignClient) PostMultipartForm(ctx *azugo.Context, url string, form *multipart.Form) ([]byte, error) {
	c := ctx.HTTPClient()
	req := c.NewRequest()
	req.Header.SetMethod(fasthttp.MethodPost)

	if err := req.SetRequestURL(url); err != nil {
		return nil, err
	}

	req.Header.Set("ApiKey", ssc.apiKey)

	var bbuf [30]byte
	if _, err := io.ReadFull(rand.Reader, bbuf[:]); err != nil {
		return nil, err
	}

	boundary := hex.EncodeToString(bbuf[:])

	req.Header.SetMultipartFormBoundary(boundary)

	buf := ssc.bufferPool.Get()
	if err := fasthttp.WriteMultipartForm(buf, form, boundary); err != nil {
		ssc.bufferPool.Put(buf)

		return nil, err
	}

	req.SetBodyRaw(buf.Bytes())
	ssc.bufferPool.Put(buf)

	resp := c.NewResponse()
	defer c.ReleaseResponse(resp)

	err := c.Do(req, resp)
	c.ReleaseRequest(req)

	if err != nil {
		return nil, err
	}

	// error handling should be custom
	if err := Error(resp); err != nil {
		return nil, err
	}

	body, err := resp.BodyUncompressed()
	if err != nil {
		return nil, err
	}

	return body, nil
}

type SimpleSignErrorResponse struct {
	Error struct {
		ID      string        `json:"id"`
		Code    string        `json:"code"`
		Message string        `json:"message"`
		Details []interface{} `json:"details"`
	} `json:"error"`
}

// Error if the response status code is not 2xx.
func Error(r *http.Response) error {
	if r.Success() {
		return nil
	}

	switch r.StatusCode() {
	case fasthttp.StatusForbidden:
		return http.ForbiddenError{}
	case fasthttp.StatusNotFound:
		return http.NotFoundError{}
	case fasthttp.StatusUnauthorized:
		return http.UnauthorizedError{}
	default:
		body, _ := r.BodyUncompressed()
		if len(body) > 0 && bytes.Equal(r.Header.ContentType(), strContentTypeJSON) {
			e := SimpleSignErrorResponse{}
			if err := json.Unmarshal(body, &e); err == nil && len(e.Error.ID) > 0 {
				if r.StatusCode() == fasthttp.StatusBadRequest {
					return azugo.BadRequestError{
						Description: fmt.Sprintf("error %s: %s", e.Error.Code, e.Error.Message),
						Err:         nil,
					}
				}

				return fmt.Errorf("error %s: %s", e.Error.Code, e.Error.Message)
			}
		}

		bodyLen := len(body)
		if bodyLen > 0 {
			if bodyLen > 100 {
				bodyLen = 100
			}

			body = append([]byte(": "), body[:bodyLen]...)
		}

		return fmt.Errorf("unexpected response status %d%s", r.StatusCode(), body)
	}
}
