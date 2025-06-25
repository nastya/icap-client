package icapclient

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

// Request represents the icap client request data
type Request struct {
	Method                string
	URL                   *url.URL
	Header                http.Header
	HTTPRequest           *http.Request
	HTTPResponse          *http.Response
	ChunkLength           int
	PreviewBytes          int
	ctx                   *context.Context
	previewSet            bool
	bodyFittedInPreview   bool
	remainingPreviewBytes []byte
}

// NewRequest is the factory function for Request
func NewRequest(method, urlStr string, httpReq *http.Request, httpResp *http.Response) (*Request, error) {

	method = strings.ToUpper(method)

	u, err := url.Parse(urlStr)

	if err != nil {
		return nil, err
	}

	var httpReqClone *http.Request
	if httpReq != nil {
		httpReqClone = httpReq.Clone(context.Background())
		filterHopByHop(httpReqClone.Header)
	}
	var httpRespClone *http.Response
	if httpResp != nil {
		httpRespCloneObj := *httpResp
		httpRespCloneObj.Header = httpResp.Header.Clone()
		httpRespCloneObj.Trailer = nil
		httpRespCloneObj.TransferEncoding = nil
		httpRespClone = &httpRespCloneObj
		filterHopByHop(httpRespClone.Header)
	}
	req := &Request{
		Method:       method,
		URL:          u,
		Header:       make(map[string][]string),
		HTTPRequest:  httpReqClone,
		HTTPResponse: httpRespClone,
	}

	if err := req.Validate(); err != nil {
		return nil, err
	}

	if httpReq != nil {
		if value, ok := httpReq.Header[ProxyAuthorizationHeader]; ok {
			req.Header[ProxyAuthorizationHeader] = value
		}
	}
	if httpResp != nil {
		if value, ok := httpResp.Header[ProxyAuthenticateHeader]; ok {
			req.Header[ProxyAuthenticateHeader] = value
		}
	}

	return req, nil
}

// DumpRequest returns the given request in its ICAP/1.x wire
// representation.
func DumpRequest(req *Request, setAbsoluteUrl bool) ([]byte, error) {

	// Making the ICAP message block

	reqStr := fmt.Sprintf("%s %s %s%s", req.Method, req.URL.String(), ICAPVersion, CRLF)

	for headerName, vals := range req.Header {
		for _, val := range vals {
			reqStr += fmt.Sprintf("%s: %s%s", headerName, val, CRLF)
		}
	}

	reqStr += "Encapsulated: %s" + CRLF // will populate the Encapsulated header value after making the http Request & Response messages
	reqStr += CRLF

	// Making the HTTP Request message block

	httpReqStr := ""
	if req.HTTPRequest != nil {
		b, err := httputil.DumpRequestOut(req.HTTPRequest, true)

		if err != nil {
			return nil, err
		}

		httpReqStr = string(b)
		headerStr, bodyStr := splitBodyAndHeader(httpReqStr)
		if setAbsoluteUrl {
			partsHttp := strings.SplitN(headerStr, "\n", 2)
			if len(partsHttp) < 1 {
				return []byte{}, fmt.Errorf("Failed to parse dumped HTTPRequest: %s", httpReqStr)
			}
			headerLineParts := strings.Split(partsHttp[0], " ")
			if len(headerLineParts) != 3 {
				return []byte{}, fmt.Errorf("Incorrect HTTP header line: %s", partsHttp[0])
			}
			newHeaderLine := headerLineParts[0] + " " + req.HTTPRequest.URL.String() + " " + headerLineParts[2]
			headerStr = newHeaderLine + "\n" + partsHttp[1]
		}

		if req.Method == MethodREQMOD {
			if req.previewSet && req.PreviewBytes < len(bodyStr) {
				bodyStr = bodyStr[:req.PreviewBytes]
			}

			if !bodyAlreadyChunked(bodyStr) {
				if bodyStr != "" || req.previewSet && req.PreviewBytes == 0 {
					addHexaBodyByteNotations(&bodyStr)
				}
			}

		} else { // In case of RESPMOD we send only header (see https://datatracker.ietf.org/doc/html/rfc3507#section-4.9.1)
			bodyStr = ""
		}
		mergeHeaderAndBody(&httpReqStr, headerStr, bodyStr)

		if httpReqStr != "" { // if the HTTP Request message block doesn't end with a \r\n\r\n, then going to add one by force for better calculation of byte offsets
			for !strings.HasSuffix(httpReqStr, DoubleCRLF) {
				httpReqStr = trimAllSuffixes(httpReqStr, CRLF)
				httpReqStr += DoubleCRLF
			}
		}

	}

	// Making the HTTP Response message block

	httpRespStr := ""
	if req.HTTPResponse != nil {
		b, err := httputil.DumpResponse(req.HTTPResponse, true)

		if err != nil {
			return nil, err
		}

		httpRespStr = string(b)
		headerStr, bodyStr := splitBodyAndHeader(httpRespStr)

		if req.previewSet && req.PreviewBytes < len(bodyStr) {
			bodyStr = bodyStr[:req.PreviewBytes]
		}

		if !bodyAlreadyChunked(bodyStr) {
			if bodyStr != "" || req.previewSet && req.PreviewBytes == 0 {
				addHexaBodyByteNotations(&bodyStr)
			}
		}
		mergeHeaderAndBody(&httpRespStr, headerStr, bodyStr)
		if httpRespStr != "" && !strings.HasSuffix(httpRespStr, DoubleCRLF) { // if the HTTP Response message block doesn't end with a \r\n\r\n, then going to add one by force for better calculation of byte offsets
			httpRespStr = trimAllSuffixes(httpRespStr, CRLF)
			httpRespStr += DoubleCRLF
		}
	}

	if encpVal := req.Header.Get(EncapsulatedHeader); encpVal != "" {
		reqStr = fmt.Sprintf(reqStr, encpVal) // TODO what is it for?
	} else {
		//populating the Encapsulated header of the ICAP message portion
		setEncapsulatedHeaderValue(&reqStr, httpReqStr, httpRespStr)
	}

	// determining if the http message needs the full body fitted in the preview portion indicator or not
	if httpRespStr != "" && req.previewSet && req.bodyFittedInPreview {
		addFullBodyInPreviewIndicator(&httpRespStr)
	}

	if req.Method == MethodREQMOD && req.previewSet && req.bodyFittedInPreview {
		addFullBodyInPreviewIndicator(&httpReqStr)
	}

	data := []byte(reqStr + httpReqStr + httpRespStr)

	return data, nil
}

// SetContext sets a context for the ICAP request
func (r *Request) SetContext(ctx context.Context) { // TODO: make context take control over the whole operation
	r.ctx = &ctx
}
