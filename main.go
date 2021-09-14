package main

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/template"

	//"github.com/gorilla/mux"
	"go.uber.org/zap"
)

type (
	simpleResponse struct {
		code int
		body string
	}
	WSUSProxy struct {
		*zap.Logger
		Dumper
	}
)

var (
	internalError = simpleResponse{
		code: http.StatusInternalServerError,
		body: `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
    <s:Body>
        <s:Fault>
            <faultcode xmlns:a="http://schemas.microsoft.com/net/2005/12/windowscommunicationfoundation/dispatcher">a:InternalServiceFault</faultcode>
            <faultstring xml:lang="en-US">The server was unable to process the request due to an internal error.</faultstring>
        </s:Fault>
    </s:Body>
</s:Envelope>`,
	}
	reportingService = simpleResponse{
		code: http.StatusOK,
		body: `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema
-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
    <soap:Body>
        <ReportEventBatchResponse xmlns="http://www.microsoft.com/SoftwareDistribution">
            <ReportEventBatchResult>true</ReportEventBatchResult>
        </ReportEventBatchResponse>
    </soap:Body>
</soap:Envelope>`,
	}
)

func (s simpleResponse) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(s.code)
	w.Write([]byte(s.body))
}

func (p WSUSProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ts := getTimeStamp()
	log := p.Logger.Named(ts)
	dumper, err := p.Dumper.Inner(ts)
	if err != nil {
		log.Error("failed to create Dumper", zap.Error(err))
		panic(http.ErrAbortHandler)
	}
	log.Info(
		"new request",
		zap.String("proto", r.Proto),
		zap.String("method", r.Method),
		zap.Stringer("url", r.URL),
	)
	if err := dumper.Request(r, "request"); err != nil {
		log.Error(
			"failed to save request",
			zap.Error(err),
		)
		internalError.ServeHTTP(w, r)
		return
	}
	soapAction := r.Header.Get("HTTP_SOAPACTION")
	if soapAction == `"http://www.microsoft.com/SoftwareDistribution/ReportEventBatch"` {
		reportingService.ServeHTTP(w, r)
		return
	}

	//make new URL and contact upstream
	newurl := &url.URL{
		Scheme: "https",
		Host:   "fe2.update.microsoft.com",
		Path:   "/v6" + r.URL.Path,
	}
	log.Info(
		"URL rewrite",
		zap.Stringer("url", newurl),
	)
	transportDumper, err := dumper.Inner("upstream")
	if err != nil {
		log.Error("failed to create Dumper", zap.Error(err))
		internalError.ServeHTTP(w, r)
		return
	}
	httpTransport := RoundTripNestedDumper{
		Dumper: transportDumper,
		RoundTripper: &http.Transport{
			DialTLS: func(net, addr string) (net.Conn, error) {
				return tls.Dial(net, addr, &tls.Config{
					InsecureSkipVerify: true,
				})
			},
		},
	}
	httpClient := &http.Client{
		Transport: httpTransport,
	}
	req, err := http.NewRequest(r.Method, newurl.String(), r.Body)
	if err != nil {
		log.Error("failed to create request", zap.Error(err))
		internalError.ServeHTTP(w, r)
		return
	}
	if soapAction != "" {
		req.Header.Add("User-Agent", "Windows-Update-Agent")
		req.Header.Add("Content-Type", "text/xml; charset=utf-8")
		req.Header.Add("SOAPAction", soapAction)
	} else {
		for hdr, vals := range r.Header {
			for _, val := range vals {
				req.Header.Add(hdr, val)
			}
		}
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		log.Error("failed to contact upstream", zap.Error(err))
		internalError.ServeHTTP(w, r)
		return
	}
	//log and copy headers and status code
	for hdr, vals := range resp.Header {
		for _, val := range vals {
			w.Header().Set(hdr, val)
		}
	}
	w.WriteHeader(resp.StatusCode)
	if resp.Body != nil {
		io.Copy(w, resp.Body)
		resp.Body.Close()
	}
}

func loggingMiddleware(next http.Handler, log *zap.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Info(
			"request",
			zap.String("proto", r.Proto),
			zap.String("method", r.Method),
			zap.Stringer("url", r.URL),
		)
		next.ServeHTTP(w, r)
	})
}

func serveWSUSSettings(w http.ResponseWriter, r *http.Request) {
	localIP, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	tmplContent :=
		`reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v WUServer /t REG_SZ /d "http://{{.}}/wsus/" /f
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v WUStatusServer /t REG_SZ /d "http://{{.}}/wsus/" /f
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer /t REG_DWORD /d 1 /f
proxycfg -d
proxycfg -p http={{.}};https={{.}} "{{.}};<local>"
net stop wuauserv
net start wuauserv
`
	tmplContent = strings.Replace(tmplContent, "\n", "\r\n", -1)
	tmpl, err := template.New("").Parse(tmplContent)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Add("Content-Disposition", `attachment; filename="wsus.bat"`)
	err = tmpl.Execute(w, localIP.String())
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

}

func serveServerCertificate(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Disposition", `attachment; filename="server.crt"`)
	w.Header().Add("Content-Type", "application/octet-stream")

	f, err := os.Open("server.crt")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer f.Close()

	io.Copy(w, f)

}

func main() {

	logger, err := zap.NewDevelopment()
	if err != nil {
		panic(err)
	}
	defer logger.Sync()

	ts := getTimeStamp()
	dumper, err := NewDumper("./dump/", ts)
	if err != nil {
		panic(err)
	}
	logger.Info("session started", zap.String("name", ts))

	mitmDumper, err := dumper.Inner("mitm")
	if err != nil {
		panic(err)
	}
	wsusDumper, err := dumper.Inner("wsus")
	if err != nil {
		panic(err)
	}

	mitm := &MITMProxy{
		Logger: logger.Named("mitm"),
		Dumper: mitmDumper,
	}
	if err := mitm.loadCA("server.crt", "server.key"); err != nil {
		panic(err)
	}

	/*
		r := mux.NewRouter()
		r.PathPrefix("/wsus/").Handler(
			WSUSProxy{
				Logger: logger.Named("wsus"),
				Dumper: wsusDumper,
			},
		)
		r.PathPrefix("/").Handler(mitm)
	*/

	/*
		r := http.NewServeMux()
		r.Handle("/wsus/",
			http.StripPrefix("/wsus",
				WSUSProxy{
					Logger: logger.Named("wsus"),
					Dumper: wsusDumper,
				},
			),
		)
		r.Handle("/",
			mitm,
		)*/
	wsusHandler := http.StripPrefix("/wsus",
		WSUSProxy{
			Logger: logger.Named("wsus"),
			Dumper: wsusDumper,
		},
	)
	handler := func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/wsus/"):
			wsusHandler.ServeHTTP(w, r)
		case strings.HasPrefix(r.URL.Path, "/proxy-local/"):
			http.StripPrefix("/proxy-local",
				http.FileServer(
					http.Dir("./local/"))).ServeHTTP(w, r)
		case r.URL.Path == "/wsus.bat":
			serveWSUSSettings(w, r)
		case r.URL.Path == "/server.crt":
			serveServerCertificate(w, r)
		default:
			stripRangeFromURL(mitm, logger).ServeHTTP(w, r)
		}
	}

	err = http.ListenAndServe("0.0.0.0:10080", loggingMiddleware(http.HandlerFunc(handler), logger))
	if err != nil {
		panic(err)
	}
}
