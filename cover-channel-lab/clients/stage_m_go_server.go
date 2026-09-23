package main

import (
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

func responseSize(path string) int {
	switch {
	case strings.HasPrefix(path, "/api/detail"):
		return 4096
	case strings.HasPrefix(path, "/api/upload"):
		return 96
	case strings.HasPrefix(path, "/public/"):
		return 192
	default:
		return 512
	}
}

func handler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok":true}`)
		return
	}
	if r.URL.Path == "/api/unavailable" {
		http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	if r.URL.Path == "/dns-query" {
		var b []byte
		if r.Method == "GET" {
			token := r.URL.Query().Get("dns")
			token += strings.Repeat("=", (4-len(token)%4)%4)
			b, _ = base64.URLEncoding.DecodeString(token)
		} else {
			b, _ = io.ReadAll(io.LimitReader(r.Body, 65536))
		}
		if len(b) == 0 {
			b = []byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(b)
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 65536))
	n := responseSize(r.URL.Path)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprint(n))
	w.WriteHeader(200)
	w.Write([]byte(strings.Repeat("R", n)))
}

func main() {
	host := flag.String("host", "10.20.0.20", "")
	httpPort := flag.Int("http-port", 9080, "")
	httpsPort := flag.Int("https-port", 9444, "")
	cert := flag.String("cert", "", "")
	key := flag.String("key", "", "")
	flag.Parse()
	mux := http.NewServeMux()
	mux.HandleFunc("/", handler)
	plain := &http.Server{Addr: fmt.Sprintf("%s:%d", *host, *httpPort), Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := plain.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()
	pair, err := tls.LoadX509KeyPair(*cert, *key)
	if err != nil {
		log.Fatal(err)
	}
	tlsSrv := &http.Server{Addr: fmt.Sprintf("%s:%d", *host, *httpsPort), Handler: mux, ReadHeaderTimeout: 5 * time.Second, TLSConfig: &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}}
	if err := tlsSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
