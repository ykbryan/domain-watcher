package handlers

import (
	_ "embed"
	"net/http"
)

//go:embed openapi.yaml
var openapiSpec []byte

// ServeOpenAPI returns an http.HandlerFunc that emits the embedded
// openapi.yaml. The spec lives next to the handler so it ships with
// the binary and stays in version control alongside the code.
func ServeOpenAPI() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_, _ = w.Write(openapiSpec)
	}
}
