// The module path is under Go Coraza's `internal/` on purpose: Go lets only packages
// below `github.com/corazawaf/coraza/v3/` import its internal body processor.
module github.com/corazawaf/coraza/v3/internal/multipartfixture

go 1.27.3

require github.com/corazawaf/coraza/v3 v3.8.2-0.20261114225743-1cfa4f955a19

require (
	github.com/tidwall/gjson v1.18.0 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	github.com/valllabh/ocsf-schema-golang v1.0.3 // indirect
	golang.org/x/sync v0.24.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)
