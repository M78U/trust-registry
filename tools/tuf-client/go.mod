module github.com/M78U/trust-registry/tools/tuf-client

go 1.26.0

require (
	github.com/M78U/trust-registry v0.0.0
	github.com/theupdateframework/go-tuf/v2 v2.4.2
	github.com/sigstore/sigstore v1.10.6
)

replace github.com/M78U/trust-registry => ../..
