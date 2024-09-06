module github.com/bitcoinschema/go-sigma

go 1.22

toolchain go1.22.5

require (
	github.com/bitcoin-sv/go-sdk v1.1.4
	github.com/bitcoinschema/go-bpu v0.1.3
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rogpeppe/go-internal v1.11.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

require (
	github.com/pkg/errors v0.9.1 // indirect
	github.com/stretchr/testify v1.9.0
	golang.org/x/crypto v0.21.0 // indirect
)

replace github.com/bitcoin-sv/go-sdk => ../../go-sdk

replace github.com/bitcoinschema/go-bpu => ../go-bpu
