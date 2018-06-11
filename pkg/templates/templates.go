package templates

//go get github.com/go-bindata/go-bindata/go-bindata
//go:generate go-bindata -nometadata -pkg $GOPACKAGE data/...
//go:generate gofmt -s -l -w bindata.go
