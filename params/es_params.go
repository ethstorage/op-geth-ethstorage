package params

const (
	EsGetBlobPerWordGas uint64 = 3     // Per-word price for an esGetBlob operation.
	EsGetBlobBaseGas    uint64 = 50000 // Base price for an esGetBlob operation.
)

var (
	EsNodeURL = "http://localhost:9545"
)
