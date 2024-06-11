package analysis

import "github.com/ethereum/go-ethereum/common"

type Report struct {
	NumCodeChunks int
}

type Chunker interface {
	AccessPC(common.Address, uint64) error
	GetReport() Report
}
