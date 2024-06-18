package analysis

import "github.com/ethereum/go-ethereum/common"

type ChunkerMetrics struct {
	ChunkerName          string
	Gas                  uint64
	ContractsChunkedSize map[common.Address]int
}

type Chunker interface {
	Init([]common.Address, map[common.Address][]byte) error
	AccessPC(common.Address, uint64) error
	GetReport() ChunkerMetrics
}
