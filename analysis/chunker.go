package analysis

import "github.com/ethereum/go-ethereum/common"

type ChunkerMetrics struct {
	ChunkerName    string
	Gas            uint64
	ContractsStats map[common.Address]ContractStats
}

type ContractStats struct {
	ChunkedSizeBytes int
	ChunksStats      []ChunkStats
}

type ChunkStats struct {
	ChunkNumber   int
	AccessedBytes int
	ChargedGas    uint64
}

type Chunker interface {
	Init([]common.Address, map[common.Address][]byte, bool) error
	AccessPC(common.Address, uint64) error
	GetReport() ChunkerMetrics
}
