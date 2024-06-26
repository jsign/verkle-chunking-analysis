package z31bytechunker

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/jsign/verkle-chunking-analysis/analysis"
)

type Chunker struct {
	contractBytecodes map[common.Address][]byte
	accessEvents      *state.AccessWitness
	enableChunksStats bool

	gas            uint64
	contractsStats map[common.Address]contractStats
}

type contractStats struct {
	chunkedSizeBytes int
	chunksStats      map[int]chunkStats
}
type chunkStats struct {
	accessedBytesBitset uint32
	chargedGas          uint64
}

func New() *Chunker {
	return &Chunker{}
}

func (c *Chunker) Init(touchedContracts []common.Address, contractBytecodes map[common.Address][]byte, enableChunksStats bool) error {
	accessEvents := state.NewAccessWitness(nil)
	contractsStats := map[common.Address]contractStats{}
	for _, addr := range touchedContracts {
		// The touched contracts are the tx destination, or contracts that are called by the tx.
		// In any case, we warm those accounts headers since tx destination or *CALL targets will
		// access the account header branch for at least CodeSize reasons.
		accessEvents.TouchTxExistingAndComputeGas(addr.Bytes(), false)

		contractCode, ok := contractBytecodes[addr]
		if !ok {
			return fmt.Errorf("contract %v not found in contractBytecodes", addr)
		}

		cs := contractsStats[addr]
		cs.chunkedSizeBytes = len(trie.ChunkifyCode(contractCode))
		cs.chunksStats = map[int]chunkStats{}
		contractsStats[addr] = cs
	}
	*c = Chunker{
		contractBytecodes: contractBytecodes,
		accessEvents:      accessEvents,
		contractsStats:    contractsStats,
		enableChunksStats: enableChunksStats,
	}

	return nil
}

func (c *Chunker) AccessPC(addr common.Address, pc uint64) error {
	chargedGas := c.accessEvents.TouchCodeChunksRangeAndChargeGas(addr.Bytes(), pc, 1, uint64(len(c.contractBytecodes[addr])), false)
	c.gas += chargedGas

	if !c.enableChunksStats {
		return nil
	}

	chunkNumber := int(pc / 31)
	chunkStats := c.contractsStats[addr].chunksStats[chunkNumber]
	chunkStats.accessedBytesBitset |= 1                // Consider the first byte of the chunk (PUSHN byte) always accessed.
	chunkStats.accessedBytesBitset |= 1 << (pc%31 + 1) // Mark the accessed byte in the bitset.

	if chargedGas > 0 {
		if chunkStats.chargedGas > 0 {
			return fmt.Errorf("gas already charged for chunk %d, newly charged gas must be 0", chunkNumber)
		}
		chunkStats.chargedGas = chargedGas
	}
	c.contractsStats[addr].chunksStats[chunkNumber] = chunkStats

	return nil
}

func (c *Chunker) GetReport() analysis.ChunkerMetrics {
	contractsStats := make(map[common.Address]analysis.ContractStats, len(c.contractsStats))
	for addr, stats := range c.contractsStats {
		chunksStats := make([]analysis.ChunkStats, 0, len(stats.chunksStats))
		for chunkNumber, chstats := range stats.chunksStats {
			var accessedBytes int
			for i := 0; i < 31; i++ {
				if chstats.accessedBytesBitset&(1<<i) != 0 {
					accessedBytes++
				}
			}
			chunksStats = append(chunksStats, analysis.ChunkStats{
				ChunkNumber:   chunkNumber,
				AccessedBytes: accessedBytes,
				ChargedGas:    chstats.chargedGas,
			})
		}

		contractsStats[addr] = analysis.ContractStats{
			ChunkedSizeBytes: stats.chunkedSizeBytes,
			ChunksStats:      chunksStats,
		}
	}
	return analysis.ChunkerMetrics{
		ChunkerName:    "31bytechunker",
		Gas:            c.gas,
		ContractsStats: contractsStats,
	}
}
