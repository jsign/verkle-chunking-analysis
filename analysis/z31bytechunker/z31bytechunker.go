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
	chunkedSizes      map[common.Address]int
	gas               uint64
}

func New() *Chunker {
	return &Chunker{}
}

func (c *Chunker) Init(touchedContracts []common.Address, contractBytecodes map[common.Address][]byte) error {
	*c = Chunker{
		contractBytecodes: contractBytecodes,
		accessEvents:      state.NewAccessWitness(nil),
		chunkedSizes:      map[common.Address]int{},
	}
	for _, addr := range touchedContracts {
		// The touched contracts are the tx destination, or contracts that are called by the tx.
		// In any case, we warm those accounts headers since tx destination or *CALL targets will
		// access the account header branch for at least CodeSize reasons.
		c.accessEvents.TouchTxExistingAndComputeGas(addr.Bytes(), false)

		contractCode, ok := contractBytecodes[addr]
		if !ok {
			return fmt.Errorf("contract %v not found in contractBytecodes", addr)
		}
		c.chunkedSizes[addr] = len(trie.ChunkifyCode(contractCode))
	}
	return nil
}

func (c *Chunker) AccessPC(addr common.Address, pc uint64) error {
	c.gas += c.accessEvents.TouchCodeChunksRangeAndChargeGas(addr.Bytes(), pc, 1, uint64(len(c.contractBytecodes[addr])), false)
	return nil
}

func (c *Chunker) GetReport() analysis.ChunkerMetrics {
	return analysis.ChunkerMetrics{ChunkerName: "31bytechunker", ContractsChunkedSize: c.chunkedSizes, Gas: c.gas}
}
