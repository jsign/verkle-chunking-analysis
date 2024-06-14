package z31bytechunker

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/jsign/verkle-chunking-analysis/analysis"
)

type Chunker struct {
	accessEvents *state.AccessWitness

	chunkedSizes map[common.Address]int
	gas          uint64
}

func New(touchedContracts []common.Address, contractBytecodes map[common.Address][]byte) (*Chunker, error) {
	ae := state.NewAccessWitness(nil)

	chunkedSizes := map[common.Address]int{}
	for _, addr := range touchedContracts {
		// The touched contracts are the tx destination, or contracts that are called by the tx.
		// In any case, we warm those accounts headers since tx destination or *CALL targets will
		// access the account header branch for at least CodeSize reasons.
		ae.TouchTxExistingAndComputeGas(addr.Bytes(), false)

		contractCode, ok := contractBytecodes[addr]
		if !ok {
			return nil, fmt.Errorf("contract %v not found in contractBytecodes", addr)
		}
		chunkedSizes[addr] = len(trie.ChunkifyCode(contractCode))
	}

	return &Chunker{accessEvents: ae, chunkedSizes: chunkedSizes}, nil
}

func (c *Chunker) AccessPC(addr common.Address, pc uint64) error {
	gas := c.accessEvents.TouchCodeChunksRangeAndChargeGas(addr.Bytes(), uint64(pc), 1, 1, false)
	c.gas += gas
	return nil
}

func (c *Chunker) GetReport() analysis.ChunkerMetrics {
	return analysis.ChunkerMetrics{ChunkerName: "31bytechunker", ContractsChunkedSize: c.chunkedSizes, Gas: c.gas}
}
