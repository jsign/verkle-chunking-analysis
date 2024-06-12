package z31bytechunker

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/jsign/verkle-chunking-analysis/analysis"
)

type Chunker struct {
	accessEvents *state.AccessWitness

	gas uint64
}

func New(touchedContracts []common.Address) *Chunker {
	ae := state.NewAccessWitness(nil)

	// The touched contracts are the tx destination, or contracts that are called by the tx.
	// In any case, we warm those accounts headers since tx destination or *CALL targets will
	// access the account header branch for at least CodeSize reasons.
	for _, addr := range touchedContracts {
		ae.TouchTxExistingAndComputeGas(addr.Bytes(), false)
	}

	return &Chunker{accessEvents: ae}
}

func (c *Chunker) AccessPC(addr common.Address, pc uint64) error {
	gas := c.accessEvents.TouchCodeChunksRangeAndChargeGas(addr.Bytes(), uint64(pc), 1, 1, false)
	c.gas += gas
	return nil
}

func (c *Chunker) GetReport() analysis.Report {
	return analysis.Report{Gas: c.gas}
}
