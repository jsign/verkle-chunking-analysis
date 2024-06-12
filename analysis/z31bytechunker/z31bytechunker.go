package z31bytechunker

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/jsign/verkle-chunking-analysis/analysis"
)

type Chunker struct {
	accessEvents *state.AccessEvents

	codeChunks int
	gas        uint64
}

func New(contractAddr common.Address) *Chunker {
	ae := state.NewAccessEvents(nil)
	ae.AddTxDestination(contractAddr, false) // Warm account header.
	return &Chunker{accessEvents: ae}
}

func (c *Chunker) AccessPC(addr common.Address, pc uint64) error {
	gas := c.accessEvents.CodeChunksRangeGas(addr, uint64(pc), 1, 1, false)
	c.gas += gas
	if gas > 0 {
		c.codeChunks++
	}
	return nil
}

func (c *Chunker) GetReport() analysis.Report {
	return analysis.Report{NumCodeChunks: c.codeChunks, Gas: c.gas}
}
