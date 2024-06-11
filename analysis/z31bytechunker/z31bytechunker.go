package z31bytechunker

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/jsign/verkle-chunking-analysis/analysis"
)

type Chunker struct {
	accessEvents *state.AccessEvents

	codeChunks int
}

func New() *Chunker {
	return &Chunker{accessEvents: state.NewAccessEvents(nil)}
}

func (c *Chunker) AccessPC(addr common.Address, pc uint64) error {
	gas := c.accessEvents.CodeChunksRangeGas(addr, uint64(pc), 1, 1, false)
	if gas > 0 {
		c.codeChunks++
	}
	return nil
}

func (c *Chunker) GetReport() analysis.Report {
	return analysis.Report{NumCodeChunks: c.codeChunks}
}
