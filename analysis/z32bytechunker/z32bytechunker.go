package z32bytechunker

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/holiman/uint256"
	"github.com/jsign/verkle-chunking-analysis/analysis"
)

type Chunker struct {
	contractBytecodes map[common.Address][]byte
	aw                *state.AccessWitness

	gas             uint64
	chunkedSizes    map[common.Address]int
	contractPCShift map[common.Address]int
}

func New() *Chunker {
	return &Chunker{}
}

func (c *Chunker) Init(touchedContracts []common.Address, contractBytecodes map[common.Address][]byte, _ bool) error {
	*c = Chunker{
		aw:                state.NewAccessWitness(nil),
		chunkedSizes:      map[common.Address]int{},
		contractPCShift:   map[common.Address]int{},
		contractBytecodes: contractBytecodes,
	}
	for _, addr := range touchedContracts {
		// The touched contracts are the tx destination, or contracts that are called by the tx.
		// In any case, we warm those accounts headers since tx destination or *CALL targets will
		// access the account header branch for at least CodeSize reasons.
		c.aw.TouchTxExistingAndComputeGas(addr.Bytes(), false)

		// Generate JUMPDEST table and place it at the start in the account header, and calculate the shift for the
		// rest of contract bytecodes for later `pc` mappings.
		table := chunkifyCodeInvalidJumpdests(contractBytecodes[addr])
		var buf [3]byte
		tableSizeEncoded := leb128Encode(buf[:], len(table))
		totalTableSize := tableSizeEncoded + len(table)
		c.gas += c.aw.TouchCodeChunksRangeAndChargeGas(addr.Bytes(), 0, uint64(totalTableSize), uint64(totalTableSize), false)
		c.contractPCShift[addr] = totalTableSize

		// Record contract chunked size, aligned to 32-bytes.
		c.chunkedSizes[addr] = totalTableSize + len(contractBytecodes[addr])
		if c.chunkedSizes[addr]%32 != 0 {
			c.chunkedSizes[addr] += 32 - c.chunkedSizes[addr]%32
		}
	}
	return nil
}

func (c *Chunker) AccessPC(addr common.Address, pc uint64) error {
	gas := c.touchCodeChunksRangeAndChargeGas(c.aw, addr.Bytes(), pc, 1, uint64(len(c.contractBytecodes[addr])), false)
	c.gas += gas
	return nil
}

func (c *Chunker) GetReport() analysis.ChunkerMetrics {
	contractStats := make(map[common.Address]analysis.ContractStats)
	for addr, size := range c.chunkedSizes {
		contractStats[addr] = analysis.ContractStats{
			ChunkedSizeBytes: size,
		}
	}
	return analysis.ChunkerMetrics{
		ChunkerName:    "32bytechunker",
		Gas:            c.gas,
		ContractsStats: contractStats,
	}
}

func (c *Chunker) touchCodeChunksRangeAndChargeGas(aw *state.AccessWitness, contractAddr []byte, startPC, size uint64, codeLen uint64, isWrite bool) uint64 {
	if (codeLen == 0 && size == 0) || startPC > codeLen {
		return 0
	}

	endPC := startPC + size
	if endPC > codeLen {
		endPC = codeLen
	}
	if endPC > 0 {
		endPC -= 1 // endPC is the last bytecode that will be touched.
	}

	shift := uint64(c.contractPCShift[common.BytesToAddress(contractAddr)])
	startPC += shift
	endPC += shift

	var statelessGasCharged uint64
	for chunkNumber := startPC / 32; chunkNumber <= endPC/32; chunkNumber++ {
		treeIndex := *uint256.NewInt((chunkNumber + 128) / 256)
		subIndex := byte((chunkNumber + 128) % 256)
		gas := aw.TouchAddressAndChargeGas(contractAddr, treeIndex, subIndex, isWrite)
		var overflow bool
		statelessGasCharged, overflow = math.SafeAdd(statelessGasCharged, gas)
		if overflow {
			panic("overflow when adding gas")
		}
	}

	return statelessGasCharged
}

const (
	PUSH1    = byte(0x60)
	PUSH32   = byte(0x7f)
	JUMPDEST = byte(0x5b)
)

type TableInvalidJumpdestEncoder struct {
	table         []byte
	lastCodeChunk int

	// used to do leb128 encoding without allocations
	buf [3]byte
}

func NewTableInvalidJumpdestEncoder() TableInvalidJumpdestEncoder {
	return TableInvalidJumpdestEncoder{
		table: make([]byte, 0, 32),
	}
}

func (enc *TableInvalidJumpdestEncoder) append(codeChunk int, firstValidInstructionOffset int) {
	delta := codeChunk - enc.lastCodeChunk
	e := delta*33 + firstValidInstructionOffset
	size := leb128Encode(enc.buf[:], e)
	enc.table = append(enc.table, enc.buf[:size]...)
	enc.lastCodeChunk = codeChunk
}

func (enc *TableInvalidJumpdestEncoder) encodedTable() []byte {
	return enc.table
}

// chunkifyCodeInvalidJumpdests returns the table of invalid jumpdests in the code.
// Note that the actual code-chunking is always a 32-byte slicing of the original code.
func chunkifyCodeInvalidJumpdests(code []byte) []byte {
	encoder := NewTableInvalidJumpdestEncoder()

	var addedEntry bool
	var validOffset int
	for i := 0; i < len(code); {
		if i%32 == 0 {
			validOffset = 0
			addedEntry = false
		}
		if code[i] < PUSH1 || code[i] > PUSH32 {
			i++
			continue
		}
		pushDataEnd := i + int(code[i]-PUSH1+1)
		i += 1
		for i <= pushDataEnd && i < len(code) {
			if i%32 == 0 {
				validOffset = pushDataEnd%32 + 1
				addedEntry = false
			}
			if code[i] == JUMPDEST && !addedEntry {
				encoder.append(i/32, validOffset)
				addedEntry = true
				i = min(i/32*32+32, pushDataEnd+1)
			} else {
				i++
			}
		}
	}
	return encoder.encodedTable()
}

func leb128Encode(buf []byte, value int) int {
	if value == 0 {
		buf[0] = 0
		return 1
	}
	var i int
	for value != 0 {
		part := byte(value & 0x7f)
		value >>= 7
		if value != 0 {
			part |= 0x80
		}
		buf[i] = part
		i++
	}
	return i
}
