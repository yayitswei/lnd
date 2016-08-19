package portxo

import (
	"bytes"

	"github.com/roasbeef/btcd/wire"
)

// txoSliceByBip69 is a sortable txo slice - same algo as txsort / BIP69
type TxoSliceByBip69 []PorTxo

// Sort utxos just like txins -- Len, Less, Swap
func (s TxoSliceByBip69) Len() int      { return len(s) }
func (s TxoSliceByBip69) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

// outpoint sort; First input hash (reversed / rpc-style), then index.
func (s TxoSliceByBip69) Less(i, j int) bool {
	// Input hashes are the same, so compare the index.
	ihash := s[i].Op.Hash
	jhash := s[j].Op.Hash
	if ihash == jhash {
		return s[i].Op.Index < s[j].Op.Index
	}
	// At this point, the hashes are not equal, so reverse them to
	// big-endian and return the result of the comparison.
	const hashSize = wire.HashSize
	for b := 0; b < hashSize/2; b++ {
		ihash[b], ihash[hashSize-1-b] = ihash[hashSize-1-b], ihash[b]
		jhash[b], jhash[hashSize-1-b] = jhash[hashSize-1-b], jhash[b]
	}
	return bytes.Compare(ihash[:], jhash[:]) == -1
}

// txoSliceByAmt is a sortable txo slice.  Sorts by value, and puts unconfirmed last.
type TxoSliceByAmt []*PorTxo

func (s TxoSliceByAmt) Len() int      { return len(s) }
func (s TxoSliceByAmt) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

// height 0 means you are lesser
func (s TxoSliceByAmt) Less(i, j int) bool {
	if s[i].Height == 0 && s[j].Height > 0 {
		return true
	}
	if s[j].Height == 0 && s[i].Height > 0 {
		return false
	}
	return s[i].Value < s[j].Value
}
