package sorceror

import (
	"fmt"

	"github.com/lightningnetwork/lnd/elkrem"
	"github.com/lightningnetwork/lnd/uspv"
	"github.com/roasbeef/btcd/wire"
)

// SorcedChan is data sufficient to monitor and guard the channel
type SorcedChan struct {

	// Static, per channel data
	FundPoint     wire.OutPoint // the outpoint of the channel we're monitoring
	DestPKHScript [22]byte      // PKH to grab to

	BasePoint       [33]byte // the base revokable point (pre-HAKD)
	OtherRefdundPub [33]byte // the other side's refund pubkey (invariant)

	XorIdx uint64 // xor mask to determine state index
	Delay  uint16 // timeout in blocks
	Fee    int64  // fee to use for grab tx

	// Variable, per-state data
	Elk  elkrem.ElkremReceiver // elk receiver of the channel
	Sigs [][]byte              // the sigs for each tx

	// note that Elk.UpTo() will be 1 less than len(Sigs)
	// as Elk[0] fits with Sigs[0], which has len 1
}

// SorcedState is the next state of the channel for monitoring
type SorcedState struct {
	ElkHash wire.ShaHash // elk hash to figure out the pubkey
	Sig     []byte       // signature of grab tx
}

// Ingest the next state.  Will error half the time if the elkrem's invalid.
// Never errors on invalid sig.
func (sc *SorcedChan) Ingest(ss SorcedState) error {
	if sc == nil {
		return fmt.Errorf("Ingest: nil SorcedChan")
	}
	sc.Sigs = append(sc.Sigs, ss.Sig)
	return sc.Elk.AddNext(&ss.ElkHash)
}

// Detect if this close tx is invalid and if we should attempt to grab it.
// If there's errors we'll just return false for now.
func (sc *SorcedChan) Detect(tx *wire.MsgTx) (hit bool) {
	if tx == nil || sc == nil {
		return
	}
	stateIdx := uspv.GetStateIdxFromTx(tx, sc.XorIdx)
	if stateIdx == 0 {
		// no valid state index, likely a cooperative close
		return
	}
	// state index is LESS than our max state!  Can grab!
	// ###### watch out for off-by one here!! there is no state 0 or sig for 0.
	// but there IS an elkrem for 0; a little messy.
	if stateIdx < sc.Elk.UpTo() {
		hit = true
	}
	// if stateIdx == or > len(sc.Sigs), it's a later state than we can grab
	return
}

// Grab produces the grab tx, if possible.
func (sc *SorcedChan) Grab(cTx *wire.MsgTx) (*wire.MsgTx, error) {
	// sanity chex
	if sc == nil {
		return nil, fmt.Errorf("Grab: nil SorcedChan")
	}
	if cTx == nil {
		return nil, fmt.Errorf("Grab: nil close tx")
	}
	// determine state index from close tx
	stateIdx := uspv.GetStateIdxFromTx(cTx, sc.XorIdx)
	if stateIdx == 0 {
		// no valid state index, likely a cooperative close
		return nil, fmt.Errorf("Grab: close tx has 0 state index")
	}
	// check if we have sufficient elkrem
	if stateIdx >= sc.Elk.UpTo() {
		return nil, fmt.Errorf("Grab: state idx %d but elk up to %d",
			stateIdx, sc.Elk.UpTo())
	}
	// check if we have sufficient sig.  This is redundant because elks & sigs
	// should always be in sync.
	if stateIdx > uint64(len(sc.Sigs)) {
		return nil, fmt.Errorf("Grab: state idx %d but %d sigs",
			stateIdx, len(sc.Sigs))
	}
	PubArr := sc.BasePoint
	elk, err := sc.Elk.AtIndex(stateIdx)
	if err != nil {
		return nil, err
	}
	err = uspv.PubKeyArrAddBytes(&PubArr, elk.Bytes())
	if err != nil {
		return nil, err
	}

	// calculate script for p2wsh
	preScript, _ := uspv.CommitScript2(PubArr, sc.OtherRefdundPub, sc.Delay)

	// annoying 2-step outpoint calc
	closeTxid := cTx.TxSha()
	grabOP := wire.NewOutPoint(&closeTxid, 0)
	// make the txin
	grabTxIn := wire.NewTxIn(grabOP, nil, make([][]byte, 2))
	// sig, then script
	grabTxIn.Witness[0] = sc.Sigs[stateIdx]
	grabTxIn.Witness[1] = preScript

	// make a txout
	grabTxOut := wire.NewTxOut(10000, sc.DestPKHScript[:])

	// make the tx and add the txin and txout
	grabTx := wire.NewMsgTx()
	grabTx.AddTxIn(grabTxIn)
	grabTx.AddTxOut(grabTxOut)

	return grabTx, nil
}
