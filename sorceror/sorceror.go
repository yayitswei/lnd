package sorceror

import (
	"fmt"
	"os"

	"github.com/lightningnetwork/lnd/elkrem"
	"github.com/roasbeef/btcd/wire"
)

// SorcedChan is data sufficient to monitor and guard the channel
// You can't actually tell what the channel is though!
type SorceChan struct {
	// Static, per channel data
	// Channels are primarily identified by their destination PKH.
	DestPKHScript [20]byte // PKH to grab to

	Delay uint16 // timeout in blocks
	Fee   int64  // fee to use for grab tx. could make variable but annoying...

	HAKDBasePoint [33]byte // client's HAKD key base point
	TimeBasePoint [33]byte // potential attacker's timeout basepoint

	// state data
	Elk       elkrem.ElkremReceiver // elk receiver of the channel
	StateFile *os.File              // flat file storing states
}

// SorceDescriptor is the initial description of a SorceChan
type SorceDescriptor struct {
	DestPKHScript [20]byte // PKH to grab to; main unique identifier.

	Delay uint16 // timeout in blocks
	Fee   int64  // fee to use for grab tx. could make variable but annoying...

	HAKDBasePoint [33]byte // client's HAKD key base point
	TimeBasePoint [33]byte // potential attacker's timeout basepoint
}

// the message describing the next state, sent from the client
type SorceMsg struct {
	Txid wire.ShaHash // txid of close tx
	Elk  wire.ShaHash // elkrem for this state index
	Sig  [64]byte     // sig for the grab tx
}

// SorcedState is the state of the channel being monitored
// (for writing to disk; 100 bytes).
type SorceState struct {
	Txid wire.ShaHash // txid of invalid close tx
	Sig  [64]byte     // signature of grab tx
	xtra [4]byte      // empty 4 bytes for now, could use for fee or something
}

// Ingest the next state.  Will error half the time if the elkrem's invalid.
// Never errors on invalid sig.
func (sc *SorceChan) Ingest(ss SorceState) error {
	if sc == nil {
		return fmt.Errorf("Ingest: nil SorcedChan")
	}
	return nil
}

// Detect if this close tx is invalid and if we should attempt to grab it.
// If there's errors we'll just return false for now.
//func (sc *SorceChan) Detect(tx *wire.MsgTx) (hit bool) {
//	if tx == nil || sc == nil {
//		return
//	}
//	return
//}

// Grab produces the grab tx, if possible.
func (sc *SorceChan) Grab(cTx *wire.MsgTx) (*wire.MsgTx, error) {
	// sanity chex
	//	if sc == nil {
	//		return nil, fmt.Errorf("Grab: nil SorcedChan")
	//	}
	//	if cTx == nil || len(cTx.TxOut) == 0 {
	//		return nil, fmt.Errorf("Grab: nil close tx")
	//	}
	//	// determine state index from close tx
	//	stateIdx := uspv.GetStateIdxFromTx(cTx, sc.XorIdx)
	//	if stateIdx == 0 {
	//		// no valid state index, likely a cooperative close
	//		return nil, fmt.Errorf("Grab: close tx has 0 state index")
	//	}
	//	// check if we have sufficient elkrem
	//	if stateIdx >= sc.Elk.UpTo() {
	//		return nil, fmt.Errorf("Grab: state idx %d but elk up to %d",
	//			stateIdx, sc.Elk.UpTo())
	//	}
	//	// check if we have sufficient sig.  This is redundant because elks & sigs
	//	// should always be in sync.
	//	if stateIdx > uint64(len(sc.Sigs)) {
	//		return nil, fmt.Errorf("Grab: state idx %d but %d sigs",
	//			stateIdx, len(sc.Sigs))
	//	}
	//	PubArr := sc.BasePoint
	//	elk, err := sc.Elk.AtIndex(stateIdx)
	//	if err != nil {
	//		return nil, err
	//	}
	//	err = uspv.PubKeyArrAddBytes(&PubArr, elk.Bytes())
	//	if err != nil {
	//		return nil, err
	//	}

	//	// figure out amount to grab
	//	// for now, assumes 2 outputs.  Later, look for the largest wsh output
	//	if len(cTx.TxOut[0].PkScript) == 34 {
	//		shIdx = 0
	//	} else {
	//		shIdx = 1
	//	}

	//	// calculate script for p2wsh
	//	preScript, _ := uspv.CommitScript2(PubArr, sc.OtherRefdundPub, sc.Delay)

	//	// annoying 2-step outpoint calc
	//	closeTxid := cTx.TxSha()
	//	grabOP := wire.NewOutPoint(&closeTxid, 0)
	//	// make the txin
	//	grabTxIn := wire.NewTxIn(grabOP, nil, make([][]byte, 2))
	//	// sig, then script
	//	grabTxIn.Witness[0] = sc.Sigs[stateIdx]
	//	grabTxIn.Witness[1] = preScript

	//	// make a txout
	//	grabTxOut := wire.NewTxOut(10000, sc.DestPKHScript[:])

	//	// make the tx and add the txin and txout
	//	grabTx := wire.NewMsgTx()
	//	grabTx.AddTxIn(grabTxIn)
	//	grabTx.AddTxOut(grabTxOut)

	//	return grabTx, nil
	return nil, nil
}
