package sorceror

import (
	"fmt"
	"os"

	"github.com/lightningnetwork/lnd/elkrem"
	"github.com/roasbeef/btcd/wire"
)

const defaultpath = "."

// SorcedChan is data sufficient to monitor and guard the channel
// You can't actually tell what the channel is though!
type SorceChan struct {
	// Static, per channel data

	ChanId  uint32 // Channel number, decided by peer
	PeerIdx uint32 // peer ID, decided by me

	// Channels should be globally uniquely identified by their destination PKH
	DestPKHScript [20]byte // PKH to grab to

	Delay uint16 // timeout in blocks
	Fee   int64  // fee to use for grab tx. could make variable but annoying...

	HAKDBasePoint [33]byte // client's HAKD key base point
	TimeBasePoint [33]byte // potential attacker's timeout basepoint

	// state data
	Elk elkrem.ElkremReceiver // elk receiver of the channel
	// File storage
	//	Path      string   // path for all files
	ElkFile   *os.File // file for elkrem
	StateFile *os.File // flat file storing states, stays open

	// maybe put file mutexes, or a general struct mutex?
	// basically no operations should happen on this concurrently.
}

// SorceDescriptor is the initial description of a SorceChan
type SorceDescriptor struct {
	ChanId        uint32
	DestPKHScript [20]byte // PKH to grab to; main unique identifier.

	Delay uint16 // timeout in blocks
	Fee   int64  // fee to use for grab tx. could make variable but annoying...

	HAKDBasePoint [33]byte // client's HAKD key base point
	TimeBasePoint [33]byte // potential attacker's timeout basepoint
}

// the message describing the next state, sent from the client
type SorceMsg struct {
	ChanId uint32
	Txid   wire.ShaHash // txid of close tx
	Elk    wire.ShaHash // elkrem for this state index
	Sig    [64]byte     // sig for the grab tx
}

// SorcedState is the state of the channel being monitored
// (for writing to disk; 100 bytes).
type SorceState struct {
	Txid wire.ShaHash // txid of invalid close tx
	Sig  [64]byte     // signature of grab tx
	xtra [4]byte      // empty 4 bytes for now, could use for fee or something
}

func NewSorceChanFromDesc(
	sd SorceDescriptor, peerIdx uint32, path string) SorceChan {
	var sc SorceChan

	// copy everything over; straightforward
	sc.ChanId = sd.ChanId
	sc.PeerIdx = peerIdx // not specified in descriptor, arg instead
	sc.DestPKHScript = sd.DestPKHScript
	sc.Delay = sd.Delay
	sc.Fee = sd.Fee
	sc.HAKDBasePoint = sd.HAKDBasePoint
	sc.TimeBasePoint = sd.TimeBasePoint

	return sc
}

// Ingest the next state.  Will error half the time if the elkrem's invalid.
// Never errors on invalid sig.
func (sc *SorceChan) Ingest(sm SorceMsg) error {
	if sc == nil {
		return fmt.Errorf("Ingest: nil SorcedChan")
	}
	// first ingest the elkrem
	err := sc.Elk.AddNext(&sm.Elk)
	if err != nil {
		return err
	}
	// serialize elkrem
	elkBytes, err := sc.Elk.ToBytes()
	if err != nil {
		return err
	}
	// should mv elk to oldelk here?  For faster recovery if write fails?
	// not really critical though as this is a backup anyway and can re-sync it
	// from the client

	//overwrite elkrem on disk, at offset 0
	n, err := sc.ElkFile.WriteAt(elkBytes, 0)
	if err != nil {
		return err
	}
	// truncate to that write in case it got smaller.  Might not do anything.
	err = sc.ElkFile.Truncate(int64(n))
	if err != nil {
		return err
	}
	err = sc.ElkFile.Sync()
	if err != nil {
		return err
	}

	ss := SorceState{
		Txid: sm.Txid,
		Sig:  sm.Sig,
	}

	_, err = sc.StateFile.Seek(0, 2)
	if err != nil {
		return err
	}
	_, err = sc.StateFile.Write(ss.ToBytes())
	if err != nil {
		return err
	}
	err = sc.StateFile.Sync()
	if err != nil {
		return err
	}

	return nil
}

func (sc *SorceChan) GetAllTxids() ([]wire.ShaHash, error) {

	// get file length
	stat, err := sc.StateFile.Stat()
	if err != nil {
		return nil, err
	}

	if stat.Size()%100 != 0 {
		return nil, fmt.Errorf("State file %d bytes, expect ...00", stat.Size())
	}
	// make txid slice
	txids := make([]wire.ShaHash, stat.Size()/100)

	// read 32, skip 68, repeat.  Probably faster to read the whole thing
	// into ram first, but that won't work for huge files.
	// for really huge, this won't work at all though, and have to return
	// a filter...
	for i, _ := range txids {
		_, err := sc.StateFile.ReadAt(txids[i][:], i*100)
		if err != nil {
			return nil, err
		}
	}
	return txids, nil
}

// Grab produces the grab tx, if possible.
func (sc *SorceChan) Grab(cTx *wire.MsgTx) (*wire.MsgTx, error) {
	sc.StateFile.Name()

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
