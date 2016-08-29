package qln

import (
	"fmt"
	"strconv"

	"github.com/lightningnetwork/lnd/lnutil"

	"github.com/lightningnetwork/lnd/uspv"
	"github.com/roasbeef/btcd/btcec"
	"github.com/roasbeef/btcd/wire"
)

const minBal = 10000 // channels have to have 10K sat in them; can make variable later.

// Grab the coins that are rightfully yours! Plus some more.
// For right now, spend all outputs from channel close.
//func Grab(args []string) error {
//	return SCon.GrabAll()
//}

// BreakChannel closes the channel without the other party's involvement.
// The user causing the channel Break has to wait for the OP_CSV timeout
// before funds can be recovered.  Break output addresses are already in the
// DB so you can't specify anything other than which channel to break.
func (nd LnNode) BreakChannel(args []string) error {
	// need args, fail
	if len(args) < 2 {
		return fmt.Errorf("need args: break peerIdx chanIdx")
	}

	peerIdx, err := strconv.ParseInt(args[0], 10, 32)
	if err != nil {
		return err
	}
	cIdx, err := strconv.ParseInt(args[1], 10, 32)
	if err != nil {
		return err
	}

	qc, err := nd.GetQchanByIdx(uint32(peerIdx), uint32(cIdx))
	if err != nil {
		return err
	}

	fmt.Printf("breaking (%d,%d)\n", qc.KeyGen.Step[3], qc.KeyGen.Step[4])
	z, err := qc.ElkSnd.AtIndex(0)
	if err != nil {
		return err
	}
	fmt.Printf("elk send 0: %s\n", z.String())
	z, err = qc.ElkRcv.AtIndex(0)
	if err != nil {
		return err
	}
	fmt.Printf("elk recv 0: %s\n", z.String())
	// set delta to 0...
	qc.State.Delta = 0
	tx, err := nd.SignBreakTx(qc)
	if err != nil {
		return err
	}

	// broadcast
	return nd.BaseWallet.PushTx(tx)
}

/*
SendNextMsg logic:

Message to send: channel state (sanity check)

RTS:
delta < 0
(prevHAKD == 0)

ACKSIG:
delta > 0
(prevHAKD != 0)

SIGREV:
delta == 0
prevHAKD != 0

REV:
delta == 0
prevHAKD == 0

Note that when there's nothing to send, it'll send a REV message,
revoking the previous state which has already been revoked.

We could distinguish by writing to the db that we've sent the REV message...
but that doesn't seem that useful because we don't know if they got it so
we might have to send it again anyway.
*/

// SendNextMsg determines what message needs to be sent next
// based on the channel state.  It then calls the appropriate function.
func SendNextMsg(qc *Qchan) error {
	var empty [33]byte

	// RTS
	if qc.State.Delta < 0 {
		if qc.State.PrevElkPointR != empty {
			return fmt.Errorf("delta is %d but prevHAKD full!", qc.State.Delta)
		}
		return SendRTS(qc)
	}

	// ACKSIG
	if qc.State.Delta > 0 {
		if qc.State.PrevElkPointR == empty {
			return fmt.Errorf("delta is %d but prevHAKD empty!", qc.State.Delta)
		}
		return SendACKSIG(qc)
	}

	//SIGREV (delta must be 0 by now)
	if qc.State.PrevElkPointR != empty {
		return SendSIGREV(qc)
	}

	// REV
	return SendREV(qc)
}

// PushChannel initiates a state update by sending an RTS
func (nd LnNode) PushChannel(qc *Qchan, amt uint32) error {

	var empty [33]byte

	// don't try to update state until all prior updates have cleared
	// may want to change this later, but requires other changes.
	if qc.State.Delta != 0 || qc.State.PrevElkPointR != empty {
		return fmt.Errorf("channel update in progress, cannot push")
	}
	// check if this push would lower my balance below minBal
	if int64(amt)+minBal > qc.State.MyAmt {
		return fmt.Errorf("want to push %d but %d available, %d minBal",
			amt, qc.State.MyAmt, minBal)
	}
	// check if this push is sufficient to get them above minBal (only needed at
	// state 1)
	// if qc.State.StateIdx < 2 && int64(amt)+(qc.Value-qc.State.MyAmt) < minBal {
	if int64(amt)+(qc.Value-qc.State.MyAmt) < minBal {
		return fmt.Errorf("pushing %d insufficient; counterparty minBal %d",
			amt, minBal)
	}

	qc.State.Delta = int32(-amt)
	// save to db with ONLY delta changed
	err := nd.SaveQchanState(qc)
	if err != nil {
		return err
	}
	return SendRTS(qc)
}

// SendRTS based on channel info
func SendRTS(qc *Qchan) error {
	qc.State.StateIdx++

	elkPointR, elkPointT, err := qc.MakeTheirCurElkPoints()
	if err != nil {
		return err
	}

	fmt.Printf("will send RTS with delta:%d elkPR %x\n",
		qc.State.Delta, elkPointR[:4])

	opArr := uspv.OutPointToBytes(qc.Op)
	// RTS is op (36), delta (4), ElkPointR (33), ElkPointT (33)
	// total length 106
	// could put index as well here but for now index just goes ++ each time.
	msg := []byte{MSGID_RTS}
	msg = append(msg, opArr[:]...)
	msg = append(msg, uspv.U32tB(uint32(-qc.State.Delta))...)
	msg = append(msg, elkPointR[:]...)
	msg = append(msg, elkPointT[:]...)
	_, err = RemoteCon.Write(msg)
	if err != nil {
		return err
	}
	return nil
}

// RTSHandler takes in an RTS and responds with an ACKSIG (if everything goes OK)
func RTSHandler(from [16]byte, RTSBytes []byte) {

	if len(RTSBytes) < 106 || len(RTSBytes) > 106 {
		fmt.Printf("got %d byte RTS, expect 106", len(RTSBytes))
		return
	}

	var opArr [36]byte
	var RTSDelta uint32
	var RTSElkPointR, RTSElkPointT [33]byte

	// deserialize RTS
	copy(opArr[:], RTSBytes[:36])
	RTSDelta = lnutil.BtU32(RTSBytes[36:40])
	copy(RTSElkPointR[:], RTSBytes[40:73])
	copy(RTSElkPointT[:], RTSBytes[73:])

	// make sure the ElkPoint is a point (basically starts with a 02/03)
	_, err := btcec.ParsePubKey(RTSElkPointR[:], btcec.S256())
	if err != nil {
		fmt.Printf("RTSHandler err %s", err.Error())
		return
	}
	_, err = btcec.ParsePubKey(RTSElkPointT[:], btcec.S256())
	if err != nil {
		fmt.Printf("RTSHandler err %s", err.Error())
		return
	}

	// find who we're talkikng to
	var peerArr [33]byte
	copy(peerArr[:], RemoteCon.RemotePub.SerializeCompressed())
	// load qchan & state from DB
	qc, err := LNode.GetQchan(peerArr, opArr)
	if err != nil {
		fmt.Printf("RTSHandler GetQchan err %s", err.Error())
		return
	}
	if qc.CloseData.Closed {
		fmt.Printf("RTSHandler err: %d, %d is closed.",
			qc.KeyGen.Step[3], qc.KeyGen.Step[4])
		return
	}
	if RTSDelta < 1 {
		fmt.Printf("RTSHandler err: RTS delta %d", RTSDelta)
		return
	}
	// check if this push would lower counterparty balance below minBal
	if int64(RTSDelta) > (qc.Value-qc.State.MyAmt)+minBal {
		fmt.Printf("RTSHandler err: RTS delta %d but they have %d, minBal %d",
			RTSDelta, qc.Value-qc.State.MyAmt, minBal)
		return
	}
	// check if this push is sufficient to get us above minBal (only needed at
	// state 1)
	//if qc.State.StateIdx < 2 && int64(RTSDelta)+qc.State.MyAmt < minBal {
	if int64(RTSDelta)+qc.State.MyAmt < minBal {
		fmt.Printf("RTSHandler err: current %d, incoming delta %d, minBal %d",
			qc.State.MyAmt, RTSDelta, minBal)
		return
	}

	if peerArr != qc.PeerId {
		fmt.Printf("RTSHandler err: peer %x trying to modify peer %x's channel\n",
			peerArr, qc.PeerId)
		fmt.Printf("This can't happen now, but joseph wants this check here ",
			"in case the code changes later and we forget.\n")
		return
	}
	qc.State.Delta = int32(RTSDelta)            // assign delta
	qc.State.PrevElkPointR = qc.State.ElkPointR // copy previous ElkPoints
	qc.State.PrevElkPointT = qc.State.ElkPointT // copy previous ElkPoints
	qc.State.ElkPointR = RTSElkPointR           // assign ElkPoints
	qc.State.ElkPointT = RTSElkPointT           // assign ElkPoints
	// save delta, ElkPoint to db
	err = LNode.SaveQchanState(qc)
	if err != nil {
		fmt.Printf("RTSHandler SaveQchanState err %s", err.Error())
		return
	}
	// saved to db, now proceed to create & sign their tx, and generate their
	// HAKD pub for them to sign
	err = SendACKSIG(qc)
	if err != nil {
		fmt.Printf("RTSHandler SendACKSIG err %s", err.Error())
		return
	}
	return
}

// SendACKSIG sends an ACKSIG message based on channel info
func SendACKSIG(qc *Qchan) error {
	qc.State.StateIdx++
	qc.State.MyAmt += int64(qc.State.Delta)
	qc.State.Delta = 0
	sig, err := LNode.SignState(qc)
	if err != nil {
		return err
	}
	theirElkPointR, theirElkPointT, err := qc.MakeTheirCurElkPoints()
	if err != nil {
		return err
	}

	opArr := uspv.OutPointToBytes(qc.Op)
	// ACKSIG is op (36), ElkPointR (33), ElkPointT (33), sig (64)
	// total length 166
	msg := []byte{MSGID_ACKSIG}
	msg = append(msg, opArr[:]...)
	msg = append(msg, theirElkPointR[:]...)
	msg = append(msg, theirElkPointT[:]...)
	msg = append(msg, sig[:]...)
	_, err = RemoteCon.Write(msg)
	return err
}

// ACKSIGHandler takes in an ACKSIG and responds with an SIGREV (if everything goes OK)
func ACKSIGHandler(from [16]byte, ACKSIGBytes []byte) {
	if len(ACKSIGBytes) < 166 || len(ACKSIGBytes) > 166 {
		fmt.Printf("got %d byte ACKSIG, expect 166", len(ACKSIGBytes))
		return
	}

	var opArr [36]byte
	var ACKSIGElkPointR, ACKSIGElkPointT [33]byte
	var sig [64]byte

	// deserialize ACKSIG
	copy(opArr[:], ACKSIGBytes[:36])
	copy(ACKSIGElkPointR[:], ACKSIGBytes[36:69])
	copy(ACKSIGElkPointT[:], ACKSIGBytes[69:102])
	copy(sig[:], ACKSIGBytes[102:])

	// make sure the ElkPoint is a point
	_, err := btcec.ParsePubKey(ACKSIGElkPointR[:], btcec.S256())
	if err != nil {
		fmt.Printf("ACKSIGHandler err %s", err.Error())
		return
	}
	// make sure the ElkPoint is a point
	_, err = btcec.ParsePubKey(ACKSIGElkPointT[:], btcec.S256())
	if err != nil {
		fmt.Printf("ACKSIGHandler err %s", err.Error())
		return
	}

	// find who we're talkikng to
	var peerArr [33]byte
	copy(peerArr[:], RemoteCon.RemotePub.SerializeCompressed())
	// load qchan & state from DB
	qc, err := LNode.GetQchan(peerArr, opArr)
	if err != nil {
		fmt.Printf("ACKSIGHandler err %s", err.Error())
		return
	}
	if peerArr != qc.PeerId {
		fmt.Printf("ACKSIGHandler err: peer %x trying to modify peer %x's channel\n",
			peerArr, qc.PeerId)
		fmt.Printf("This can't happen now, but joseph wants this check here ",
			"in case the code changes later and we forget.\n")
		return
	}

	// increment state
	qc.State.StateIdx++
	// copy current ElkPoints to previous as state has been incremented
	qc.State.PrevElkPointR = qc.State.ElkPointR
	qc.State.PrevElkPointT = qc.State.ElkPointT
	// get new ElkPoint for signing
	qc.State.ElkPointR = ACKSIGElkPointR
	qc.State.ElkPointT = ACKSIGElkPointT

	// construct tx and verify signature
	qc.State.MyAmt += int64(qc.State.Delta) // delta should be negative
	qc.State.Delta = 0
	err = qc.VerifySig(sig)
	if err != nil {
		fmt.Printf("ACKSIGHandler err %s", err.Error())
		return
	}
	// verify worked; Save to incremented state to DB with new & old myHAKDpubs
	err = LNode.SaveQchanState(qc)
	if err != nil {
		fmt.Printf("ACKSIGHandler err %s", err.Error())
		return
	}
	err = SendSIGREV(qc)
	if err != nil {
		fmt.Printf("ACKSIGHandler err %s", err.Error())
		return
	}
	return
}

// SendSIGREV sends a SIGREV message based on channel info
func SendSIGREV(qc *Qchan) error {
	// sign their tx with my new HAKD pubkey I just got.
	sig, err := LNode.SignState(qc)
	if err != nil {
		return err
	}
	// get elkrem for revoking *previous* state, so elkrem at index - 1.
	elk, err := qc.ElkSnd.AtIndex(qc.State.StateIdx - 1)
	if err != nil {
		return err
	}

	opArr := uspv.OutPointToBytes(qc.Op)

	// SIGREV is op (36), elk (32), sig (64)
	// total length ~132
	msg := []byte{MSGID_SIGREV}
	msg = append(msg, opArr[:]...)
	msg = append(msg, elk.Bytes()...)
	msg = append(msg, sig[:]...)
	_, err = RemoteCon.Write(msg)
	return err
}

// SIGREVHandler takes in an SIGREV and responds with a REV (if everything goes OK)
func SIGREVHandler(from [16]byte, SIGREVBytes []byte) {

	if len(SIGREVBytes) < 132 || len(SIGREVBytes) > 132 {
		fmt.Printf("got %d byte SIGREV, expect 132", len(SIGREVBytes))
		return
	}

	var opArr [36]byte
	var sig [64]byte
	// deserialize SIGREV
	copy(opArr[:], SIGREVBytes[:36])
	copy(sig[:], SIGREVBytes[68:])

	revElk, err := wire.NewShaHash(SIGREVBytes[36:68])
	if err != nil {
		fmt.Printf("SIGREVHandler err %s", err.Error())
		return
	}

	// find who we're talkikng to
	var peerArr [33]byte
	copy(peerArr[:], RemoteCon.RemotePub.SerializeCompressed())
	// load qchan & state from DB
	qc, err := LNode.GetQchan(peerArr, opArr)
	if err != nil {
		fmt.Printf("SIGREVHandler err %s", err.Error())
		return
	}
	if peerArr != qc.PeerId {
		fmt.Printf("SIGREVHandler err: peer %x trying to modify peer %x's channel\n",
			peerArr, qc.PeerId)
		fmt.Printf("This can't happen now, but joseph wants this check here ",
			"in case the code changes later and we forget.\n")
		return
	}
	qc.State.StateIdx++
	qc.State.MyAmt += int64(qc.State.Delta)
	qc.State.Delta = 0

	// first verify sig.
	// (if elkrem ingest fails later, at least we close out with a bit more money)
	err = qc.VerifySig(sig)
	if err != nil {
		fmt.Printf("SIGREVHandler err %s", err.Error())
		return
	}

	// verify elkrem and save it in ram
	err = qc.IngestElkrem(revElk)
	if err != nil {
		fmt.Printf("SIGREVHandler err %s", err.Error())
		fmt.Printf(" ! non-recoverable error, need to close the channel here.\n")
		return
	}
	// if the elkrem failed but sig didn't... we should update the DB to reflect
	// that and try to close with the incremented amount, why not.
	// Implement that later though.

	// all verified; Save finished state to DB, puller is pretty much done.
	err = LNode.SaveQchanState(qc)
	if err != nil {
		fmt.Printf("SIGREVHandler err %s", err.Error())
		return
	}

	fmt.Printf("SIGREV OK, state %d, will send REV\n", qc.State.StateIdx)
	err = SendREV(qc)
	if err != nil {
		fmt.Printf("SIGREVHandler err %s", err.Error())
		return
	}
	return
}

// SendREV sends a REV message based on channel info
func SendREV(qc *Qchan) error {
	// get elkrem for revoking *previous* state, so elkrem at index - 1.
	elk, err := qc.ElkSnd.AtIndex(qc.State.StateIdx - 1)
	if err != nil {
		return err
	}

	opArr := uspv.OutPointToBytes(qc.Op)
	// REV is just op (36), elk (32)
	// total length 68
	msg := []byte{MSGID_REVOKE}
	msg = append(msg, opArr[:]...)
	msg = append(msg, elk.Bytes()...)
	_, err = RemoteCon.Write(msg)
	return err
}

// REVHandler takes in an REV and clears the state's prev HAKD.  This is the
// final message in the state update process and there is no response.
func REVHandler(from [16]byte, REVBytes []byte) {
	if len(REVBytes) != 68 {
		fmt.Printf("got %d byte REV, expect 68", len(REVBytes))
		return
	}
	var opArr [36]byte
	// deserialize SIGREV
	copy(opArr[:], REVBytes[:36])
	revElk, err := wire.NewShaHash(REVBytes[36:])
	if err != nil {
		fmt.Printf("REVHandler err %s", err.Error())
		return
	}

	// find who we're talkikng to
	var peerArr [33]byte
	copy(peerArr[:], RemoteCon.RemotePub.SerializeCompressed())
	// load qchan & state from DB
	qc, err := LNode.GetQchan(peerArr, opArr)
	if err != nil {
		fmt.Printf("REVHandler err %s", err.Error())
		return
	}
	if peerArr != qc.PeerId {
		fmt.Printf("REVHandler err: peer %x trying to modify peer %x's channel\n",
			peerArr, qc.PeerId)
		fmt.Printf("This can't happen now, but joseph wants this check here ",
			"in case the code changes later and we forget.\n")
		return
	}

	// check if there's nothing for them to revoke
	var empty [33]byte
	if qc.State.StateIdx > 1 && qc.State.PrevElkPointR == empty {
		fmt.Printf("got REV message with hash %s, but nothing to revoke\n",
			revElk.String())
		return
	}

	// verify elkrem
	err = qc.IngestElkrem(revElk)
	if err != nil {
		fmt.Printf("REVHandler err %s", err.Error())
		fmt.Printf(" ! non-recoverable error, need to close the channel here.\n")
		return
	}
	// save to DB (only new elkrem)
	err = LNode.SaveQchanState(qc)
	if err != nil {
		fmt.Printf("REVHandler err %s", err.Error())
		return
	}
	fmt.Printf("REV OK, state %d all clear.\n", qc.State.StateIdx)
	return
}
