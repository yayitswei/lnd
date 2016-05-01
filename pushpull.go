package main

import (
	"bytes"
	"fmt"
	"strconv"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/uspv"
)

// Grab the coins that are rightfully yours! Plus some more.
func Grab(args []string) error {
	// need args, fail
	if len(args) < 2 {
		return fmt.Errorf("need args: recov peerIdx chanIdx")
	}

	peerIdx, err := strconv.ParseInt(args[0], 10, 32)
	if err != nil {
		return err
	}
	cIdx, err := strconv.ParseInt(args[1], 10, 32)
	if err != nil {
		return err
	}

	qc, err := SCon.TS.GetQchanByIdx(uint32(peerIdx), uint32(cIdx))
	if err != nil {
		return err
	}

	fmt.Printf("try to recover (%d,%d)\n", qc.PeerIdx, qc.KeyIdx)

	rtx, err := SCon.TS.RemedyTx(qc)
	if err != nil {
		return err
	}

	fmt.Printf(uspv.TxToString(rtx))
	return SCon.NewOutgoingTx(rtx)
}

// BreakChannel closes the channel without the other party's involvement.
// The user causing the channel Break has to wait for the OP_CSV timeout
// before funds can be recovered.  Break output addresses are already in the
// DB so you can't specify anything other than which channel to break.
func BreakChannel(args []string) error {
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

	qc, err := SCon.TS.GetQchanByIdx(uint32(peerIdx), uint32(cIdx))
	if err != nil {
		return err
	}

	fmt.Printf("breaking (%d,%d)\n", qc.PeerIdx, qc.KeyIdx)
	// set delta to 0...
	qc.State.Delta = 0
	tx, err := SCon.TS.SignBreakTx(qc)
	if err != nil {
		return err
	}

	// broadcast
	return SCon.NewOutgoingTx(tx)
}

// Resume is a shell command which resumes a message exchange for channels that
// are in a non-final state.  If the channel is in a final state it will send
// a REV (which it already sent, and should be ignored)
func Resume(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("need args: fix peerIdx chanIdx")
	}
	if RemoteCon == nil {
		return fmt.Errorf("Not connected to anyone, can't fix\n")
	}
	// this stuff is all the same as in cclose, should put into a function...
	peerIdx64, err := strconv.ParseInt(args[0], 10, 32)
	if err != nil {
		return err
	}
	cIdx64, err := strconv.ParseInt(args[1], 10, 32)
	if err != nil {
		return err
	}
	peerIdx := uint32(peerIdx64)
	cIdx := uint32(cIdx64)

	// find the peer index of who we're connected to
	currentPeerIdx, err := SCon.TS.GetPeerIdx(RemoteCon.RemotePub)
	if err != nil {
		return err
	}
	if uint32(peerIdx) != currentPeerIdx {
		return fmt.Errorf("Want to close with peer %d but connected to %d",
			peerIdx, currentPeerIdx)
	}
	fmt.Printf("fix channel (%d,%d)\n", peerIdx, cIdx)

	qc, err := SCon.TS.GetQchanByIdx(peerIdx, cIdx)
	if err != nil {
		return err
	}

	return SendNextMsg(qc)
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
func SendNextMsg(qc *uspv.Qchan) error {
	var empty [33]byte

	// RTS
	if qc.State.Delta < 0 {
		if qc.State.MyPrevHAKDPub != empty {
			return fmt.Errorf("delta is %d but prevHAKD full!", qc.State.Delta)
		}
		return SendRTS(qc)
	}

	// ACKSIG
	if qc.State.Delta > 0 {
		if qc.State.MyPrevHAKDPub == empty {
			return fmt.Errorf("delta is %d but prevHAKD empty!", qc.State.Delta)
		}
		return SendACKSIG(qc)
	}

	//SIGREV (delta must be 0 by now)
	if qc.State.MyPrevHAKDPub != empty {
		return SendSIGREV(qc)
	}

	// REV
	return SendREV(qc)
}

// Push is the shell command which calls PushChannel
func Push(args []string) error {
	if len(args) < 3 {
		return fmt.Errorf("need args: push peerIdx chanIdx amt (times)")
	}
	if RemoteCon == nil {
		return fmt.Errorf("Not connected to anyone, can't push\n")
	}
	// this stuff is all the same as in cclose, should put into a function...
	peerIdx64, err := strconv.ParseInt(args[0], 10, 32)
	if err != nil {
		return err
	}
	cIdx64, err := strconv.ParseInt(args[1], 10, 32)
	if err != nil {
		return err
	}
	amt, err := strconv.ParseInt(args[2], 10, 32)
	if err != nil {
		return err
	}
	times := int64(1)
	if len(args) > 3 {
		times, err = strconv.ParseInt(args[3], 10, 32)
		if err != nil {
			return err
		}
	}

	if amt > 100000000 || amt < 1 {
		return fmt.Errorf("push %d, max push is 1 coin / 100000000", amt)
	}
	peerIdx := uint32(peerIdx64)
	cIdx := uint32(cIdx64)

	// find the peer index of who we're connected to
	currentPeerIdx, err := SCon.TS.GetPeerIdx(RemoteCon.RemotePub)
	if err != nil {
		return err
	}
	if uint32(peerIdx) != currentPeerIdx {
		return fmt.Errorf("Want to close with peer %d but connected to %d",
			peerIdx, currentPeerIdx)
	}
	fmt.Printf("push %d to (%d,%d) %d times\n", amt, peerIdx, cIdx, times)

	qc, err := SCon.TS.GetQchanByIdx(peerIdx, cIdx)
	if err != nil {
		return err
	}

	for times > 0 {
		err = SCon.TS.ReloadQchan(qc)
		if err != nil {
			return err
		}

		err = PushChannel(qc, uint32(amt))
		if err != nil {
			return err
		}
		// such a hack.. obviously need indicator of when state update complete
		time.Sleep(time.Millisecond * 25)
		times--
	}
	return nil
}

// PushChannel initiates a state update by sending an RTS
func PushChannel(qc *uspv.Qchan, amt uint32) error {
	// local sanity check
	//	if amt >= qc.State.MyAmt {
	//		return fmt.Errorf("push %d, you have %d in channel", amt, qc.State.MyAmt)
	//	}
	var empty [33]byte

	// don't try to update state until all prior updates have cleared
	// may want to change this later, but requires other changes.
	if qc.State.Delta != 0 || qc.State.MyPrevHAKDPub != empty {
		return fmt.Errorf("channel update in progress, cannot push")
	}

	qc.State.Delta = int32(-amt)
	// save to db with ONLY delta changed
	err := SCon.TS.SaveQchanState(qc)
	if err != nil {
		return err
	}
	return SendRTS(qc)

}

// SendRTS based on channel info
func SendRTS(qc *uspv.Qchan) error {
	qc.State.StateIdx++
	theirHAKDpub, err := qc.MakeTheirHAKDPubkey()
	if err != nil {
		return err
	}

	fmt.Printf("will send RTS with delta:%d HAKD %x\n",
		qc.State.Delta, theirHAKDpub[:4])

	// RTS is op (36), delta (4), HAKDPub (33)
	// total length 73
	// could put index as well here but for now index just goes ++ each time.
	msg := []byte{uspv.MSGID_RTS}
	msg = append(msg, uspv.OutPointToBytes(qc.Op)...)
	msg = append(msg, uspv.U32tB(uint32(-qc.State.Delta))...)
	msg = append(msg, theirHAKDpub[:]...)
	_, err = RemoteCon.Write(msg)
	if err != nil {
		return err
	}
	return nil
}

// RTSHandler takes in an RTS and responds with an ACKSIG (if everything goes OK)
func RTSHandler(from [16]byte, RTSBytes []byte) {

	if len(RTSBytes) < 73 || len(RTSBytes) > 73 {
		fmt.Printf("got %d byte RTS, expect 73", len(RTSBytes))
		return
	}

	var opArr [36]byte
	var RTSDelta uint32
	var RTSHAKDpub [33]byte

	// deserialize RTS
	copy(opArr[:], RTSBytes[:36])
	RTSDelta = uspv.BtU32(RTSBytes[36:40])
	copy(RTSHAKDpub[:], RTSBytes[40:])

	// make sure the HAKD pubkey is a pubkey
	_, err := btcec.ParsePubKey(RTSHAKDpub[:], btcec.S256())
	if err != nil {
		fmt.Printf("RTSHandler err %s", err.Error())
		return
	}

	// find who we're talkikng to
	peerBytes := RemoteCon.RemotePub.SerializeCompressed()
	// load qchan & state from DB
	qc, err := SCon.TS.GetQchan(peerBytes, opArr)
	if err != nil {
		fmt.Printf("RTSHandler err %s", err.Error())
		return
	}
	if RTSDelta < 1 {
		fmt.Printf("RTSHandler err: RTS delta %d", RTSDelta)
		return
	}
	if int64(RTSDelta) > qc.Value-qc.State.MyAmt {
		fmt.Printf("RTSHandler err: RTS delta %d but they have %d",
			RTSDelta, qc.Value-qc.State.MyAmt)
		return
	}
	if !bytes.Equal(peerBytes, qc.PeerPubId[:]) {
		fmt.Printf("RTSHandler err: peer %x trying to modify peer %x's channel\n",
			peerBytes, qc.PeerPubId)
		fmt.Printf("This can't happen now, but joseph wants this check here ",
			"in case the code changes later and we forget.\n")
		return
	}
	qc.State.Delta = int32(RTSDelta)            // assign delta
	qc.State.MyPrevHAKDPub = qc.State.MyHAKDPub // copy previous HAKD pub
	qc.State.MyHAKDPub = RTSHAKDpub             // assign HAKD pub
	// save delta, HAKDpub to db
	err = SCon.TS.SaveQchanState(qc)
	if err != nil {
		fmt.Printf("RTSHandler err %s", err.Error())
		return
	}
	// saved to db, now proceed to create & sign their tx, and generate their
	// HAKD pub for them to sign
	err = SendACKSIG(qc)
	if err != nil {
		fmt.Printf("RTSHandler err %s", err.Error())
		return
	}
	return
}

// SendACKSIG sends an ACKSIG message based on channel info
func SendACKSIG(qc *uspv.Qchan) error {
	qc.State.StateIdx++
	qc.State.MyAmt += int64(qc.State.Delta)
	qc.State.Delta = 0
	sig, err := SCon.TS.SignState(qc)
	if err != nil {
		return err
	}
	fmt.Printf("made sig %x\n", sig)
	theirHAKDpub, err := qc.MakeTheirHAKDPubkey()
	if err != nil {
		return err
	}

	// ACKSIG is op (36), HAKDPub (33), sig (~70)
	// total length ~139
	msg := []byte{uspv.MSGID_ACKSIG}
	msg = append(msg, uspv.OutPointToBytes(qc.Op)...)
	msg = append(msg, theirHAKDpub[:]...)
	msg = append(msg, sig...)
	_, err = RemoteCon.Write(msg)
	return err
}

// ACKSIGHandler takes in an ACKSIG and responds with an SIGREV (if everything goes OK)
func ACKSIGHandler(from [16]byte, ACKSIGBytes []byte) {

	if len(ACKSIGBytes) < 135 || len(ACKSIGBytes) > 145 {
		fmt.Printf("got %d byte ACKSIG, expect 139", len(ACKSIGBytes))
		return
	}

	var opArr [36]byte
	var ACKSIGHAKDpub [33]byte

	// deserialize ACKSIG
	copy(opArr[:], ACKSIGBytes[:36])
	copy(ACKSIGHAKDpub[:], ACKSIGBytes[36:69])
	sig := ACKSIGBytes[69:]
	// make sure the HAKD pubkey is a pubkey
	_, err := btcec.ParsePubKey(ACKSIGHAKDpub[:], btcec.S256())
	if err != nil {
		fmt.Printf("ACKSIGHandler err %s", err.Error())
		return
	}
	// find who we're talkikng to
	peerBytes := RemoteCon.RemotePub.SerializeCompressed()
	// load qchan & state from DB
	qc, err := SCon.TS.GetQchan(peerBytes, opArr)
	if err != nil {
		fmt.Printf("ACKSIGHandler err %s", err.Error())
		return
	}
	if !bytes.Equal(peerBytes, qc.PeerPubId[:]) {
		fmt.Printf("ACKSIGHandler err: peer %x trying to modify peer %x's channel\n",
			peerBytes, qc.PeerPubId)
		fmt.Printf("This can't happen now, but joseph wants this check here ",
			"in case the code changes later and we forget.\n")
		return
	}

	// increment state
	qc.State.StateIdx++
	// copy current HAKDPub to previous as state has been incremented
	qc.State.MyPrevHAKDPub = qc.State.MyHAKDPub
	// get new HAKDpub for signing
	qc.State.MyHAKDPub = ACKSIGHAKDpub

	// construct tx and verify signature
	qc.State.MyAmt += int64(qc.State.Delta) // delta should be negative
	qc.State.Delta = 0
	err = qc.VerifySig(sig)
	if err != nil {
		fmt.Printf("ACKSIGHandler err %s", err.Error())
		return
	}
	// verify worked; Save to incremented state to DB with new & old myHAKDpubs
	err = SCon.TS.SaveQchanState(qc)
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
func SendSIGREV(qc *uspv.Qchan) error {
	// sign their tx with my new HAKD pubkey I just got.
	sig, err := SCon.TS.SignState(qc)
	if err != nil {
		return err
	}
	// get elkrem for revoking *previous* state, so elkrem at index - 1.
	elk, err := qc.ElkSnd.AtIndex(qc.State.StateIdx - 1)
	if err != nil {
		return err
	}

	// SIGREV is op (36), elk (32), sig (~70)
	// total length ~138
	msg := []byte{uspv.MSGID_SIGREV}
	msg = append(msg, uspv.OutPointToBytes(qc.Op)...)
	msg = append(msg, elk.Bytes()...)
	msg = append(msg, sig...)
	_, err = RemoteCon.Write(msg)
	return err
}

// SIGREVHandler takes in an SIGREV and responds with a REV (if everything goes OK)
func SIGREVHandler(from [16]byte, SIGREVBytes []byte) {

	if len(SIGREVBytes) < 135 || len(SIGREVBytes) > 145 {
		fmt.Printf("got %d byte SIGREV, expect 138", len(SIGREVBytes))
		return
	}

	var opArr [36]byte
	// deserialize SIGREV
	copy(opArr[:], SIGREVBytes[:36])
	sig := SIGREVBytes[68:]
	revElk, err := wire.NewShaHash(SIGREVBytes[36:68])
	if err != nil {
		fmt.Printf("SIGREVHandler err %s", err.Error())
		return
	}

	// find who we're talkikng to
	peerBytes := RemoteCon.RemotePub.SerializeCompressed()
	// load qchan & state from DB
	qc, err := SCon.TS.GetQchan(peerBytes, opArr)
	if err != nil {
		fmt.Printf("SIGREVHandler err %s", err.Error())
		return
	}
	if !bytes.Equal(peerBytes, qc.PeerPubId[:]) {
		fmt.Printf("SIGREVHandler err: peer %x trying to modify peer %x's channel\n",
			peerBytes, qc.PeerPubId)
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
	err = SCon.TS.SaveQchanState(qc)
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
func SendREV(qc *uspv.Qchan) error {
	// get elkrem for revoking *previous* state, so elkrem at index - 1.
	elk, err := qc.ElkSnd.AtIndex(qc.State.StateIdx - 1)
	if err != nil {

		return err
	}
	// REV is just op (36), elk (32)
	// total length 68
	msg := []byte{uspv.MSGID_REVOKE}
	msg = append(msg, uspv.OutPointToBytes(qc.Op)...)
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
	peerBytes := RemoteCon.RemotePub.SerializeCompressed()
	// load qchan & state from DB
	qc, err := SCon.TS.GetQchan(peerBytes, opArr)
	if err != nil {
		fmt.Printf("REVHandler err %s", err.Error())
		return
	}
	if !bytes.Equal(peerBytes, qc.PeerPubId[:]) {
		fmt.Printf("REVHandler err: peer %x trying to modify peer %x's channel\n",
			peerBytes, qc.PeerPubId)
		fmt.Printf("This can't happen now, but joseph wants this check here ",
			"in case the code changes later and we forget.\n")
		return
	}

	// check if there's nothing for them to revoke
	var empty [33]byte
	if qc.State.StateIdx > 1 && qc.State.MyPrevHAKDPub == empty {
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
	err = SCon.TS.SaveQchanState(qc)
	if err != nil {
		fmt.Printf("REVHandler err %s", err.Error())
		return
	}
	fmt.Printf("REV OK, state %d all clear.\n", qc.State.StateIdx)
	return
}
