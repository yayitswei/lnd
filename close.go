package main

import (
	"fmt"
	"strconv"

	"github.com/lightningnetwork/lnd/uspv"
)

/* CloseChannel --- cooperative close
This is the simplified close which sends to the same outputs as a break tx,
just with no timeouts.

Users might want a more advanced close function which allows multiple outputs.
They can exchange txouts and sigs.  That could be "fancyClose", but this is
just close, so only a signature is sent by the initiator, and the receiver
doesn't reply, as the channel is closed.

*/

// CloseChannel is a cooperative closing of a channel to a specified address.
func CloseChannel(args []string) error {
	if RemoteCon == nil || RemoteCon.RemotePub == nil {
		return fmt.Errorf("Not connected to anyone\n")
	}
	// need args, fail
	if len(args) < 2 {
		return fmt.Errorf("need args: cclose peerIdx chanIdx")
	}

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
	if peerIdx != currentPeerIdx {
		return fmt.Errorf("Want to close with peer %d but connected to %d	",
			peerIdx, currentPeerIdx)
	}

	qc, err := SCon.TS.GetQchanByIdx(peerIdx, cIdx)
	if err != nil {
		return err
	}

	sig, err := SCon.TS.SignSimpleClose(qc)
	if err != nil {
		return err
	}

	// Save something to db... TODO
	// Should save something, just so the UI marks it as closed, and
	// we don't accept payments on this channel anymore.

	// close request is just the op, sig
	msg := []byte{uspv.MSGID_CLOSEREQ}
	msg = append(msg, uspv.OutPointToBytes(qc.Op)...)
	msg = append(msg, sig...)

	_, err = RemoteCon.Write(msg)
	return nil
}

// CloseReqHandler takes in a close request from a remote host, signs and
// responds with a close response.  Obviously later there will be some judgment
// over what to do, but for now it just signs whatever it's requested to.
func CloseReqHandler(from [16]byte, reqbytes []byte) {
	if len(reqbytes) < 100 {
		fmt.Printf("got %d byte closereq, expect 100ish\n", len(reqbytes))
		return
	}

	// figure out who we're talking to
	var peerArr [33]byte
	copy(peerArr[:], RemoteCon.RemotePub.SerializeCompressed())

	// deserialize outpoint
	var opArr [36]byte
	copy(opArr[:], reqbytes[:36])

	// find their sig
	theirSig := reqbytes[36:]

	// get channel
	qc, err := SCon.TS.GetQchan(peerArr, opArr)
	if err != nil {
		fmt.Printf("CloseReqHandler err %s", err.Error())
		return
	}
	// verify their sig?  should do that before signing our side just to be safe

	// sign close
	mySig, err := SCon.TS.SignSimpleClose(qc)
	if err != nil {
		fmt.Printf("CloseReqHandler err %s", err.Error())
		return
	}

	tx := qc.SimpleCloseTx()

	pre, swap, err := uspv.FundTxScript(qc.MyPub, qc.TheirPub)
	if err != nil {
		fmt.Printf("CloseReqHandler err %s", err.Error())
		return
	}

	// swap if needed
	if swap {
		tx.TxIn[0].Witness = uspv.SpendMultiSigWitStack(pre, theirSig, mySig)
	} else {
		tx.TxIn[0].Witness = uspv.SpendMultiSigWitStack(pre, mySig, theirSig)
	}
	//	fmt.Printf("%s", uspv.TxToString(tx))
	err = SCon.NewOutgoingTx(tx)
	if err != nil {
		fmt.Printf("CloseReqHandler err %s", err.Error())
		return
	}

	return
}
