package main

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/elkrem"
	"github.com/lightningnetwork/lnd/uspv"
)

/*
right now fund makes a channel without actually building commit
transactions before signing and broadcasting the fund transaction.
Once state update push/pull messages work that will be added on to
this process

Note that the first elkrem exchange revokes state 0, which was never actually
commited to  (there are no HAKDpubs for state 0; those start at state 1.)
So it's kindof pointless, but you still have to send the right one, because
elkrem 2 is the parent of elkrems 0 and 1, so that checks 0.

*/

// FundChannel makes a multisig address with the node connected to...
// first just request one of their pubkeys (1 byte message)
func FundChannel(args []string) error {
	if RemoteCon == nil {
		return fmt.Errorf("Not connected to anyone\n")
	}
	msg := []byte{uspv.MSGID_PUBREQ}
	_, err := RemoteCon.Write(msg)
	return err
}

// PubReqHandler gets a (content-less) pubkey request.  Respond with a pubkey
// and a refund pubkey hash. (currently makes pubkey hash, need to only make 1)
// so if someone sends 10 pubkeyreqs, they'll get the same pubkey back 10 times.
// they have to provide an actual tx before the next pubkey will come out.
func PubReqHandler(from [16]byte) {
	// pub req; check that idx matches next idx of ours and create pubkey
	peerBytes := RemoteCon.RemotePub.SerializeCompressed()
	pub, refundadr, err := SCon.TS.NextPubForPeer(peerBytes)
	if err != nil {
		fmt.Printf("MultiReqHandler err %s", err.Error())
		return
	}
	fmt.Printf("Generated pubkey %x\n", pub)

	msg := []byte{uspv.MSGID_PUBRESP}
	msg = append(msg, pub[:]...)
	msg = append(msg, refundadr...)
	_, err = RemoteCon.Write(msg)
	return
}

// PubRespHandler -once the pubkey response comes back, we can create the
// transaction.  Create, save to DB, sign and send over the wire (and broadcast)
func PubRespHandler(from [16]byte, pubRespBytes []byte) {
	qChanCapacity := int64(2000000) // this will be an arg
	satPerByte := int64(80)
	initPay := int64(1000000) // also an arg
	capBytes := uspv.I64tB(qChanCapacity)
	if len(pubRespBytes) != 53 {
		fmt.Printf("PubRespHandler err: pubRespBytes %d bytes, expect 53\n",
			len(pubRespBytes))
		return
	}
	var theirPub [33]byte
	copy(theirPub[:], pubRespBytes[:33])

	var theirRefundAdr [20]byte
	copy(theirRefundAdr[:], pubRespBytes[33:])

	// make sure their pubkey is a pubkey
	_, err := btcec.ParsePubKey(theirPub[:], btcec.S256())
	if err != nil {
		fmt.Printf("PubRespHandler err %s", err.Error())
		return
	}

	fmt.Printf("got pubkey response %x\n", theirPub)

	tx := wire.NewMsgTx() // make new tx
	//	tx.Flags = 0x01       // tx will be witty

	// first get inputs. comes sorted from PickUtxos.
	utxos, overshoot, err := SCon.PickUtxos(qChanCapacity, true)
	if err != nil {
		fmt.Printf("PubRespHandler err %s", err.Error())
		return
	}
	if overshoot < 0 {
		fmt.Printf("witness utxos undershoot by %d", -overshoot)
		return
	}
	// add all the inputs to the tx
	for _, utxo := range utxos {
		tx.AddTxIn(wire.NewTxIn(&utxo.Op, nil, nil))
	}
	// estimate fee
	fee := uspv.EstFee(tx, satPerByte)
	// create change output
	changeOut, err := SCon.TS.NewChangeOut(overshoot - fee)
	if err != nil {
		fmt.Printf("PubRespHandler err %s", err.Error())
		return
	}

	tx.AddTxOut(changeOut) // add change output

	//	fmt.Printf("overshoot %d pub idx %d; made output script: %x\n",
	//		overshoot, idx, multiOut.PkScript)

	peerBytes := RemoteCon.RemotePub.SerializeCompressed()
	// send partial tx to db to be saved and have output populated
	op, myPub, myRefundBytes, err := SCon.TS.MakeFundTx(
		tx, qChanCapacity, peerBytes, theirPub, theirRefundAdr)
	if err != nil {
		fmt.Printf("PubRespHandler err %s", err.Error())
		return
	}
	// don't need to add to filters; we'll pick the TX up anyway because it
	// spends our utxos.

	// tx saved in DB.  Next then notify peer (then sign and broadcast)
	fmt.Printf("tx:%s ", uspv.TxToString(tx))
	// load qchan from DB (that we just saved) to generate elkrem / sig / etc
	var opArr [36]byte
	copy(opArr[:], uspv.OutPointToBytes(*op))
	qc, err := SCon.TS.GetQchan(peerBytes, opArr)
	if err != nil {
		fmt.Printf("PubRespHandler err %s", err.Error())
		return
	}

	// create initial state
	qc.State.StateIdx = 0
	qc.State.MyAmt = qc.Value - initPay

	err = SCon.TS.SaveQchanState(qc)
	if err != nil {
		fmt.Printf("PubRespHandler err %s", err.Error())
		return
	}

	initPayBytes := uspv.I64tB(qc.State.MyAmt) // also will be an arg
	// description is outpoint (36), myPubkey(33), myrefund(20), capacity (8),
	// initial payment (8)
	// total length
	msg := []byte{uspv.MSGID_CHANDESC}
	msg = append(msg, uspv.OutPointToBytes(*op)...)
	msg = append(msg, myPub[:]...)
	msg = append(msg, myRefundBytes...)
	msg = append(msg, capBytes...)
	msg = append(msg, initPayBytes...)
	_, err = RemoteCon.Write(msg)

	return
}

// QChanDescHandler takes in a description of a channel output.  It then
// saves it to the local db.
func QChanDescHandler(from [16]byte, descbytes []byte) {
	if len(descbytes) < 105 || len(descbytes) > 110 {
		fmt.Printf("got %d byte multiDesc, expect 105\n", len(descbytes))
		return
	}
	peerBytes := RemoteCon.RemotePub.SerializeCompressed()
	var theirPub [33]byte
	copy(theirPub[:], descbytes[36:69])

	// make sure their pubkey is a pubkey
	_, err := btcec.ParsePubKey(theirPub[:], btcec.S256())
	if err != nil {
		fmt.Printf("QChanDescHandler err %s", err.Error())
		return
	}
	// deserialize outpoint
	var opArr [36]byte
	var theirRefundAdr [20]byte
	copy(opArr[:], descbytes[:36])
	op := uspv.OutPointFromBytes(opArr)
	copy(theirRefundAdr[:], descbytes[69:89])
	amt := uspv.BtI64(descbytes[89:97])
	initPay := uspv.BtI64(descbytes[97:105])

	// save to db
	// it should go into the next bucket and get the right key index.
	// but we can't actually check that.
	qc, err := SCon.TS.SaveFundTx(op, amt, peerBytes, theirPub, theirRefundAdr)
	if err != nil {
		fmt.Printf("QChanDescHandler err %s", err.Error())
		return
	}
	fmt.Printf("got multisig output %s amt %d\n", op.String(), amt)
	// before acking, add to bloom filter.  Otherwise we won't see it as
	// it doesn't involve our utxos / adrs.
	err = SCon.TS.RefilterLocal()
	if err != nil {
		fmt.Printf("QChanDescHandler err %s", err.Error())
		return
	}

	// create initial state
	qc.State = new(uspv.StatCom)
	qc.State.StateIdx = 0
	qc.State.MyAmt = initPay
	// create empty elkrem pair
	qc.ElkRcv = new(elkrem.ElkremReceiver)
	qc.ElkSnd = new(elkrem.ElkremSender)

	err = SCon.TS.SaveQchanState(qc)
	if err != nil {
		fmt.Printf("QChanDescHandler err %s", err.Error())
		return
	}

	// ACK the channel address, which causes the funder to sign / broadcast
	// ACK is outpoint (36), revokepubkey (33) and signature (~70)
	// except you don't need the outpoint if you have the signature...
	msg := []byte{uspv.MSGID_CHANACK}
	msg = append(msg, uspv.OutPointToBytes(*op)...)

	_, err = RemoteCon.Write(msg)
	return
}

// QChanAckHandler takes in an acknowledgement multisig description.
// when a multisig outpoint is ackd, that causes the funder to sign and broadcast.
func QChanAckHandler(from [16]byte, ackbytes []byte) {
	if len(ackbytes) != 36 {
		fmt.Printf("got %d byte multiAck, expect 36\n", len(ackbytes))
		return
	}
	peerBytes := RemoteCon.RemotePub.SerializeCompressed()
	// deserialize outpoint
	var opBytes [36]byte
	copy(opBytes[:], ackbytes)
	op := uspv.OutPointFromBytes(opBytes)
	// sign multi tx
	tx, err := SCon.TS.SignFundTx(op, peerBytes)
	if err != nil {
		fmt.Printf("QChanAckHandler err %s", err.Error())
		return
	}
	fmt.Printf("tx to broadcast: %s ", uspv.TxToString(tx))
	err = SCon.NewOutgoingTx(tx)
	if err != nil {
		fmt.Printf("QChanAckHandler err %s", err.Error())
		return
	}
	return
}
