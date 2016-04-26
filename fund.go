package main

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/uspv"
	"github.com/lightningnetwork/lnd/uspv/uwire"
)

// FundChannel makes a multisig address with the node connected to...
// first just request one of their pubkeys (1 byte message)
func FundChannel(args []string) error {
	if RemoteCon == nil {
		return fmt.Errorf("Not connected to anyone\n")
	}
	msg := []byte{uwire.MSGID_PUBREQ}
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

	msg := []byte{uwire.MSGID_PUBRESP}
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
	capBytes := uspv.I64tB(qChanCapacity)
	initPayBytes := uspv.I64tB(1000000) // also will be an arg
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
	//	fmt.Printf()

	sig, revPub, err := SCon.TS.SignState(qc)

	// description is outpoint (36), myPubkey(33), myrefund(20), capacity (8),
	// initial payment (8), revokepubkey (33), signature (~70)
	// total length
	msg := []byte{uwire.MSGID_MULTIDESC}
	msg = append(msg, uspv.OutPointToBytes(*op)...)
	msg = append(msg, myPub[:]...)
	msg = append(msg, myRefundBytes...)
	msg = append(msg, capBytes...)
	msg = append(msg, initPayBytes...)
	msg = append(msg, revPub[:]...)
	msg = append(msg, sig...)
	_, err = RemoteCon.Write(msg)

	return
}

// QChanDescHandler takes in a description of a channel output.  It then
// saves it to the local db.
func QChanDescHandler(from [16]byte, descbytes []byte) {
	if len(descbytes) < 200 || len(descbytes) > 215 {
		fmt.Printf("got %d byte multiDesc, expect ~208\n", len(descbytes))
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
	var opBytes [36]byte
	var theirRefundAdr [20]byte
	var revokePub [33]byte
	copy(opBytes[:], descbytes[:36])
	op := uspv.OutPointFromBytes(opBytes)
	copy(theirRefundAdr[:], descbytes[69:89])
	amt := uspv.BtI64(descbytes[89:97])
	initPay := uspv.BtI64(descbytes[97:105])
	copy(revokePub[:], descbytes[105:138])
	sig := descbytes[138:]

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
	qc.State.MyRevPub = revokePub
	qc.State.Sig = sig

	err = SCon.TS.SaveQchanState(qc)
	if err != nil {
		fmt.Printf("QChanDescHandler err %s", err.Error())
		return
	}

	// ACK the channel address, which causes the funder to sign / broadcast
	// ACK is outpoint (36), that's all.
	msg := []byte{uwire.MSGID_MULTIACK}
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
