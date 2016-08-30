package qln

import (
	"fmt"

	"github.com/lightningnetwork/lnd/elkrem"
	"github.com/lightningnetwork/lnd/lnutil"
	"github.com/lightningnetwork/lnd/portxo"
	"github.com/lightningnetwork/lnd/uspv"
	"github.com/roasbeef/btcd/wire"
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

/*
New funding process.
No fancy curve stuff.  Just ask the other node for a point on a curve, which
will be their channel pubkey.
There are 2 ways to then change to a channel-proof-y method later.
One way is to construct the channel pubkey FROM that point, by having
ID:A
Random point:B
Channel point:C
and set C = hash(A, B)*(A + B)
or you could do it 4-way so that
C = hash(A1, B1, A2, B2)*(A + B)
to commit to both sides' creation process.  This is a little more complex,
but the proof of ownership for the channel just consists of the point B so
it's compact.

Another way to do it, after the fact with arbitrary points.
ID:A, Channel pub:C
B = A + C
sign B with b.  That signature is proof that someone / something knew
a and c at the same time.

Either of these can be added later without changing much.  The messages
don't have to change at all, and in the first case you'd change the channel
pubkey calculation.  In the second it's independant of the fund process.

For now though:
funding --
A -> B point request

A channel point (33) (channel pubkey for now)
A refund (33)

B -> A point response
B replies with channel point and refund pubkey

B channel point (32) (channel pubkey for now)
B refund (33)

A -> B Channel Description:
---
outpoint (36)
capacity (8)
initial push (8)
B's HAKD pub #1 (33)
signature (~70)
---

add next:
timeout (2)
fee? fee can
(fee / timeout...?  hardcoded for now)

B -> A  Channel Acknowledge:
A's HAKD pub #1 (33)
signature (~70)

=== time passes, fund tx gets in a block ===

A -> B SigProof
SPV proof of the outpoint (block height, tree depth, tx index, hashes)
signature (~70)


B knows the channel is open and he got paid when he receives the sigproof.
A's got B's signature already.  So "payment happened" is sortof the same as
bitcoin now; wait for confirmations.

Alternatively A can open a channel with no initial funding going to B, then
update the state once the channel is open.  If for whatever reason you want
an exact timing for the payment.

*/

// PubReqHandler gets a (content-less) pubkey request.  Respond with a pubkey
// and a refund pubkey hash. (currently makes pubkey hash, need to only make 1)
// so if someone sends 10 pubkeyreqs, they'll get the same pubkey back 10 times.
// they have to provide an actual tx before the next pubkey will come out.
func (nd LnNode) PointReqHandler(from [16]byte, pointReqBytes []byte) {
	// pub req; check that idx matches next idx of ours and create pubkey
	var peerArr [33]byte
	copy(peerArr[:], nd.RemoteCon.RemotePub.SerializeCompressed())

	peerIdx, cIdx, err := nd.NextIdxForPeer(peerArr)
	if err != nil {
		fmt.Printf("PointReqHandler err %s", err.Error())
		return
	}

	var kg portxo.KeyGen
	kg.Depth = 5
	kg.Step[0] = 44 + 0x80000000
	kg.Step[1] = 0 + 0x80000000
	kg.Step[2] = uspv.UseChannelFund
	kg.Step[3] = peerIdx + 0x80000000
	kg.Step[4] = cIdx + 0x80000000

	myChanPub := nd.GetUsePub(kg, uspv.UseChannelFund)
	myRefundPub := nd.GetUsePub(kg, uspv.UseChannelRefund)
	myHAKDbase := nd.GetUsePub(kg, uspv.UseChannelHAKDBase)
	fmt.Printf("Generated pubkey %x\n", myChanPub)

	msg := []byte{MSGID_POINTRESP}
	msg = append(msg, myChanPub[:]...)
	msg = append(msg, myRefundPub[:]...)
	msg = append(msg, myHAKDbase[:]...)
	_, err = nd.RemoteCon.Write(msg)
	return
}

// FundChannel makes a multisig address with the node connected to...
func (nd LnNode) PointRespHandler(from [16]byte, pointRespBytes []byte) error {
	// not sure how to do this yet
	/*
		if len(FundChanStash) == 0 {
			return fmt.Errorf("Got point response but no channel creation in progress")
		}
		fr := FundChanStash[0]
		//TODO : check that pointResp is from the same peer as the FundReserve peer

		satPerByte := int64(80)
		capBytes := uspv.I64tB(fr.Cap)

		if len(pointRespBytes) != 99 {
			return fmt.Errorf("PointRespHandler err: pointRespBytes %d bytes, expect 99\n",
				len(pointRespBytes))
		}
		var theirPub [33]byte
		copy(theirPub[:], pointRespBytes[:33])

		var theirRefundPub [33]byte
		copy(theirRefundPub[:], pointRespBytes[33:66])

		var theirHAKDbase [33]byte
		copy(theirHAKDbase[:], pointRespBytes[66:])

		// make sure their pubkey is a pubkey
		_, err := btcec.ParsePubKey(theirPub[:], btcec.S256())
		if err != nil {
			return fmt.Errorf("PubRespHandler err %s", err.Error())
		}

		tx := wire.NewMsgTx() // make new tx

		// first get inputs. comes sorted from PickUtxos.
		utxos, overshoot, err := SCon.TS.PickUtxos(fr.Cap, true)
		if err != nil {
			return err
		}
		if overshoot < 0 {
			return fmt.Errorf("witness utxos undershoot by %d", -overshoot)
		}
		//TODO use frozen utxos
		// add all the inputs to the tx
		for _, utxo := range utxos {
			tx.AddTxIn(wire.NewTxIn(&utxo.Op, nil, nil))
		}
		// estimate fee
		fee := uspv.EstFee(tx, satPerByte)
		// create change output
		changeOut, err := SCon.TS.NewChangeOut(overshoot - fee)
		if err != nil {
			return err
		}

		tx.AddTxOut(changeOut) // add change output

		var peerArr [33]byte
		copy(peerArr[:], RemoteCon.RemotePub.SerializeCompressed())

		// save partial tx to db; populate output, get their channel pubkey
		op, err := LNode.MakeFundTx(tx, fr.Cap, fr.PeerIdx, fr.ChanIdx,
			peerArr, theirPub, theirRefundPub, theirHAKDbase)
		if err != nil {
			return err
		}
		// don't need to add to filters; we'll pick the TX up anyway because it
		// spends our utxos.

		// tx saved in DB.  Next then notify peer (then sign and broadcast)
		fmt.Printf("tx:%s ", uspv.TxToString(tx))
		// load qchan from DB (that we just saved) to generate elkrem / sig / etc
		// this is kindof dumb; remove later.
		opArr := uspv.OutPointToBytes(*op)
		qc, err := LNode.GetQchan(peerArr, opArr)
		if err != nil {
			return err
		}

		// create initial state
		qc.State.StateIdx = 1
		qc.State.MyAmt = qc.Value - fr.InitSend

		err = LNode.SaveQchanState(qc)
		if err != nil {
			return err
		}

		theirElkPointR, theirElkPointT, err := qc.MakeTheirCurElkPoints()
		if err != nil {
			return err
		}

		elk, err := qc.ElkSnd.AtIndex(0)
		if err != nil {
			return err
		}

		initPayBytes := uspv.I64tB(fr.InitSend) // also will be an arg
		// description is outpoint (36), mypub(33), myrefund(33),
		// myHAKDbase(33), capacity (8),
		// initial payment (8), ElkPointR (33), ElkPointT (33), elk0 (32)
		// total length 249
		msg := []byte{qln.MSGID_CHANDESC}
		msg = append(msg, opArr[:]...)
		msg = append(msg, qc.MyPub[:]...)
		msg = append(msg, qc.MyRefundPub[:]...)
		msg = append(msg, qc.MyHAKDBase[:]...)
		msg = append(msg, capBytes...)
		msg = append(msg, initPayBytes...)
		msg = append(msg, theirElkPointR[:]...)
		msg = append(msg, theirElkPointT[:]...)
		msg = append(msg, elk.Bytes()...)
		_, err = RemoteCon.Write(msg)
	*/
	return nil
}

// QChanDescHandler takes in a description of a channel output.  It then
// saves it to the local db.
func (nd LnNode) QChanDescHandler(from [16]byte, descbytes []byte) {
	if len(descbytes) < 249 || len(descbytes) > 249 {
		fmt.Printf("got %d byte channel description, expect 249", len(descbytes))
		return
	}
	var peerArr, myFirstElkPointR, myFirstElkPointT, theirPub, theirRefundPub, theirHAKDbase [33]byte
	var opArr [36]byte
	copy(peerArr[:], nd.RemoteCon.RemotePub.SerializeCompressed())

	// deserialize desc
	copy(opArr[:], descbytes[:36])
	op := lnutil.OutPointFromBytes(opArr)
	copy(theirPub[:], descbytes[36:69])
	copy(theirRefundPub[:], descbytes[69:102])
	copy(theirHAKDbase[:], descbytes[102:135])
	amt := lnutil.BtI64(descbytes[135:143])
	initPay := lnutil.BtI64(descbytes[143:151])
	copy(myFirstElkPointR[:], descbytes[151:184])
	copy(myFirstElkPointT[:], descbytes[184:217])
	revElk, err := wire.NewShaHash(descbytes[217:])
	if err != nil {
		fmt.Printf("QChanDescHandler SaveFundTx err %s", err.Error())
		return
	}

	// save to db
	// it should go into the next bucket and get the right key index.
	// but we can't actually check that.
	qc, err := nd.SaveFundTx(
		op, amt, peerArr, theirPub, theirRefundPub, theirHAKDbase)
	if err != nil {
		fmt.Printf("QChanDescHandler SaveFundTx err %s", err.Error())
		return
	}
	fmt.Printf("got multisig output %s amt %d\n", op.String(), amt)

	// create initial state
	qc.State = new(StatCom)
	// similar to SIGREV in pushpull
	qc.State.MyAmt = initPay
	qc.State.StateIdx = 1
	// use new ElkPoint for signing
	qc.State.ElkPointR = myFirstElkPointR
	qc.State.ElkPointT = myFirstElkPointT

	// create empty elkrem receiver to save
	qc.ElkRcv = new(elkrem.ElkremReceiver)
	err = qc.IngestElkrem(revElk)
	if err != nil { // this can't happen because it's the first elk... remove?
		fmt.Printf("QChanDescHandler err %s", err.Error())
		return
	}

	err = nd.SaveQchanState(qc)
	if err != nil {
		fmt.Printf("QChanDescHandler SaveQchanState err %s", err.Error())
		return
	}
	// load ... the thing I just saved.  ugly.
	qc, err = nd.GetQchan(peerArr, opArr)
	if err != nil {
		fmt.Printf("QChanDescHandler GetQchan err %s", err.Error())
		return
	}

	theirElkPointR, theirElkPointT, err := qc.MakeTheirCurElkPoints()
	if err != nil {
		fmt.Printf("QChanDescHandler MakeTheirCurElkPoint err %s", err.Error())
		return
	}

	sig, err := nd.SignState(qc)
	if err != nil {
		fmt.Printf("QChanDescHandler SignState err %s", err.Error())
		return
	}

	elk, err := qc.ElkSnd.AtIndex(qc.State.StateIdx - 1) // which is 0
	if err != nil {
		fmt.Printf("QChanDescHandler ElkSnd err %s", err.Error())
		return
	}
	// ACK the channel address, which causes the funder to sign / broadcast
	// ACK is outpoint (36), ElkPointR (33), ElkPointT (33), elk (32) and signature (64)
	msg := []byte{MSGID_CHANACK}
	msg = append(msg, opArr[:]...)
	msg = append(msg, theirElkPointR[:]...)
	msg = append(msg, theirElkPointT[:]...)
	msg = append(msg, elk.Bytes()...)
	msg = append(msg, sig[:]...)
	_, err = nd.RemoteCon.Write(msg)
	return
}

// QChanAckHandler takes in an acknowledgement multisig description.
// when a multisig outpoint is ackd, that causes the funder to sign and broadcast.
func (nd LnNode) QChanAckHandler(from [16]byte, ackbytes []byte) {
	if len(ackbytes) < 198 || len(ackbytes) > 198 {
		fmt.Printf("got %d byte multiAck, expect 198", len(ackbytes))
		return
	}
	var opArr [36]byte
	var peerArr, myFirstElkPointR, myFirstElkPointT [33]byte
	var sig [64]byte

	copy(peerArr[:], nd.RemoteCon.RemotePub.SerializeCompressed())
	// deserialize chanACK
	copy(opArr[:], ackbytes[:36])
	copy(myFirstElkPointR[:], ackbytes[36:69])
	copy(myFirstElkPointT[:], ackbytes[69:102])
	// don't think this can error as length is specified
	revElk, _ := wire.NewShaHash(ackbytes[102:134])
	copy(sig[:], ackbytes[134:])

	//	op := lnutil.OutPointFromBytes(opArr)

	// load channel to save their refund address
	qc, err := nd.GetQchan(peerArr, opArr)
	if err != nil {
		fmt.Printf("QChanAckHandler GetQchan err %s", err.Error())
		return
	}

	err = qc.IngestElkrem(revElk)
	if err != nil { // this can't happen because it's the first elk... remove?
		fmt.Printf("QChanAckHandler IngestElkrem err %s", err.Error())
		return
	}
	qc.State.ElkPointR = myFirstElkPointR
	qc.State.ElkPointT = myFirstElkPointT

	err = qc.VerifySig(sig)
	if err != nil {
		fmt.Printf("QChanAckHandler VerifySig err %s", err.Error())
		return
	}

	// verify worked; Save state 1 to DB
	err = nd.SaveQchanState(qc)
	if err != nil {
		fmt.Printf("QChanAckHandler SaveQchanState err %s", err.Error())
		return
	}
	// clear this channel from FundChanStash
	// currently one per peer at a time
	//	for i, stashChan := range FundChanStash {
	//		if stashChan.PeerIdx == qc.KeyGen.Step[3] {
	//			FundChanStash = append(FundChanStash[:i], FundChanStash[i+1:]...)
	//		}
	//	}

	// sign their com tx to send
	sig, err = nd.SignState(qc)
	if err != nil {
		fmt.Printf("QChanAckHandler SignState err %s", err.Error())
		return
	}

	// verify is all OK so fund away.
	// sign multi tx
	//	tx, err := LNode.SignFundTx(op, peerArr)
	//	if err != nil {
	//		fmt.Printf("QChanAckHandler SignFundTx err %s", err.Error())
	//		return
	//	}

	// add to bloom filter here for channel creator
	//	filt, err := SCon.TS.GimmeFilter()
	//	if err != nil {
	//		fmt.Printf("QChanDescHandler GimmeFilter err %s", err.Error())
	//		return
	//	}
	//	SCon.Refilter(filt)

	//	fmt.Printf("tx to broadcast: %s ", uspv.TxToString(tx))
	//	err = SCon.NewOutgoingTx(tx)
	//	if err != nil {
	//		fmt.Printf("QChanAckHandler NewOutgoingTx err %s", err.Error())
	//		return
	//	}

	// sig proof should be sent later once there are confirmations.
	// it'll have an spv proof of the fund tx.
	// but for now just send the sig.
	msg := []byte{MSGID_SIGPROOF}
	msg = append(msg, opArr[:]...)
	msg = append(msg, sig[:]...)
	_, err = nd.RemoteCon.Write(msg)
	return
}

// QChanAckHandler takes in an acknowledgement multisig description.
// when a multisig outpoint is ackd, that causes the funder to sign and broadcast.
func (nd LnNode) SigProofHandler(from [16]byte, sigproofbytes []byte) {
	if len(sigproofbytes) < 100 || len(sigproofbytes) > 100 {
		fmt.Printf("got %d byte Sigproof, expect ~100\n", len(sigproofbytes))
		return
	}
	var peerArr [33]byte
	var opArr [36]byte
	var sig [64]byte
	copy(peerArr[:], nd.RemoteCon.RemotePub.SerializeCompressed())
	copy(opArr[:], sigproofbytes[:36])
	copy(sig[:], sigproofbytes[36:])

	qc, err := nd.GetQchan(peerArr, opArr)
	if err != nil {
		fmt.Printf("SigProofHandler err %s", err.Error())
		return
	}

	err = qc.VerifySig(sig)
	if err != nil {
		fmt.Printf("SigProofHandler err %s", err.Error())
		return
	}

	// sig OK, save
	err = nd.SaveQchanState(qc)
	if err != nil {
		fmt.Printf("SigProofHandler err %s", err.Error())
		return
	}

	// add to bloom filter here; later should instead receive spv proof
	//	filt, err := SCon.TS.GimmeFilter()
	//	if err != nil {
	//		fmt.Printf("QChanDescHandler RefilterLocal err %s", err.Error())
	//		return
	//	}
	//	SCon.Refilter(filt)

	// sig OK; in terms of UI here's where you can say "payment received"
	// "channel online" etc
	return
}
