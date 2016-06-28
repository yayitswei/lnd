package main

import (
	"fmt"
	"strconv"

	"github.com/lightningnetwork/lnd/elkrem"
	"github.com/lightningnetwork/lnd/uspv"
	"github.com/roasbeef/btcd/btcec"
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

// Do math, see if this curve thing works.
func Math(args []string) error {
	priv := SCon.TS.GetChanPrivkey(5, 5)
	fmt.Printf("initial priv: %x\n", priv.Serialize())

	pubArr := SCon.TS.GetChanPubkey(5, 5)
	pub, _ := btcec.ParsePubKey(pubArr[:], btcec.S256())
	fmt.Printf("initial  pub: %x\n", pub.SerializeCompressed())
	//	for i := 0; i < 10000; i++ {

	return nil
}

func FundChannel(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("need args: fund capacity initialSend")
	}
	if RemoteCon == nil || RemoteCon.RemotePub == nil {
		return fmt.Errorf("Not connected to anyone")
	}
	if len(FundChanStash) > 0 {
		return fmt.Errorf("Other channel creation not done yet")
	}

	// this stuff is all the same as in cclose, should put into a function...
	cCap, err := strconv.ParseInt(args[0], 10, 32)
	if err != nil {
		return err
	}
	iSend, err := strconv.ParseInt(args[1], 10, 32)
	if err != nil {
		return err
	}
	if iSend < 0 || cCap < 0 {
		return fmt.Errorf("Can't have negative send or capacity")
	}
	if cCap < 1000000 { // limit for now
		return fmt.Errorf("Min channe capacity 1M sat")
	}
	if iSend > cCap {
		return fmt.Errorf("Cant send %d in %d capacity channel",
			iSend, cCap)
	}
	// get inputs. comes sorted from PickUtxos.
	// add these into fundreserve to freeze them
	_, overshoot, err := SCon.TS.PickUtxos(cCap, true)
	if err != nil {
		return err
	}
	if overshoot < 0 {
		return fmt.Errorf("witness utxos undershoot by %d", -overshoot)
	}

	var peerArr [33]byte
	copy(peerArr[:], RemoteCon.RemotePub.SerializeCompressed())
	peerIdx, cIdx, err := SCon.TS.NextIdxForPeer(peerArr)
	if err != nil {
		return err
	}

	fr := new(FundReserve)
	fr.PeerIdx = peerIdx
	fr.ChanIdx = cIdx
	fr.Cap = cCap
	fr.InitSend = iSend
	//TODO freeze utxos here

	FundChanStash = append(FundChanStash, fr)
	msg := []byte{uspv.MSGID_POINTREQ}
	_, err = RemoteCon.Write(msg)
	return err
}

// PubReqHandler gets a (content-less) pubkey request.  Respond with a pubkey
// and a refund pubkey hash. (currently makes pubkey hash, need to only make 1)
// so if someone sends 10 pubkeyreqs, they'll get the same pubkey back 10 times.
// they have to provide an actual tx before the next pubkey will come out.
func PointReqHandler(from [16]byte, pointReqBytes []byte) {
	// pub req; check that idx matches next idx of ours and create pubkey
	var peerArr [33]byte
	copy(peerArr[:], RemoteCon.RemotePub.SerializeCompressed())

	peerIdx, cIdx, err := SCon.TS.NextIdxForPeer(peerArr)
	if err != nil {
		fmt.Printf("PointReqHandler err %s", err.Error())
		return
	}
	myChanPub := SCon.TS.GetChanPubkey(peerIdx, cIdx)
	myRefundPub := SCon.TS.GetRefundPubkey(peerIdx, cIdx)
	fmt.Printf("Generated pubkey %x\n", myChanPub)

	msg := []byte{uspv.MSGID_POINTRESP}
	msg = append(msg, myChanPub[:]...)
	msg = append(msg, myRefundPub[:]...)
	_, err = RemoteCon.Write(msg)
	return
}

// FundChannel makes a multisig address with the node connected to...
func PointRespHandler(from [16]byte, pointRespBytes []byte) error {
	if len(FundChanStash) == 0 {
		return fmt.Errorf("Got point response but no channel creation in progress")
	}
	fr := FundChanStash[0]
	//TODO : check that pointResp is from the same peer as the FundReserve peer

	satPerByte := int64(80)
	capBytes := uspv.I64tB(fr.Cap)

	if len(pointRespBytes) != 66 {
		return fmt.Errorf("PointRespHandler err: pointRespBytes %d bytes, expect 66\n",
			len(pointRespBytes))
	}
	var theirPub [33]byte
	copy(theirPub[:], pointRespBytes[:33])

	var theirRefundPub [33]byte
	copy(theirRefundPub[:], pointRespBytes[33:])
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
	op, err := SCon.TS.MakeFundTx(
		tx, fr.Cap, fr.PeerIdx, fr.ChanIdx, peerArr, theirPub, theirRefundPub)
	if err != nil {
		return err
	}
	// don't need to add to filters; we'll pick the TX up anyway because it
	// spends our utxos.

	// tx saved in DB.  Next then notify peer (then sign and broadcast)
	fmt.Printf("tx:%s ", uspv.TxToString(tx))
	// load qchan from DB (that we just saved) to generate elkrem / sig / etc
	// this is kindof dumb; remove later.
	var opArr [36]byte
	copy(opArr[:], uspv.OutPointToBytes(*op))
	qc, err := SCon.TS.GetQchan(peerArr, opArr)
	if err != nil {
		return err
	}

	// create initial state
	qc.State.StateIdx = 1
	qc.State.MyAmt = qc.Value - fr.InitSend

	err = SCon.TS.SaveQchanState(qc)
	if err != nil {
		return err
	}

	theirHAKDpub, err := qc.MakeTheirHAKDPubkey()
	if err != nil {
		return err
	}
	elk, err := qc.ElkSnd.AtIndex(0)
	if err != nil {
		//		fmt.Printf("QChanDescHandler ElkSnd err %s", err.Error())
		return err
	}

	initPayBytes := uspv.I64tB(fr.InitSend) // also will be an arg
	// description is outpoint (36), mypub(33), myrefund(33), capacity (8),
	// initial payment (8), HAKD (33), elk0 (32)
	// total length 138
	msg := []byte{uspv.MSGID_CHANDESC}
	msg = append(msg, uspv.OutPointToBytes(*op)...)
	msg = append(msg, qc.MyPub[:]...)
	msg = append(msg, qc.MyRefundPub[:]...)
	msg = append(msg, capBytes...)
	msg = append(msg, initPayBytes...)
	msg = append(msg, theirHAKDpub[:]...)
	msg = append(msg, elk.Bytes()...)
	_, err = RemoteCon.Write(msg)

	return err
}

// QChanDescHandler takes in a description of a channel output.  It then
// saves it to the local db.
func QChanDescHandler(from [16]byte, descbytes []byte) {
	if len(descbytes) < 183 || len(descbytes) > 183 {
		fmt.Printf("got %d byte channel description, expect 151", len(descbytes))
		return
	}
	var peerArr, myFirstHAKD, theirPub, theirRefundPub [33]byte
	var opArr [36]byte
	copy(peerArr[:], RemoteCon.RemotePub.SerializeCompressed())

	// deserialize desc
	copy(opArr[:], descbytes[:36])
	op := uspv.OutPointFromBytes(opArr)
	copy(theirPub[:], descbytes[36:69])
	copy(theirRefundPub[:], descbytes[69:102])
	amt := uspv.BtI64(descbytes[102:110])
	initPay := uspv.BtI64(descbytes[110:118])
	copy(myFirstHAKD[:], descbytes[118:151])
	revElk, err := wire.NewShaHash(descbytes[151:])
	if err != nil {
		fmt.Printf("QChanDescHandler SaveFundTx err %s", err.Error())
		return
	}

	// save to db
	// it should go into the next bucket and get the right key index.
	// but we can't actually check that.
	qc, err := SCon.TS.SaveFundTx(op, amt, peerArr, theirPub, theirRefundPub)
	if err != nil {
		fmt.Printf("QChanDescHandler SaveFundTx err %s", err.Error())
		return
	}
	fmt.Printf("got multisig output %s amt %d\n", op.String(), amt)
	// before acking, add to bloom filter.  Otherwise we won't see it as
	// it doesn't involve our utxos / adrs.
	filt, err := SCon.TS.GimmeFilter()
	if err != nil {
		fmt.Printf("QChanDescHandler RefilterLocal err %s", err.Error())
		return
	}
	SCon.Refilter(filt)

	// create initial state
	qc.State = new(uspv.StatCom)
	// similar to SIGREV in pushpull
	qc.State.MyAmt = initPay
	qc.State.StateIdx = 1
	// use new HAKDpub for signing
	qc.State.MyHAKDPub = myFirstHAKD

	// create empty elkrem receiver to save
	qc.ElkRcv = new(elkrem.ElkremReceiver)
	err = qc.IngestElkrem(revElk)
	if err != nil { // this can't happen because it's the first elk... remove?
		fmt.Printf("QChanDescHandler err %s", err.Error())
		return
	}

	err = SCon.TS.SaveQchanState(qc)
	if err != nil {
		fmt.Printf("QChanDescHandler SaveQchanState err %s", err.Error())
		return
	}
	// load ... the thing I just saved.  ugly.
	qc, err = SCon.TS.GetQchan(peerArr, opArr)
	if err != nil {
		fmt.Printf("QChanDescHandler GetQchan err %s", err.Error())
		return
	}
	theirHAKDpub, err := qc.MakeTheirHAKDPubkey()
	if err != nil {
		fmt.Printf("QChanDescHandler MakeTheirHAKDPubkey err %s", err.Error())
		return
	}
	sig, err := SCon.TS.SignState(qc)
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
	// ACK is outpoint (36), HAKD (33), elk (32) and signature (~70)
	msg := []byte{uspv.MSGID_CHANACK}
	msg = append(msg, uspv.OutPointToBytes(*op)...)
	msg = append(msg, theirHAKDpub[:]...)
	msg = append(msg, elk.Bytes()...)
	msg = append(msg, sig...)
	_, err = RemoteCon.Write(msg)
	return
}

// QChanAckHandler takes in an acknowledgement multisig description.
// when a multisig outpoint is ackd, that causes the funder to sign and broadcast.
func QChanAckHandler(from [16]byte, ackbytes []byte) {
	if len(ackbytes) < 170 || len(ackbytes) > 180 {
		fmt.Printf("got %d byte multiAck, expect ~170\n", len(ackbytes))
		return
	}
	var opArr [36]byte
	var peerArr, myFirstHAKD [33]byte

	copy(peerArr[:], RemoteCon.RemotePub.SerializeCompressed())
	// deserialize chanACK
	copy(opArr[:], ackbytes[:36])
	copy(myFirstHAKD[:], ackbytes[36:69])
	revElk, err := wire.NewShaHash(ackbytes[69:101])
	if err != nil {
		fmt.Printf("QChanAckHandler err %s", err.Error())
		return
	}
	sig := ackbytes[101:]

	op := uspv.OutPointFromBytes(opArr)

	// load channel to save their refund address
	qc, err := SCon.TS.GetQchan(peerArr, opArr)
	if err != nil {
		fmt.Printf("QChanAckHandler err %s", err.Error())
		return
	}

	err = qc.IngestElkrem(revElk)
	if err != nil { // this can't happen because it's the first elk... remove?
		fmt.Printf("QChanAckHandler err %s", err.Error())
		return
	}

	// save the refund address they gave us.  Save state doesn't do this.
	//	err = SCon.TS.SetQchanRefund(qc, refund)
	//	if err != nil {
	//		fmt.Printf("QChanAckHandler err %s", err.Error())
	//		return
	//	}
	err = qc.VerifySig(sig)
	if err != nil {
		fmt.Printf("QChanAckHandler err %s", err.Error())
		return
	}
	qc.State.MyHAKDPub = myFirstHAKD

	// verify worked; Save state 1 to DB
	err = SCon.TS.SaveQchanState(qc)
	if err != nil {
		fmt.Printf("QChanAckHandler err %s", err.Error())
		return
	}
	// clear this channel from FundChanStash
	// currently one per peer at a time
	for i, stashChan := range FundChanStash {
		if stashChan.PeerIdx == qc.PeerIdx {
			FundChanStash = append(FundChanStash[:i], FundChanStash[i+1:]...)
		}
	}

	// sign their com tx to send
	sig, err = SCon.TS.SignState(qc)
	if err != nil {
		fmt.Printf("QChanAckHandler err %s", err.Error())
		return
	}

	// verify is all OK so fund away.
	// sign multi tx
	tx, err := SCon.TS.SignFundTx(op, peerArr)
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

	//	elk, err := qc.ElkSnd.AtIndex(qc.State.StateIdx - 1)
	//	if err != nil {
	//		fmt.Printf("QChanAckHandler err %s", err.Error())
	//		return
	//	}

	// sig proof should be sent later once there are confirmations.
	// it'll have an spv proof of the fund tx.
	// but for now just send the sig.
	msg := []byte{uspv.MSGID_SIGPROOF}
	msg = append(msg, uspv.OutPointToBytes(*op)...)
	//	msg = append(msg, elk.Bytes()...)
	msg = append(msg, sig...)
	_, err = RemoteCon.Write(msg)
	return
}

// QChanAckHandler takes in an acknowledgement multisig description.
// when a multisig outpoint is ackd, that causes the funder to sign and broadcast.
func SigProofHandler(from [16]byte, sigproofbytes []byte) {
	if len(sigproofbytes) < 100 || len(sigproofbytes) > 110 {
		fmt.Printf("got %d byte Sigproof, expect ~137\n", len(sigproofbytes))
		return
	}
	var peerArr [33]byte
	var opArr [36]byte
	copy(peerArr[:], RemoteCon.RemotePub.SerializeCompressed())
	copy(opArr[:], sigproofbytes[:36])
	//	revElk, err := wire.NewShaHash(sigproofbytes[36:68])
	//	if err != nil {
	//		fmt.Printf("SigProofHandler err %s", err.Error())
	//		return
	//	}
	sig := sigproofbytes[36:]

	qc, err := SCon.TS.GetQchan(peerArr, opArr)
	if err != nil {
		fmt.Printf("SigProofHandler err %s", err.Error())
		return
	}

	err = qc.VerifySig(sig)
	if err != nil {
		fmt.Printf("SigProofHandler err %s", err.Error())
		return
	}
	//	err = qc.IngestElkrem(revElk)
	//	if err != nil { // this can't happen because it's the first elk... remove?
	//		fmt.Printf("SigProofHandler err %s", err.Error())
	//		return
	//	}

	// sig OK, save
	err = SCon.TS.SaveQchanState(qc)
	if err != nil {
		fmt.Printf("SigProofHandler err %s", err.Error())
		return
	}
	// sig OK; in terms of UI here's where you can say "payment received"
	// "channel online" etc
	return
}
