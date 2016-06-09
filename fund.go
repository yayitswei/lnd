package main

import (
	"fmt"

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

B replies with channel point and refund pubkey

B channel point (32) (channel pubkey for now)
B refund (33)

A -> B Channel Description:
---
outpoint (36)
capacity (8)
initial push (8)
B's HAKD pub #1 (33)
---

add next:
timeout (2)
fee? fee can
(fee / timeout...?  hardcoded for now)

B -> A  Channel Acknowledge:
B refund address (20)
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
	priv := SCon.TS.GetFundPrivkey(5, 5)
	fmt.Printf("initial priv: %x\n", priv.Serialize())

	pubArr := SCon.TS.GetFundPubkey(5, 5)
	pub, _ := btcec.ParsePubKey(pubArr[:], btcec.S256())
	fmt.Printf("initial  pub: %x\n", pub.SerializeCompressed())
	//	for i := 0; i < 10000; i++ {

	uspv.PubKeyMult(pub, 212)
	//	}
	fmt.Printf("modified pub: %x\n", pub.SerializeCompressed())

	//	for i := 0; i < 10000; i++ {
	uspv.PrivKeyMult(priv, 212)
	//	}
	fmt.Printf("from prv pub: %x\n", priv.PubKey().SerializeCompressed())
	fmt.Printf("modified priv: %x\n", priv.Serialize())
	uspv.PrivKeyDiv(priv, 212)
	fmt.Printf("modifieX priv: %x\n", priv.Serialize())

	return nil
}

// FundChannel makes a multisig address with the node connected to...
// first just request one of their pubkeys (1 byte message)
func FundChannel(args []string) error {
	if RemoteCon == nil {
		return fmt.Errorf("Not connected to anyone\n")
	}

	qChanCapacity := int64(2000000) // this will be an arg. soon.
	satPerByte := int64(80)
	initPay := int64(1000000) // also an arg. real soon.
	capBytes := uspv.I64tB(qChanCapacity)

	tx := wire.NewMsgTx() // make new tx

	// first get inputs. comes sorted from PickUtxos.
	utxos, overshoot, err := SCon.PickUtxos(qChanCapacity, true)
	if err != nil {
		return err
	}
	if overshoot < 0 {
		return fmt.Errorf("witness utxos undershoot by %d", -overshoot)
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
		return err
	}

	tx.AddTxOut(changeOut) // add change output

	var peerArr [33]byte
	copy(peerArr[:], RemoteCon.RemotePub.SerializeCompressed())

	// save partial tx to db; populate output, get their channel pubkey
	op, err := SCon.TS.MakeFundTx(tx, qChanCapacity, peerArr)
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
	qc.State.MyAmt = qc.Value - initPay

	err = SCon.TS.SaveQchanState(qc)
	if err != nil {
		return err
	}

	theirHAKDpub, err := qc.MakeTheirHAKDPubkey()
	if err != nil {
		return err
	}

	initPayBytes := uspv.I64tB(qc.State.MyAmt) // also will be an arg
	// description is outpoint (36), nonce(20), myrefund(33), capacity (8),
	// initial payment (8)
	// total length 138
	msg := []byte{uspv.MSGID_CHANDESC}
	msg = append(msg, uspv.OutPointToBytes(*op)...)
	msg = append(msg, qc.ChannelNonce[:]...)
	msg = append(msg, qc.MyRefundPub[:]...)
	msg = append(msg, capBytes...)
	msg = append(msg, initPayBytes...)
	msg = append(msg, theirHAKDpub[:]...)
	_, err = RemoteCon.Write(msg)

	return err
}

// QChanDescHandler takes in a description of a channel output.  It then
// saves it to the local db.
func QChanDescHandler(from [16]byte, descbytes []byte) {
	if len(descbytes) < 138 || len(descbytes) > 138 {
		fmt.Printf("got %d byte multiDesc, expect 138", len(descbytes))
		return
	}
	var peerArr, myFirstHAKD, theirRefundPub [33]byte
	var opArr [36]byte
	var cNonce [20]byte
	copy(peerArr[:], RemoteCon.RemotePub.SerializeCompressed())

	// deserialize desc
	copy(opArr[:], descbytes[:36])
	op := uspv.OutPointFromBytes(opArr)
	copy(cNonce[:], descbytes[36:56])
	copy(theirRefundPub[:], descbytes[56:89])
	amt := uspv.BtI64(descbytes[89:97])
	initPay := uspv.BtI64(descbytes[97:105])
	copy(myFirstHAKD[:], descbytes[105:])

	// save to db
	// it should go into the next bucket and get the right key index.
	// but we can't actually check that.
	qc, err := SCon.TS.SaveFundTx(op, amt, peerArr, theirRefundPub, cNonce)
	if err != nil {
		fmt.Printf("QChanDescHandler SaveFundTx err %s", err.Error())
		return
	}
	fmt.Printf("got multisig output %s amt %d\n", op.String(), amt)
	// before acking, add to bloom filter.  Otherwise we won't see it as
	// it doesn't involve our utxos / adrs.
	err = SCon.TS.RefilterLocal()
	if err != nil {
		fmt.Printf("QChanDescHandler RefilterLocal err %s", err.Error())
		return
	}

	// create initial state
	qc.State = new(uspv.StatCom)
	// similar to SIGREV in pushpull
	qc.State.MyAmt = initPay
	qc.State.StateIdx = 1
	// use new HAKDpub for signing
	qc.State.MyHAKDPub = myFirstHAKD

	// create empty elkrem pair
	qc.ElkRcv = new(elkrem.ElkremReceiver)
	qc.ElkSnd = new(elkrem.ElkremSender)

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

	elk, err := qc.ElkSnd.AtIndex(qc.State.StateIdx - 1)
	if err != nil {
		fmt.Printf("QChanDescHandler ElkSnd err %s", err.Error())
		return
	}
	// ACK the channel address, which causes the funder to sign / broadcast
	// ACK is outpoint (36), refund pub (33), HAKD (33) and signature (~70)
	// except you don't need the outpoint if you have the signature...
	msg := []byte{uspv.MSGID_CHANACK}
	msg = append(msg, uspv.OutPointToBytes(*op)...)
	msg = append(msg, qc.MyRefundPub[:]...)
	msg = append(msg, theirHAKDpub[:]...)
	msg = append(msg, elk.Bytes()...)
	msg = append(msg, sig...)
	_, err = RemoteCon.Write(msg)
	return
}

// QChanAckHandler takes in an acknowledgement multisig description.
// when a multisig outpoint is ackd, that causes the funder to sign and broadcast.
func QChanAckHandler(from [16]byte, ackbytes []byte) {
	if len(ackbytes) < 200 || len(ackbytes) > 210 {
		fmt.Printf("got %d byte multiAck, expect ~205\n", len(ackbytes))
		return
	}
	var opArr [36]byte
	var peerArr, myFirstHAKD, refund [33]byte

	copy(peerArr[:], RemoteCon.RemotePub.SerializeCompressed())
	// deserialize chanACK
	copy(opArr[:], ackbytes[:36])
	copy(refund[:], ackbytes[36:69])
	copy(myFirstHAKD[:], ackbytes[69:102])
	revElk, err := wire.NewShaHash(ackbytes[102:134])
	if err != nil {
		fmt.Printf("QChanAckHandler err %s", err.Error())
		return
	}
	sig := ackbytes[134:]

	op := uspv.OutPointFromBytes(opArr)

	// load channel to save their refund address
	qc, err := SCon.TS.GetQchan(peerArr, opArr)
	if err != nil {
		fmt.Printf("QChanAckHandler err %s", err.Error())
		return
	}

	// set refund here instead of reloading...
	qc.TheirRefundPub = refund
	// save the refund address they gave us.  Save state doesn't do this.
	err = SCon.TS.SetQchanRefund(qc, refund)
	if err != nil {
		fmt.Printf("QChanAckHandler err %s", err.Error())
		return
	}
	err = qc.VerifySig(sig)
	if err != nil {
		fmt.Printf("QChanAckHandler err %s", err.Error())
		return
	}
	qc.State.MyHAKDPub = myFirstHAKD

	err = qc.IngestElkrem(revElk)
	if err != nil { // this can't happen because it's the first elk... remove?
		fmt.Printf("QChanAckHandler err %s", err.Error())
		return
	}

	// verify worked; Save state 1 to DB
	err = SCon.TS.SaveQchanState(qc)
	if err != nil {
		fmt.Printf("QChanAckHandler err %s", err.Error())
		return
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

	elk, err := qc.ElkSnd.AtIndex(qc.State.StateIdx - 1)
	if err != nil {
		fmt.Printf("QChanAckHandler err %s", err.Error())
		return
	}

	// sig proof should be sent later once there are confirmations.
	// it'll have an spv proof of the fund tx.
	// but for now just send the sig.
	msg := []byte{uspv.MSGID_SIGPROOF}
	msg = append(msg, uspv.OutPointToBytes(*op)...)
	msg = append(msg, elk.Bytes()...)
	msg = append(msg, sig...)
	_, err = RemoteCon.Write(msg)
	return
}

// QChanAckHandler takes in an acknowledgement multisig description.
// when a multisig outpoint is ackd, that causes the funder to sign and broadcast.
func SigProofHandler(from [16]byte, sigproofbytes []byte) {
	if len(sigproofbytes) < 130 || len(sigproofbytes) > 140 {
		fmt.Printf("got %d byte Sigproof, expect ~137\n", len(sigproofbytes))
		return
	}
	var peerArr [33]byte
	var opArr [36]byte
	copy(peerArr[:], RemoteCon.RemotePub.SerializeCompressed())
	copy(opArr[:], sigproofbytes[:36])
	revElk, err := wire.NewShaHash(sigproofbytes[36:68])
	if err != nil {
		fmt.Printf("SigProofHandler err %s", err.Error())
		return
	}
	sig := sigproofbytes[68:]

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
	err = qc.IngestElkrem(revElk)
	if err != nil { // this can't happen because it's the first elk... remove?
		fmt.Printf("SigProofHandler err %s", err.Error())
		return
	}

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
