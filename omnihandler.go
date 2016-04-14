package main

import (
	"fmt"
	"net"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/lightningnetwork/lnd/uspv"
	"github.com/lightningnetwork/lnd/uspv/uwire"
)

// Mult makes a multisig address with the node connected to...
// first just request one of their pubkeys (1 byte message)
func Mult(args []string) error {
	if RemoteCon == nil {
		return fmt.Errorf("Not connected to anyone\n")
	}
	msg := []byte{uwire.MSGID_PUBREQ}
	_, err := RemoteCon.Write(msg)
	return err
}

// get a (content-less) pubkey request.  Respond with a pubkey
// note that this only causes a disk read, not a disk write.
// so if someone sends 10 pubkeyreqs, they'll get the same pubkey back 10 times.
// they have to provide an actual tx before the next pubkey will come out.
func MultiReqHandler(from [16]byte) {
	// pub req; check that idx matches next idx of ours and create pubkey
	peerBytes := RemoteCon.RemotePub.SerializeCompressed()
	pub, err := SCon.TS.NextPubForPeer(peerBytes)
	if err != nil {
		fmt.Printf("MultiReqHandler err %s", err.Error())
		return
	}
	fmt.Printf("Generated pubkey %x\n", pub)
	msg := []byte{uwire.MSGID_PUBRESP}
	msg = append(msg, pub...)

	_, err = RemoteCon.Write(msg)
	return
}

// once the pubkey response comes back, we can create the transaction.
// create, save to DB, sign and send over the wire (and broadcast)
func MultiRespHandler(from [16]byte, theirPubBytes []byte) {
	multiCapacity := int64(2000000) // this will be an arg
	satPerByte := int64(80)
	capBytes := uspv.I64tB(multiCapacity)

	// make sure their pubkey is a pubkey
	theirPub, err := btcec.ParsePubKey(theirPubBytes, btcec.S256())
	if err != nil {
		fmt.Printf("MultiRespHandler err %s", err.Error())
		return
	}

	fmt.Printf("got pubkey response %x\n", theirPub.SerializeCompressed())

	tx := wire.NewMsgTx() // make new tx
	//	tx.Flags = 0x01       // tx will be witty

	// first get inputs. comes sorted from PickUtxos.
	utxos, overshoot, err := SCon.PickUtxos(multiCapacity, true)
	if err != nil {
		fmt.Printf("MultiRespHandler err %s", err.Error())
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
		fmt.Printf("MultiRespHandler err %s", err.Error())
		return
	}

	tx.AddTxOut(changeOut) // add change output

	//	fmt.Printf("overshoot %d pub idx %d; made output script: %x\n",
	//		overshoot, idx, multiOut.PkScript)

	peerBytes := RemoteCon.RemotePub.SerializeCompressed()
	// send partial tx to db to be saved and have output populated
	op, myPubBytes, err := SCon.TS.MakeFundTx(
		tx, multiCapacity, peerBytes, theirPub)
	if err != nil {
		fmt.Printf("MultiRespHandler err %s", err.Error())
		return
	}
	// don't need to add to filters; we'll pick the TX up anyway because it
	// spends our utxos.

	// tx saved in DB.  Next then notify peer (then sign and broadcast)
	fmt.Printf("tx:%s ", uspv.TxToString(tx))

	// description is outpoint (36), myPubkey(33), multisig capacity (8)
	msg := []byte{uwire.MSGID_MULTIDESC}
	msg = append(msg, uspv.OutPointToBytes(*op)...)
	msg = append(msg, myPubBytes...)
	// do you actually need to say the capacity?  They'll figure it out...
	// nah, better to send capacity; needed for channel refund
	msg = append(msg, capBytes...)
	_, err = RemoteCon.Write(msg)

	return
}

// MultiDescHandler takes in a description of a multisig output.  It then
// saves it to the local db.
func MultiDescHandler(from [16]byte, descbytes []byte) {
	if len(descbytes) != 77 {
		fmt.Printf("got %d byte multiDesc, expect 77\n", len(descbytes))
		return
	}
	peerBytes := RemoteCon.RemotePub.SerializeCompressed()
	// make sure their pubkey is a pubkey
	theirPub, err := btcec.ParsePubKey(descbytes[36:69], btcec.S256())
	if err != nil {
		fmt.Printf("MultiDescHandler err %s", err.Error())
		return
	}
	// deserialize outpoint
	var opBytes [36]byte
	copy(opBytes[:], descbytes[:36])
	op := uspv.OutPointFromBytes(opBytes)
	amt := uspv.BtI64(descbytes[69:])

	// save to db
	// it should go into the next bucket and get the right key index.
	// but we can't actually check that.
	err = SCon.TS.SaveFundTx(op, amt, peerBytes, theirPub)
	if err != nil {
		fmt.Printf("MultiDescHandler err %s", err.Error())
		return
	}
	fmt.Printf("got multisig output %s amt %d\n", op.String(), amt)
	// before acking, add to bloom filter.  Otherwise we won't see it as
	// it doesn't involve our utxos / adrs.
	err = SCon.TS.RefilterLocal()
	if err != nil {
		fmt.Printf("MultiDescHandler err %s", err.Error())
		return
	}

	// ACK the multi address, which causes the funder to sign / broadcast
	// ACK is outpoint (36), that's all.
	msg := []byte{uwire.MSGID_MULTIACK}
	msg = append(msg, uspv.OutPointToBytes(*op)...)
	_, err = RemoteCon.Write(msg)
	return
}

// MultiAckHandler takes in an acknowledgement multisig description.
// when a multisig outpoint is ackd, that causes the funder to sign and broadcast.
func MultiAckHandler(from [16]byte, ackbytes []byte) {
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
		fmt.Printf("MultiAckHandler err %s", err.Error())
		return
	}
	fmt.Printf("tx to broadcast: %s ", uspv.TxToString(tx))
	err = SCon.NewOutgoingTx(tx)
	if err != nil {
		fmt.Printf("MultiAckHandler err %s", err.Error())
		return
	}
	return
}

// MultSend closes / spends from a shared multisig output.
func MultSend(args []string) error {
	if RemoteCon == nil {
		return fmt.Errorf("Not connected to anyone\n")
	}
	// need args, fail
	if len(args) < 1 {
		return fmt.Errorf("need args: msend address")
	}

	adr, err := btcutil.DecodeAddress(args[0], SCon.TS.Param)
	if err != nil {
		fmt.Printf("error parsing %s as address\t", args[0])
		return err
	}

	// find the peer index of who we're connected to
	currentPeerIdx, err := SCon.TS.GetPeerIdx(RemoteCon.RemotePub)
	if err != nil {
		return err
	}
	// get all multi txs
	multis, err := SCon.TS.GetAllMultiOuts()
	if err != nil {
		return err
	}
	var opBytes []byte
	// find the multi we want to close
	for _, m := range multis {
		if m.PeerIdx == currentPeerIdx {
			opBytes = uspv.OutPointToBytes(m.Op)
			fmt.Printf("peerIdx %d multIdx %d height %d %s amt: %d\n",
				m.PeerIdx, m.KeyIdx, m.AtHeight, m.Op.String(), m.Value)
			break
		}
	}

	// save to db the address we want to close to.
	peerBytes := RemoteCon.RemotePub.SerializeCompressed()
	var opArr [36]byte
	copy(opArr[:], opBytes)
	var adrArr [20]byte
	copy(adrArr[:], adr.ScriptAddress())
	err = SCon.TS.SetMultiClose(peerBytes, opArr, adrArr)
	if err != nil {
		return err
	}

	// close request specifies the outpoint, and the dest address.
	// (no amounts yet, fixed fee of 8K sat. specify these later of course.)
	msg := []byte{uwire.MSGID_CLOSEREQ}
	msg = append(msg, opBytes...)
	msg = append(msg, adr.ScriptAddress()...)

	fmt.Printf("msg: %x\n", msg)

	_, err = RemoteCon.Write(msg)
	return nil
}

// CloseReqHandler takes in a close request from a remote host, signs and
// responds with a close response.  Obviously later there will be some judgment
// over what to do, but for now it just signs whatever it's requested to.
func CloseReqHandler(from [16]byte, reqbytes []byte) {
	if len(reqbytes) != 56 {
		fmt.Printf("got %d byte closereq, expect 56\n", len(reqbytes))
		return
	}
	fee := int64(8000) // fix fixed fee later

	peerBytes := RemoteCon.RemotePub.SerializeCompressed()
	// deserialize outpoint
	var opArr [36]byte
	copy(opArr[:], reqbytes[:36])
	op := uspv.OutPointFromBytes(opArr)
	adrBytes := reqbytes[36:] // 20 byte address (put a 0x00 in front)

	mult, err := SCon.TS.GetMultiOut(peerBytes, opArr)
	if err != nil {
		fmt.Printf("CloseReqHandler err %s", err.Error())
		return
	}
	fmt.Printf("___Got close req for %s. our key is %d, %d, their key is %x\n",
		op.String(), mult.PeerIdx, mult.KeyIdx, mult.TheirPub.SerializeCompressed())

	// we have the data needed to make the tx; make tx, sign, and send sig.
	tx := wire.NewMsgTx() // make new tx

	// get private key for this (need pubkey now but will need priv soon)
	priv := SCon.TS.GetFundPrivkey(mult.PeerIdx, mult.KeyIdx)
	// get pubkey for prev script (preimage)
	myPubBytes := priv.PubKey().SerializeCompressed()
	theirPubBytes := mult.TheirPub.SerializeCompressed()
	// reconstruct output script (preimage)
	// don't care if swapped as not aggregating signatures
	pre, _, err := uspv.FundMultiPre(myPubBytes, theirPubBytes)
	if err != nil {
		fmt.Printf("CloseReqHandler err %s", err.Error())
		return
	}

	subScript := uspv.P2WSHify(pre)
	fmt.Printf("\n\t\t>>> recovered subscript: %x\npre: %x\n\n", subScript, pre)
	fmt.Printf("spending multi %s\n", mult.Op.String())
	// add multi input, with no subscript or witness or anything.
	tx.AddTxIn(wire.NewTxIn(op, nil, nil))

	// generate address from the 20 pubkey hash they sent us
	wa, err := btcutil.NewAddressWitnessPubKeyHash(adrBytes, SCon.TS.Param)
	if err != nil {
		fmt.Printf("CloseReqHandler err %s", err.Error())
		return
	}
	// make script from address (seems a bit redundant; they could send directly)
	outputScript, err := txscript.PayToAddrScript(wa)
	if err != nil {
		fmt.Printf("CloseReqHandler err %s", err.Error())
		return
	}

	tx.AddTxOut(wire.NewTxOut(mult.Value-fee, outputScript))

	hCache := txscript.NewTxSigHashes(tx)
	// generate sig.  Use Raw because we don't want the pubkey
	sig, err := txscript.RawTxInWitnessSignature(
		tx, hCache, 0, mult.Value, pre, txscript.SigHashAll, priv)
	if err != nil {
		fmt.Printf("CloseReqHandler err %s", err.Error())
		return
	}

	fmt.Printf("generated sig %x\n", sig)

	msg := []byte{uwire.MSGID_CLOSERESP}
	msg = append(msg, opArr[:]...)
	msg = append(msg, sig...)
	_, err = RemoteCon.Write(msg)

	return
}

// CloseRespHandler takes the close response, which contains a sig, also
// constructs and signs the tx, and then broadcasts the tx.
func CloseRespHandler(from [16]byte, respbytes []byte) {
	// variable length sigs, boo.
	if len(respbytes) < 100 || len(respbytes) > 150 {
		fmt.Printf("got %d byte closereq, expect 100ish \n", len(respbytes))
		return
	}

	fee := int64(8000) // fix fixed fee later

	peerBytes := RemoteCon.RemotePub.SerializeCompressed()
	// deserialize outpoint
	var opArr [36]byte
	copy(opArr[:], respbytes[:36])
	op := uspv.OutPointFromBytes(opArr)
	theirSig := respbytes[36:] // sig is everything after the outpoint

	adrBytes, err := SCon.TS.GetMultiClose(peerBytes, opArr)
	if err != nil {
		fmt.Printf("CloseRespHandler err %s", err.Error())
		return
	}
	fmt.Printf("got adrBytes: %x (len %d)\n", adrBytes, len(adrBytes))
	// -----uglyness start-----
	// from here down, it's ugly because it's mostly just copying what
	// CloseReqHandler does... just instead of sending the sig over at the end,
	// it uses both sigs and broadcasts.  Probably should break this middle
	// part out into its own function or something.

	mult, err := SCon.TS.GetMultiOut(peerBytes, opArr)
	if err != nil {
		fmt.Printf("CloseRespHandler err %s", err.Error())
		return
	}

	// we have the data needed to make the tx; make tx, sign, and send sig.
	tx := wire.NewMsgTx() // make new tx
	//	tx.Flags = 0x01       // tx will be witty

	// get private key for this (need pubkey now but will need priv soon)
	priv := SCon.TS.GetFundPrivkey(mult.PeerIdx, mult.KeyIdx)
	// get pubkey for prev script (preimage)
	myPubBytes := priv.PubKey().SerializeCompressed()
	theirPubBytes := mult.TheirPub.SerializeCompressed()
	// reconstruct output script (preimage)
	pre, swap, err := uspv.FundMultiPre(myPubBytes, theirPubBytes)
	if err != nil {
		fmt.Printf("CloseRespHandler err %s", err.Error())
		return
	}

	subScript := uspv.P2WSHify(pre)
	fmt.Printf("\t\t>>> recovered subscript: %x\npre: %x\n", subScript, pre)
	fmt.Printf("spending multi %s\n", mult.Op.String())
	// add multi input, with no subscript or witness or anything.
	tx.AddTxIn(wire.NewTxIn(op, nil, nil))

	// generate address from the 20 pubkey hash they sent us
	wa, err := btcutil.NewAddressWitnessPubKeyHash(adrBytes, SCon.TS.Param)
	if err != nil {
		fmt.Printf("CloseRespHandler err %s", err.Error())
		return
	}
	// make script from address (seems a bit redundant; they could send directly)
	outputScript, err := txscript.PayToAddrScript(wa)
	if err != nil {
		fmt.Printf("CloseRespHandler err %s", err.Error())
		return
	}

	tx.AddTxOut(wire.NewTxOut(mult.Value-fee, outputScript))

	hCache := txscript.NewTxSigHashes(tx)
	// check their sig.
	//	err = txscript.CheckSig(tx, hCache, 0, mult.Value, subScript,
	//		txscript.SigHashAll, mult.TheirPub, theirSig)

	// generate sig.  Use Raw because we don't want the pubkey
	// subscript is the preimage.  mkay.
	mySig, err := txscript.RawTxInWitnessSignature(
		tx, hCache, 0, mult.Value, pre, txscript.SigHashAll, priv)
	if err != nil {
		fmt.Printf("CloseReqHandler err %s", err.Error())
		return
	}

	fmt.Printf("generated sig %x\n", mySig)
	// -----uglyness end-----

	// 2 sigs and a preimage.  AND A ZERO IN THE BEGINNING. STILL.
	if swap {
		tx.TxIn[0].Witness = uspv.SpendMultiSigWitStack(pre, theirSig, mySig)
	} else {
		tx.TxIn[0].Witness = uspv.SpendMultiSigWitStack(pre, mySig, theirSig)
	}
	fmt.Printf("tx to broadcast: %s ", uspv.TxToString(tx))
	err = SCon.NewOutgoingTx(tx)
	if err != nil {
		fmt.Printf("MultiAckHandler err %s", err.Error())
		return
	}

	return
}

// handles stuff that comes in over the wire.  Not user-initiated.
func OmniHandler(OmniChan chan []byte) {
	var from [16]byte
	for {
		newdata := <-OmniChan // blocks here
		if len(newdata) < 17 {
			fmt.Printf("got too short message")
			continue
		}
		copy(from[:], newdata[:16])
		msg := newdata[16:]
		msgid := msg[0]

		// TEXT MESSAGE.  SIMPLE
		if msgid == uwire.MSGID_TEXTCHAT { //it's text
			fmt.Printf("text from %x: %s\n", from, msg[1:])
			continue
		}

		// PUBKEY REQUEST
		if msgid == uwire.MSGID_PUBREQ {
			fmt.Printf("got pubkey req from %x\n", from)
			MultiReqHandler(from) // goroutine ready
			continue
		}
		// PUBKEY RESPONSE
		if msgid == uwire.MSGID_PUBRESP {
			fmt.Printf("got pubkey response from %x\n", from)
			MultiRespHandler(from, msg[1:]) // goroutine ready
			continue
		}
		// MULTISIG DESCTIPTION
		if msgid == uwire.MSGID_MULTIDESC {
			fmt.Printf("Got multisig description from %x\n", from)
			MultiDescHandler(from, msg[1:])
			continue
		}
		// MULTISIG ACK
		if msgid == uwire.MSGID_MULTIACK {
			fmt.Printf("Got multisig ack from %x\n", from)
			MultiAckHandler(from, msg[1:])
			continue
		}
		// CLOSE REQ
		if msgid == uwire.MSGID_CLOSEREQ {
			fmt.Printf("Got close request from %x\n", from)
			CloseReqHandler(from, msg[1:])
			continue
		}
		// CLOSE RESP
		if msgid == uwire.MSGID_CLOSERESP {
			fmt.Printf("Got close response from %x\n", from)
			CloseRespHandler(from, msg[1:])
			continue
		}
		fmt.Printf("Unknown message id byte %x", msgid)
		continue
	}
}

// Every lndc has one of these running
// it listens for incoming messages on the lndc and hands it over
// to the OmniHandler via omnichan
func LNDCReceiver(l net.Conn, id [16]byte, OmniChan chan []byte) error {
	// first store peer in DB if not yet known
	_, err := SCon.TS.NewPeer(RemoteCon.RemotePub)
	if err != nil {
		return err
	}
	for {
		msg := make([]byte, 65535)
		//	fmt.Printf("read message from %x\n", l.RemoteLNId)
		n, err := l.Read(msg)
		if err != nil {
			fmt.Printf("read error with %x: %s\n",
				id, err.Error())
			//			delete(CnMap, id)
			return l.Close()
		}
		msg = msg[:n]
		msg = append(id[:], msg...)
		fmt.Printf("incoming msg %x\n", msg)
		OmniChan <- msg
	}
}
