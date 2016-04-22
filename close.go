package main

import (
	"fmt"
	"strconv"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/lightningnetwork/lnd/uspv"
	"github.com/lightningnetwork/lnd/uspv/uwire"
)

// CloseChannel is a cooperative closing of a channel to a specified address.
func CloseChannel(args []string) error {
	if RemoteCon == nil {
		return fmt.Errorf("Not connected to anyone\n")
	}
	// need args, fail
	if len(args) < 3 {
		return fmt.Errorf("need args: cclose peerIdx chanIdx address")
	}

	peerIdx, err := strconv.ParseInt(args[0], 10, 32)
	if err != nil {
		return err
	}
	cIdx, err := strconv.ParseInt(args[1], 10, 32)
	if err != nil {
		return err
	}

	adr, err := btcutil.DecodeAddress(args[2], SCon.TS.Param)
	if err != nil {
		fmt.Printf("error parsing %s as address\t", args[0])
		return err
	}

	// find the peer index of who we're connected to
	currentPeerIdx, err := SCon.TS.GetPeerIdx(RemoteCon.RemotePub)
	if err != nil {
		return err
	}
	if uint32(peerIdx) != currentPeerIdx {
		return fmt.Errorf("Want to close with peer %d but connected to %d	",
			peerIdx, currentPeerIdx)
	}

	// get all multi txs
	qcs, err := SCon.TS.GetAllQchans()
	if err != nil {
		return err
	}
	var found bool
	var opBytes []byte
	// find the multi we want to close
	for _, m := range qcs {
		if m.PeerIdx == currentPeerIdx && m.KeyIdx == uint32(cIdx) {
			opBytes = uspv.OutPointToBytes(m.Op)
			fmt.Printf("peerIdx %d multIdx %d height %d %s amt: %d\n",
				m.PeerIdx, m.KeyIdx, m.AtHeight, m.Op.String(), m.Value)
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("channel (%d,%d) not found in db", peerIdx, cIdx)
	}

	// save to db the address we want to close to.
	peerBytes := RemoteCon.RemotePub.SerializeCompressed()
	var opArr [36]byte
	copy(opArr[:], opBytes)
	var adrArr [20]byte
	copy(adrArr[:], adr.ScriptAddress())
	err = SCon.TS.SetChanClose(peerBytes, opArr, adrArr)
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

	mult, err := SCon.TS.GetQchan(peerBytes, opArr)
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
	pre, _, err := uspv.FundTxScript(myPubBytes, theirPubBytes)
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

	adrBytes, err := SCon.TS.GetChanClose(peerBytes, opArr)
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

	mult, err := SCon.TS.GetQchan(peerBytes, opArr)
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
	pre, swap, err := uspv.FundTxScript(myPubBytes, theirPubBytes)
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
