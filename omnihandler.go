package main

import (
	"fmt"
	"net"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/wire"
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
	multiCapacity := int64(100000000) // this will be an arg
	capBytes := uspv.I64tB(multiCapacity)

	// make sure their pubkey is a pubkey
	theirPub, err := btcec.ParsePubKey(theirPubBytes, btcec.S256())
	if err != nil {
		fmt.Printf("MultiRespHandler err %s", err.Error())
		return
	}

	fmt.Printf("got pubkey response %x\n", theirPub.SerializeCompressed())

	tx := wire.NewMsgTx() // make new tx

	// first get inputs
	utxos, overshoot, err := SCon.PickUtxos(multiCapacity, true)
	if err != nil {
		fmt.Printf("MultiRespHandler err %s", err.Error())
		return
	}
	// add all the inputs to the tx
	for _, utxo := range utxos {
		tx.AddTxIn(wire.NewTxIn(&utxo.Op, nil, nil))
	}

	// create change output
	changeOut, err := SCon.TS.NewChangeOut(overshoot)
	if err != nil {
		fmt.Printf("MultiRespHandler err %s", err.Error())
		return
	}

	tx.AddTxOut(changeOut) // add change output

	//	fmt.Printf("overshoot %d pub idx %d; made output script: %x\n",
	//		overshoot, idx, multiOut.PkScript)

	peerBytes := RemoteCon.RemotePub.SerializeCompressed()
	// send partial tx to db to be saved and have output populated
	op, myPubBytes, err := SCon.TS.MakeMultiTx(
		tx, multiCapacity, peerBytes, theirPub)
	if err != nil {
		fmt.Printf("MultiRespHandler err %s", err.Error())
		return
	}

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
	err = SCon.TS.SaveMultiTx(op, amt, peerBytes, theirPub)
	if err != nil {
		fmt.Printf("MultiDescHandler err %s", err.Error())
		return
	}
	fmt.Printf("got multisig output %d coins %x\n", amt, descbytes)
	// before acking, add to bloom filter.

	// ACK the multi address, which causes the funder to sign / broadcast
	// ACK is outpoint (36), that's all.
	msg := []byte{uwire.MSGID_MULTIACK}
	msg = append(msg, uspv.OutPointToBytes(*op)...)
	_, err = RemoteCon.Write(msg)
	return
}

// MultiAckHandler takes in an acknowledgement multisig description.
// when a multisig outpoint is ackd, that causes the funder to sign and broadcast.
func MultiAckHandler(from [16]byte, descbytes []byte) {
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
	err = SCon.TS.SaveMultiTx(op, amt, peerBytes, theirPub)
	if err != nil {
		fmt.Printf("MultiDescHandler err %s", err.Error())
		return
	}
	fmt.Printf("got multisig output %d coins %x\n", amt, descbytes)
	// ACK the multi address, which causes the funder to sign / broadcast
	// ACK is outpoint (36), that's all.
	msg := []byte{uwire.MSGID_MULTIACK}
	msg = append(msg, uspv.OutPointToBytes(*op)...)
	_, err = RemoteCon.Write(msg)
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
