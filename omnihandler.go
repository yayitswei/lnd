package main

import (
	"fmt"
	"net"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil/txsort"
	"github.com/lightningnetwork/lnd/uspv"
	"github.com/lightningnetwork/lnd/uspv/uwire"
)

// Mult makes a multisig address with the node connected to
func Mult(args []string) error {
	if RemoteCon == nil {
		return fmt.Errorf("Not connected to anyone\n")
	}
	msg := []byte{uwire.MSGID_PUBREQ}
	_, err := RemoteCon.Write(msg)
	return err
}

func MultiReqHandler(from [16]byte) {
	pub, idx, err := SCon.TS.NewPub()
	if err != nil {
		fmt.Printf("MultiReqHandler error: %s", err.Error())
	}
	fmt.Printf("Generated pubkey %d: %x\n", idx, pub.SerializeCompressed())
	msg := []byte{uwire.MSGID_PUBRESP}
	msg = append(msg, pub.SerializeCompressed()...)

	_, err = RemoteCon.Write(msg)
	return
}

func MultiRespHandler(from [16]byte, pubbytes []byte) {
	if len(pubbytes) != 33 {
		fmt.Printf("pubkey is %d bytes, expect 33\n", len(pubbytes))
		return
	}
	theirPub, err := btcec.ParsePubKey(pubbytes, btcec.S256())
	if err != nil {
		fmt.Printf(err.Error())
		return
	}

	fmt.Printf("got pubkey response %x\n", theirPub.SerializeCompressed())
	// now build a multisig output

	// make our own pubkey
	myPub, idx, err := SCon.TS.NewPub()
	if err != nil {
		fmt.Printf(err.Error())
		return
	}

	txo, err := uspv.FundMultiOut(
		theirPub.SerializeCompressed(), myPub.SerializeCompressed(), 100000000)
	if err != nil {
		fmt.Printf(err.Error())
		return
	}

	utxos, overshoot, err := SCon.PickUtxos(100000000)
	if err != nil {
		fmt.Printf(err.Error())
		return
	}

	tx := wire.NewMsgTx() // make new tx
	tx.AddTxOut(txo)      // add multisig output

	changeOut, err := SCon.TS.NewChangeOut(overshoot)
	if err != nil {
		fmt.Printf(err.Error())
		return
	}
	tx.AddTxOut(changeOut) // add change output
	txsort.InPlaceSort(tx)

	fmt.Printf("overshoot %d pub idx %d; made output script: %x\n",
		overshoot, idx, txo.PkScript)
	for _, utxo := range utxos {
		tx.AddTxIn(wire.NewTxIn(&utxo.Op, nil, nil))
	}

	fmt.Printf("tx:%s ", uspv.TxToString(tx))

	return
}

func MultiDescHandler(from [16]byte, descbytes []byte) {
	// if len(descbytes) != 33 {
	//		return
	// }

	fmt.Printf("got multisig output %x\n", descbytes)
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
		}

		fmt.Printf("Unknown message id byte %x", msgid)
		continue
	}
}

// Every lndc has one of these running
// it listens for incoming messages on the lndc and hands it over
// to the OmniHandler via omnichan
func LNDCReceiver(l net.Conn, id [16]byte, OmniChan chan []byte) error {
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
