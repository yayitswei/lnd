package main

import (
	"fmt"
	"net"
	"strconv"

	"github.com/lightningnetwork/lnd/uspv/uwire"
)

// BreakChannel closes the channel without the other party's involvement.
// The user causing the channel Break has to wait for the OP_CSV timeout
// before funds can be recovered.  Break output addresses are already in the
// DB so you can't specify anything other than which channel to break.
func BreakChannel(args []string) error {
	if RemoteCon == nil {
		return fmt.Errorf("Not connected to anyone\n")
	}

	// need args, fail
	if len(args) < 2 {
		return fmt.Errorf("need args: break peerIdx chanIdx")
	}

	peerIdx, err := strconv.ParseInt(args[0], 10, 32)
	if err != nil {
		return err
	}
	cIdx, err := strconv.ParseInt(args[1], 10, 32)
	if err != nil {
		return err
	}

	qc, err := SCon.TS.GetQchanByIdx(uint32(peerIdx), uint32(cIdx))

	fmt.Printf("%s (%d,%d) h: %d a: %d\n",
		qc.Op.String(), qc.PeerIdx, qc.KeyIdx, qc.AtHeight, qc.Value)


qc.SignNextState()
	return nil
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
			PubReqHandler(from) // goroutine ready
			continue
		}
		// PUBKEY RESPONSE
		if msgid == uwire.MSGID_PUBRESP {
			fmt.Printf("got pubkey response from %x\n", from)
			PubRespHandler(from, msg[1:]) // goroutine ready
			continue
		}
		// MULTISIG DESCTIPTION
		if msgid == uwire.MSGID_MULTIDESC {
			fmt.Printf("Got multisig description from %x\n", from)
			QChanDescHandler(from, msg[1:])
			continue
		}
		// MULTISIG ACK
		if msgid == uwire.MSGID_MULTIACK {
			fmt.Printf("Got multisig ack from %x\n", from)
			QChanAckHandler(from, msg[1:])
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
