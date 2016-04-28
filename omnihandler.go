package main

import (
	"fmt"
	"net"

	"github.com/lightningnetwork/lnd/uspv"
)

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
		if msgid == uspv.MSGID_TEXTCHAT { //it's text
			fmt.Printf("text from %x: %s\n", from, msg[1:])
			continue
		}

		// PUBKEY REQUEST
		if msgid == uspv.MSGID_PUBREQ {
			fmt.Printf("got pubkey req from %x\n", from)
			PubReqHandler(from) // goroutine ready
			continue
		}
		// PUBKEY RESPONSE
		if msgid == uspv.MSGID_PUBRESP {
			fmt.Printf("got pubkey response from %x\n", from)
			PubRespHandler(from, msg[1:]) // goroutine ready
			continue
		}
		// MULTISIG DESCTIPTION
		if msgid == uspv.MSGID_CHANDESC {
			fmt.Printf("Got multisig description from %x\n", from)
			QChanDescHandler(from, msg[1:])
			continue
		}
		// MULTISIG ACK
		if msgid == uspv.MSGID_CHANACK {
			fmt.Printf("Got multisig ack from %x\n", from)
			QChanAckHandler(from, msg[1:])
			continue
		}
		// CLOSE REQ
		if msgid == uspv.MSGID_CLOSEREQ {
			fmt.Printf("Got close request from %x\n", from)
			CloseReqHandler(from, msg[1:])
			continue
		}
		// CLOSE RESP
		if msgid == uspv.MSGID_CLOSERESP {
			fmt.Printf("Got close response from %x\n", from)
			CloseRespHandler(from, msg[1:])
			continue
		}
		if msgid == uspv.MSGID_RTS {
			fmt.Printf("Got RTS from %x\n", from)
			RTSHandler(from, msg[1:])
			continue
		}
		if msgid == uspv.MSGID_ACKSIG {
			fmt.Printf("Got ACKSIG from %x\n", from)
			ACKSIGHandler(from, msg[1:])
			continue
		}
		if msgid == uspv.MSGID_SIGREV {
			fmt.Printf("Got SIGREV from %x\n", from)
			SIGREVHandler(from, msg[1:])
			continue
		}
		if msgid == uspv.MSGID_REVOKE {
			fmt.Printf("Got REVOKE from %x\n", from)
			REVHandler(from, msg[1:])
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
