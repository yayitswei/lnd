package main

import (
	"fmt"
	"net"

	"github.com/lightningnetwork/lnd/qln"
)

// handles stuff that comes in over the wire.  Not user-initiated.
func OmniHandler(OmniChan chan []byte) {
	var from [16]byte
	for {
		newdata := <-OmniChan // blocks here
		if len(newdata) < 17 {
			fmt.Printf("got too short a message")
			continue
		}
		copy(from[:], newdata[:16])
		msg := newdata[16:]
		msgid := msg[0]

		// TEXT MESSAGE.  SIMPLE
		if msgid == qln.MSGID_TEXTCHAT { //it's text
			fmt.Printf("text from %x: %s\n", from, msg[1:])
			continue
		}
		// POINT REQUEST
		if msgid == qln.MSGID_POINTREQ {
			fmt.Printf("Got point request from %x\n", from)
			PointReqHandler(from, msg[1:])
			continue
		}
		// POINT RESPONSE
		if msgid == qln.MSGID_POINTRESP {
			fmt.Printf("Got point response from %x\n", from)
			PointRespHandler(from, msg[1:])
			continue
		}
		// CHANNEL DESCRIPTION
		if msgid == qln.MSGID_CHANDESC {
			fmt.Printf("Got channel description from %x\n", from)
			QChanDescHandler(from, msg[1:])
			continue
		}
		// CHANNEL ACKNOWLEDGE
		if msgid == qln.MSGID_CHANACK {
			fmt.Printf("Got channel acknowledgement from %x\n", from)
			QChanAckHandler(from, msg[1:])
			continue
		}
		// HERE'S YOUR CHANNEL
		if msgid == qln.MSGID_SIGPROOF {
			fmt.Printf("Got channel proof from %x\n", from)
			SigProofHandler(from, msg[1:])
			continue
		}
		// CLOSE REQ
		if msgid == qln.MSGID_CLOSEREQ {
			fmt.Printf("Got close request from %x\n", from)
			CloseReqHandler(from, msg[1:])
			continue
		}
		// CLOSE RESP
		//		if msgid == uspv.MSGID_CLOSERESP {
		//			fmt.Printf("Got close response from %x\n", from)
		//			CloseRespHandler(from, msg[1:])
		//			continue
		//		}
		// REQUEST TO SEND
		if msgid == qln.MSGID_RTS {
			fmt.Printf("Got RTS from %x\n", from)
			RTSHandler(from, msg[1:])
			continue
		}
		// CHANNEL UPDATE ACKNOWLEDGE AND SIGNATURE
		if msgid == qln.MSGID_ACKSIG {
			fmt.Printf("Got ACKSIG from %x\n", from)
			ACKSIGHandler(from, msg[1:])
			continue
		}
		// SIGNATURE AND REVOCATION
		if msgid == qln.MSGID_SIGREV {
			fmt.Printf("Got SIGREV from %x\n", from)
			SIGREVHandler(from, msg[1:])
			continue
		}
		// REVOCATION
		if msgid == qln.MSGID_REVOKE {
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
	_, err := LNode.NewPeer(RemoteCon.RemotePub)
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
		//		fmt.Printf("incoming msg %x\n", msg)
		OmniChan <- msg
	}
}
