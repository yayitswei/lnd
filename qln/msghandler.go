package qln

import (
	"fmt"
	"net"
)

// handles stuff that comes in over the wire.  Not user-initiated.
func (nd LnNode) OmniHandler(OmniChan chan []byte) {
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
		if msgid == MSGID_TEXTCHAT { //it's text
			fmt.Printf("text from %x: %s\n", from, msg[1:])
			continue
		}
		// POINT REQUEST
		if msgid == MSGID_POINTREQ {
			fmt.Printf("Got point request from %x\n", from)
			nd.PointReqHandler(from, msg[1:])
			continue
		}
		// POINT RESPONSE
		if msgid == MSGID_POINTRESP {
			fmt.Printf("Got point response from %x\n", from)
			nd.PointRespHandler(from, msg[1:])
			continue
		}
		// CHANNEL DESCRIPTION
		if msgid == MSGID_CHANDESC {
			fmt.Printf("Got channel description from %x\n", from)
			nd.QChanDescHandler(from, msg[1:])
			continue
		}
		// CHANNEL ACKNOWLEDGE
		if msgid == MSGID_CHANACK {
			fmt.Printf("Got channel acknowledgement from %x\n", from)
			nd.QChanAckHandler(from, msg[1:])
			continue
		}
		// HERE'S YOUR CHANNEL
		if msgid == MSGID_SIGPROOF {
			fmt.Printf("Got channel proof from %x\n", from)
			nd.SigProofHandler(from, msg[1:])
			continue
		}
		// CLOSE REQ
		if msgid == MSGID_CLOSEREQ {
			fmt.Printf("Got close request from %x\n", from)
			nd.CloseReqHandler(from, msg[1:])
			continue
		}
		// CLOSE RESP
		//		if msgid == uspv.MSGID_CLOSERESP {
		//			fmt.Printf("Got close response from %x\n", from)
		//			CloseRespHandler(from, msg[1:])
		//			continue
		//		}
		// REQUEST TO SEND
		if msgid == MSGID_RTS {
			fmt.Printf("Got RTS from %x\n", from)
			nd.RTSHandler(from, msg[1:])
			continue
		}
		// CHANNEL UPDATE ACKNOWLEDGE AND SIGNATURE
		if msgid == MSGID_ACKSIG {
			fmt.Printf("Got ACKSIG from %x\n", from)
			nd.ACKSIGHandler(from, msg[1:])
			continue
		}
		// SIGNATURE AND REVOCATION
		if msgid == MSGID_SIGREV {
			fmt.Printf("Got SIGREV from %x\n", from)
			nd.SIGREVHandler(from, msg[1:])
			continue
		}
		// REVOCATION
		if msgid == MSGID_REVOKE {
			fmt.Printf("Got REVOKE from %x\n", from)
			nd.REVHandler(from, msg[1:])
			continue
		}
		fmt.Printf("Unknown message id byte %x", msgid)
		continue
	}
}

// Every lndc has one of these running
// it listens for incoming messages on the lndc and hands it over
// to the OmniHandler via omnichan
func (nd LnNode) LNDCReceiver(l net.Conn, id [16]byte, OmniChan chan []byte) error {
	// first store peer in DB if not yet known
	_, err := nd.NewPeer(nd.RemoteCon.RemotePub)
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
