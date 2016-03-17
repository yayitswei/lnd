package main

import (
	"fmt"
	"net"

	"github.com/lightningnetwork/lnd/uspv/uwire"
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
		if msgid == uwire.MSGID_TEXTCHAT { //it's text
			fmt.Printf("text from %x: %s\n", from, msg[1:])
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
