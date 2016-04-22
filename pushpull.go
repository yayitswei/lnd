package main

import (
	"fmt"
	"strconv"

	"github.com/lightningnetwork/lnd/uspv"
)

var (
	hash88 = [20]byte{0xd7, 0x9f, 0x49, 0x37, 0x1f, 0xb5, 0xd9, 0xe7, 0x92, 0xf0, 0x42, 0x66, 0x4c, 0xd6, 0x89, 0xd5, 0x0e, 0x3d, 0xcf, 0x03}
)

// BreakChannel closes the channel without the other party's involvement.
// The user causing the channel Break has to wait for the OP_CSV timeout
// before funds can be recovered.  Break output addresses are already in the
// DB so you can't specify anything other than which channel to break.
func BreakChannel(args []string) error {
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

	qc.NextState = new(uspv.StatCom)
	qc.NextState.MyAmt = 1000000
	qc.NextState.TheirRevHash = hash88
	qc.NextState.MyRevHash = hash88

	sig, err := SCon.TS.SignNextState(qc)
	if err != nil {
		return err
	}
	fmt.Printf("made sig: %x\n", sig)

	return nil
}

func PushChannel(args []string) error {
	if RemoteCon == nil {
		return fmt.Errorf("Not connected to anyone, can't push\n")
	}

	//	fmt.Printf("push %d to (%d,%d)\n", peerIdx, cIdx, amt)

	return nil
}

// PushChannel pushes money to the other side of the channel.  It
// creates a sigpush message and sends that to the peer
func PushSig(peerIdx, cIdx uint32, amt int64) error {
	if RemoteCon == nil {
		return fmt.Errorf("Not connected to anyone, can't push\n")
	}

	fmt.Printf("push %d to (%d,%d)\n", peerIdx, cIdx, amt)

	return nil
}

//func PullSig(from [16]byte, sigpushBytes []byte) {

//	return
//}
