package main

import (
	"fmt"
	"strconv"

	"github.com/lightningnetwork/lnd/uspv"
)

// Do math, see if this curve thing works.
func Math(args []string) error {
	priv := SCon.TS.GetFundPrivkey(5, 5)

	pub := SCon.TS.GetFundPubkey(5, 5)

	fmt.Printf("initial  pub: %x\n", pub.SerializeCompressed())
	//	for i := 0; i < 10000; i++ {
	uspv.PubKeyAddBytes(pub, []byte("grand"))
	//	}
	fmt.Printf("modified pub: %x\n", pub.SerializeCompressed())

	//	for i := 0; i < 10000; i++ {
	uspv.PrivKeyAddBytes(priv, []byte("grane"))
	//	}
	fmt.Printf("from prv pub: %x\n", priv.PubKey().SerializeCompressed())

	return nil
}

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

	//	qc.NextState = new(uspv.StatCom)
	//	qc.NextState.MyAmt = 1000000
	//	qc.NextState.TheirRevHash = uspv.Hash88
	//	qc.NextState.MyRevHash = uspv.Hash88

	//	sig, err := SCon.TS.SignNextState(qc)
	//	if err != nil {
	//		return err
	//	}
	//	fmt.Printf("made sig: %x\n", sig)

	return nil
}

func PushChannel(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("need args: push peerIdx chanIdx amt")
	}
	if RemoteCon == nil {
		return fmt.Errorf("Not connected to anyone, can't push\n")
	}
	// this stuff is all the same as in cclose, should put into a function...
	peerIdx64, err := strconv.ParseInt(args[0], 10, 32)
	if err != nil {
		return err
	}
	cIdx64, err := strconv.ParseInt(args[1], 10, 32)
	if err != nil {
		return err
	}
	amt, err := strconv.ParseInt(args[2], 10, 32)
	if err != nil {
		return err
	}
	amt++
	peerIdx := uint32(peerIdx64)
	cIdx := uint32(cIdx64)
	// find the peer index of who we're connected to
	currentPeerIdx, err := SCon.TS.GetPeerIdx(RemoteCon.RemotePub)
	if err != nil {
		return err
	}
	if uint32(peerIdx) != currentPeerIdx {
		return fmt.Errorf("Want to close with peer %d but connected to %d",
			peerIdx, currentPeerIdx)
	}
	fmt.Printf("push %d to (%d,%d)\n", peerIdx, cIdx, amt)

	//	qc, err := SCon.TS.GetQchanByIdx(peerIdx, cIdx)
	//	qc.CurrentState = new(uspv.StatCom)
	//	qc.CurrentState.MyAmt = 1000000
	//	qc.CurrentState.MyRevHash = uspv.Hash88
	//	qc.CurrentState.StateIdx = 22
	//	qc.CurrentState.TheirRevHash = uspv.Hash88
	//	qc.CurrentState.Sig = []byte("sig")

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
