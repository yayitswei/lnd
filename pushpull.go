package main

import "fmt"

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
