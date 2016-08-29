package main

import (
	"fmt"
	"strconv"
	"time"
)

// Resume is a shell command which resumes a message exchange for channels that
// are in a non-final state.  If the channel is in a final state it will send
// a REV (which it already sent, and should be ignored)
func Resume(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("need args: fix peerIdx chanIdx")
	}
	if RemoteCon == nil || RemoteCon.RemotePub == nil {
		return fmt.Errorf("Not connected to anyone, can't fix\n")
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
	peerIdx := uint32(peerIdx64)
	cIdx := uint32(cIdx64)

	// find the peer index of who we're connected to
	currentPeerIdx, err := LNode.GetPeerIdx(RemoteCon.RemotePub)
	if err != nil {
		return err
	}
	if uint32(peerIdx) != currentPeerIdx {
		return fmt.Errorf("Want to close with peer %d but connected to %d",
			peerIdx, currentPeerIdx)
	}
	fmt.Printf("fix channel (%d,%d)\n", peerIdx, cIdx)

	qc, err := LNode.GetQchanByIdx(peerIdx, cIdx)
	if err != nil {
		return err
	}

	return SendNextMsg(qc)
}

// Push is the shell command which calls PushChannel
func Push(args []string) error {
	if len(args) < 3 {
		return fmt.Errorf("need args: push peerIdx chanIdx amt (times)")
	}
	if RemoteCon == nil || RemoteCon.RemotePub == nil {
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
	times := int64(1)
	if len(args) > 3 {
		times, err = strconv.ParseInt(args[3], 10, 32)
		if err != nil {
			return err
		}
	}

	if amt > 100000000 || amt < 1 {
		return fmt.Errorf("push %d, max push is 1 coin / 100000000", amt)
	}
	peerIdx := uint32(peerIdx64)
	cIdx := uint32(cIdx64)

	// find the peer index of who we're connected to
	currentPeerIdx, err := LNode.GetPeerIdx(RemoteCon.RemotePub)
	if err != nil {
		return err
	}
	if uint32(peerIdx) != currentPeerIdx {
		return fmt.Errorf("Want to push to peer %d but connected to %d",
			peerIdx, currentPeerIdx)
	}
	fmt.Printf("push %d to (%d,%d) %d times\n", amt, peerIdx, cIdx, times)

	qc, err := LNode.GetQchanByIdx(peerIdx, cIdx)
	if err != nil {
		return err
	}
	if qc.CloseData.Closed {
		return fmt.Errorf("channel %d, %d is closed.", peerIdx, cIdx64)
	}
	for times > 0 {
		err = LNode.ReloadQchan(qc)
		if err != nil {
			return err
		}

		err = PushChannel(qc, uint32(amt))
		if err != nil {
			return err
		}
		// such a hack.. obviously need indicator of when state update complete
		time.Sleep(time.Millisecond * 25)
		times--
	}
	return nil
}
