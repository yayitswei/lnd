package qln

import (
	"github.com/lightningnetwork/lnd/portxo"
	"github.com/roasbeef/btcutil/hdkeychain"
)

const (
	// high 3 bytes are in sequence, low 3 bytes are in time
	seqMask  = 0xff000000 // assert high byte
	timeMask = 0x21000000 // 1987 to 1988

	MSGID_POINTREQ  = 0x30
	MSGID_POINTRESP = 0x31
	MSGID_CHANDESC  = 0x32
	MSGID_CHANACK   = 0x33
	MSGID_SIGPROOF  = 0x34

	MSGID_CLOSEREQ  = 0x40
	MSGID_CLOSERESP = 0x41

	MSGID_TEXTCHAT = 0x70

	MSGID_RTS    = 0x80 // pushing funds in channel; request to send
	MSGID_ACKSIG = 0x81 // pulling funds in channel; acknowledge update and sign
	MSGID_SIGREV = 0x82 // pushing funds; signing new state and revoking old
	MSGID_REVOKE = 0x83 // pulling funds; revoking previous channel state

	MSGID_FWDMSG     = 0x20
	MSGID_FWDAUTHREQ = 0x21
)

const (
	UseWallet          = 0 + hdkeychain.HardenedKeyStart
	UseChannelFund     = 2 + hdkeychain.HardenedKeyStart
	UseChannelRefund   = 3 + hdkeychain.HardenedKeyStart
	UseChannelHAKDBase = 4 + hdkeychain.HardenedKeyStart
	UseChannelElkrem   = 8 + hdkeychain.HardenedKeyStart
	// links Id and channel. replaces UseChannelFund
	UseChannelNonce = 10 + hdkeychain.HardenedKeyStart

	UseIdKey = 11 + hdkeychain.HardenedKeyStart
)

func (nd *LnNode) GetUsePub(k portxo.KeyGen, use uint32) [33]byte {
	k.Step[2] = use
	return nd.BaseWallet.GetPub(k)
}
