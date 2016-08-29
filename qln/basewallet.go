package qln

import (
	"github.com/lightningnetwork/lnd/portxo"
	"github.com/roasbeef/btcd/chaincfg"
	"github.com/roasbeef/btcd/wire"
)

type UWallet interface {
	// Ask for a pubkey based on a bip32 path
	GetPub(k portxo.KeyGen) [33]byte

	// Send a tx out to the network.  Maybe could eliminate
	PushTx(tx *wire.MsgTx) error

	// Ask for network parameters
	Params() *chaincfg.Params
}
