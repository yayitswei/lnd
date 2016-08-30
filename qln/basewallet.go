package qln

import (
	"github.com/lightningnetwork/lnd/portxo"
	"github.com/roasbeef/btcd/btcec"
	"github.com/roasbeef/btcd/chaincfg"
	"github.com/roasbeef/btcd/wire"
)

type UWallet interface {
	// Ask for a pubkey based on a bip32 path
	GetPub(k portxo.KeyGen) *btcec.PublicKey

	// Have GetPriv for now. Get rid of it and have a signing function instead.
	GetPriv(k portxo.KeyGen) *btcec.PrivateKey

	// Send a tx out to the network.  Maybe could eliminate
	PushTx(tx *wire.MsgTx) error

	// Ask for network parameters
	Params() *chaincfg.Params
}

// GetUsePub gets a pubkey from the base wallet, but first modifies
// the "use" step
func (nd *LnNode) GetUsePub(k portxo.KeyGen, use uint32) (pubArr [33]byte) {
	k.Step[2] = use
	pub := nd.BaseWallet.GetPub(k)
	copy(pubArr[:], pub.SerializeCompressed())
	return
}

// Get rid of this function soon and replace with signing function
func (nd *LnNode) GetPriv(k portxo.KeyGen) *btcec.PrivateKey {
	return nd.BaseWallet.GetPriv(k)
}

// GetElkremRoot returns the Elkrem root for a given key path
// gets the use-pub for elkrems and hashes it.
// A little weird because it's a "pub" key you shouldn't reveal.
// either do this or export privkeys... or signing empty txs or something.
func (nd *LnNode) GetElkremRoot(k portxo.KeyGen) wire.ShaHash {
	pubArr := nd.GetUsePub(k, UseChannelElkrem)
	return wire.DoubleSha256SH(pubArr[:])
}
