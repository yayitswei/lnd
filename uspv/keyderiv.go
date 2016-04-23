package uspv

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/hdkeychain"
)

/*
Key derivation for a TxStore has 3 levels: use case, peer index, and keyindex.
Regular wallet addresses are use 0, peer 0, and then a linear index.
The identity key is use 11, peer 0, index 0.
Channel multisig keys are use 2, peer and index per peer and channel.
Channel refund keys are use 3, peer and index per peer / channel.
*/

const (
	UseWallet        = 0
	UseChannelFund   = 2
	UseChannelRefund = 3
	UseChannelElkrem = 4
	UseIdKey         = 11
)

// GetPrivkey generates and returns a private key derived from the seed.
// It will return nil if there's an error / problem, but there shouldn't be
// unless the root key itself isn't there or something.
// All other specialized derivation functions should call this.
func (ts *TxStore) GetPrivkey(use, peerIdx, cIdx uint32) *btcec.PrivateKey {
	multiRoot, err := ts.rootPrivKey.Child(use + hdkeychain.HardenedKeyStart)
	if err != nil {
		fmt.Printf("GetPrivkey err %s", err.Error())
		return nil
	}
	peerRoot, err := multiRoot.Child(peerIdx + hdkeychain.HardenedKeyStart)
	if err != nil {
		fmt.Printf("GetPrivkey err %s", err.Error())
		return nil
	}
	multiChild, err := peerRoot.Child(cIdx + hdkeychain.HardenedKeyStart)
	if err != nil {
		fmt.Printf("GetPrivkey err %s", err.Error())
		return nil
	}
	priv, err := multiChild.ECPrivKey()
	if err != nil {
		fmt.Printf("GetPrivkey err %s", err.Error())
		return nil
	}
	pubbyte := priv.PubKey().SerializeCompressed()
	fmt.Printf("- - -generated %d,%d,%d %x\n",
		use, peerIdx, cIdx, pubbyte[:8])
	return priv
}

// GetPubkey generates and returns the pubkey for a given path.
// It will return nil if there's an error / problem.
func (ts *TxStore) GetPubkey(use, peerIdx, cIdx uint32) *btcec.PublicKey {
	priv := ts.GetPrivkey(use, peerIdx, cIdx)
	if priv == nil {
		fmt.Printf("GetPubkey peer %d idx %d failed", peerIdx, cIdx)
		return nil
	}
	return priv.PubKey()
}

// GetAddress generates and returns the pubkeyhash address for a given path.
// It will return nil if there's an error / problem.
func (ts *TxStore) GetAddress(
	use, peerIdx, cIdx uint32) *btcutil.AddressWitnessPubKeyHash {
	pub := ts.GetPubkey(use, peerIdx, cIdx)
	if pub == nil {
		fmt.Printf("GetAddress %d,%d,%d made nil pub\n", use, peerIdx, cIdx)
		return nil
	}
	adr, err := btcutil.NewAddressWitnessPubKeyHash(
		btcutil.Hash160(pub.SerializeCompressed()), ts.Param)
	if err != nil {
		fmt.Printf("GetAddress %d,%d,%d made nil pub\n", use, peerIdx, cIdx)
		return nil
	}
	return adr
}

// IdKey returns the identity private key, which is child(0).child(0) from root
func (t *TxStore) IdKey() *btcec.PrivateKey {
	return t.GetPrivkey(UseIdKey, 0, 0)
}

// get a private key from the regular wallet
func (ts *TxStore) GetWalletPrivkey(idx uint32) *btcec.PrivateKey {
	return ts.GetPrivkey(UseWallet, 0, idx)
}

// get a public key from the regular wallet
func (ts *TxStore) GetWalletAddress(idx uint32) *btcutil.AddressWitnessPubKeyHash {
	return ts.GetAddress(UseWallet, 0, idx)
}

// GetFundPrivkey generates and returns the private key for a given peer, index.
// It will return nil if there's an error / problem, but there shouldn't be
// unless the root key itself isn't there or something.
func (ts *TxStore) GetFundPrivkey(peerIdx, cIdx uint32) *btcec.PrivateKey {
	return ts.GetPrivkey(UseChannelFund, peerIdx, cIdx)
}

// GetFundPubkey generates and returns the fund tx pubkey for a given index.
// It will return nil if there's an error / problem
func (ts *TxStore) GetFundPubkey(peerIdx, cIdx uint32) *btcec.PublicKey {
	return ts.GetPubkey(UseChannelFund, peerIdx, cIdx)
}

// GetFundAddress... like GetFundPubkey but hashes.  Useless/remove?
//func (ts *TxStore) GetFundAddress(
//	peerIdx, cIdx uint32) *btcutil.AddressWitnessPubKeyHash {
//	return ts.GetAddress(UseChannelFund, peerIdx, cIdx)
//}

// GetElkremRoot gives the Elkrem sender root hash for a channel.
func (ts *TxStore) GetElkremRoot(peerIdx, cIdx uint32) wire.ShaHash {
	priv := ts.GetPrivkey(UseChannelElkrem, peerIdx, cIdx)
	return wire.DoubleSha256SH(priv.Serialize())
}

func (ts *TxStore) GetRefundPrivkey(peerIdx, cIdx uint32) *btcec.PrivateKey {
	return ts.GetPrivkey(UseChannelRefund, peerIdx, cIdx)
}

// useless / remove?
//func (ts *TxStore) GetRefundPubkey(peerIdx, cIdx uint32) *btcec.PublicKey {
//	return ts.GetPubkey(UseChannelRefund, peerIdx, cIdx)
//}

func (ts *TxStore) GetRefundAddressBytes(
	peerIdx, cIdx uint32) []byte {
	adr := ts.GetAddress(UseChannelRefund, peerIdx, cIdx)
	if adr == nil {
		return nil
	}
	return adr.ScriptAddress()
}
