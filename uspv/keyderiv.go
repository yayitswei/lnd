package uspv

import (
	"fmt"
	"math/big"

	"github.com/lightningnetwork/lnd/portxo"
	"github.com/roasbeef/btcd/btcec"
	"github.com/roasbeef/btcd/wire"
	"github.com/roasbeef/btcutil"
	"github.com/roasbeef/btcutil/hdkeychain"
)

/*
Key derivation for a TxStore has 3 levels: use case, peer index, and keyindex.
Regular wallet addresses are use 0, peer 0, and then a linear index.
The identity key is use 11, peer 0, index 0.
Channel multisig keys are use 2, peer and index per peer and channel.
Channel refund keys are use 3, peer and index per peer / channel.
*/

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

// PrivKeyAddBytes adds bytes to a private key.
// NOTE that this modifies the key in place, overwriting it!!!!1
// If k is nil, does nothing and doesn't error (k stays nil)
func PrivKeyAddBytes(k *btcec.PrivateKey, b []byte) {
	if k == nil {
		return
	}
	// turn arg bytes into a bigint
	arg := new(big.Int).SetBytes(b)
	// add private key to arg
	k.D.Add(k.D, arg)
	// mod 2^256ish
	k.D.Mod(k.D, btcec.S256().N)
	// new key derived from this sum
	// D is already modified, need to update the pubkey x and y
	k.X, k.Y = btcec.S256().ScalarBaseMult(k.D.Bytes())
	return
}

// PubKeyAddBytes adds bytes to a public key.
// NOTE that this modifies the key in place, overwriting it!!!!1
func PubKeyAddBytes(k *btcec.PublicKey, b []byte) {
	// turn b into a point on the curve
	bx, by := btcec.S256().ScalarBaseMult(b)
	// add arg point to pubkey point
	k.X, k.Y = btcec.S256().Add(bx, by, k.X, k.Y)
	return
}

// multiplies a pubkey point by a scalar
func PubKeyMultBytes(k *btcec.PublicKey, n uint32) {
	b := U32tB(n)
	k.X, k.Y = btcec.S256().ScalarMult(k.X, k.Y, b)
}

// multiply the private key by a coefficient
func PrivKeyMult(k *btcec.PrivateKey, n uint32) {
	bigN := new(big.Int).SetUint64(uint64(n))
	k.D.Mul(k.D, bigN)
	k.D.Mod(k.D, btcec.S256().N)
	k.X, k.Y = btcec.S256().ScalarBaseMult(k.D.Bytes())
}

// PubKeyArrAddBytes adds a byte slice to a serialized point.
// You can't add scalars to a point, so you turn the bytes into a point,
// then add that point.
func PubKeyArrAddBytes(p *[33]byte, b []byte) error {
	pub, err := btcec.ParsePubKey(p[:], btcec.S256())
	if err != nil {
		return err
	}
	// turn b into a point on the curve
	bx, by := pub.ScalarBaseMult(b)
	// add arg point to pubkey point
	pub.X, pub.Y = btcec.S256().Add(bx, by, pub.X, pub.Y)
	copy(p[:], pub.SerializeCompressed())
	return nil
}

// ###########################
// HAKD/Elkrem point functions

// AddPointArrs takes two 33 byte serialized points, adds them, and
// returns the sum as a 33 byte array.
// Silently returns a zero array if there's an input error
func AddPubs(a, b [33]byte) [33]byte {
	var c [33]byte
	apoint, err := btcec.ParsePubKey(a[:], btcec.S256())
	if err != nil {
		return c
	}
	bpoint, err := btcec.ParsePubKey(b[:], btcec.S256())
	if err != nil {
		return c
	}

	apoint.X, apoint.Y = btcec.S256().Add(apoint.X, apoint.Y, bpoint.X, bpoint.Y)
	copy(c[:], apoint.SerializeCompressed())

	return c
}

// HashToPub turns a 32 byte hash into a 33 byte serialized pubkey
func PubFromHash(h wire.ShaHash) (p [33]byte) {
	_, pub := btcec.PrivKeyFromBytes(btcec.S256(), h[:])
	copy(p[:], pub.SerializeCompressed())
	return
}

// IDPointAdd adds an ID pubkey and a derivation point to make a channel pubkey.
func IDPointAdd(id, dp *[32]byte) ([33]byte, error) {

	cPub := new(btcec.PublicKey)
	cPub.Curve = btcec.S256()
	var cPubArr [33]byte

	// deserialize; IDs always start with 02
	idPub, err := IdToPub(*id)
	if err != nil {
		return cPubArr, err
	}
	// deserialize; derivation point starts with 03
	dPoint, err := btcec.ParsePubKey(append([]byte{0x03}, dp[:]...), btcec.S256())
	if err != nil {
		return cPubArr, err
	}

	// add the two points together
	cPub.X, cPub.Y = btcec.S256().Add(idPub.X, idPub.Y, dPoint.X, dPoint.Y)

	// return the new point, serialized
	copy(cPubArr[:], cPub.SerializeCompressed())
	return cPubArr, nil
}

// IDPrivAdd returns a channel pubkey from the sum of two scalars
func IDPrivAdd(idPriv, ds *btcec.PrivateKey) *btcec.PrivateKey {
	cPriv := new(btcec.PrivateKey)
	cPriv.Curve = btcec.S256()

	cPriv.D.Add(idPriv.D, ds.D)
	cPriv.D.Mod(cPriv.D, btcec.S256().N)

	cPriv.X, cPriv.Y = btcec.S256().ScalarBaseMult(cPriv.D.Bytes())
	return cPriv
}

func IdToPub(idArr [32]byte) (*btcec.PublicKey, error) {
	// IDs always start with 02
	return btcec.ParsePubKey(append([]byte{0x02}, idArr[:]...), btcec.S256())
}

// =====================================================================
// OK only use these now

// PathPrivkey returns a private key by descending the given path
// wrapper function for the utxo with checks
func (t *TxStore) PathPrivkey(kg portxo.KeyGen) *btcec.PrivateKey {
	// in uspv, we require path depth of 5
	if kg.Depth != 5 {
		return nil
	}
	priv, err := kg.DerivePrivateKey(t.rootPrivKey)
	if err != nil {
		fmt.Printf("PathPrivkey err %s", err.Error())
		return nil
	}
	return priv
}

// PathPrivkey returns a public key by descending the given path.
func (t *TxStore) PathPubkey(kg portxo.KeyGen) *btcec.PublicKey {
	return t.PathPrivkey(kg).PubKey()
}

// ------------- end of 2 main key deriv functions

// get a private key from the regular wallet
func (t *TxStore) GetWalletPrivkey(idx uint32) *btcec.PrivateKey {
	var kg portxo.KeyGen
	kg.Depth = 5
	kg.Step[0] = 44 + 0x80000000
	kg.Step[1] = 0 + 0x80000000
	kg.Step[2] = UseWallet
	kg.Step[3] = 0 + 0x80000000
	kg.Step[4] = idx + 0x80000000
	return t.PathPrivkey(kg)
}

// get a public key from the regular wallet
func (t *TxStore) GetWalletAddress(idx uint32) *btcutil.AddressWitnessPubKeyHash {
	if t == nil {
		fmt.Printf("GetAddress %d nil txstore\n", idx)
		return nil
	}
	priv := t.GetWalletPrivkey(idx)
	if priv == nil {
		fmt.Printf("GetAddress %d made nil pub\n", idx)
		return nil
	}
	adr, err := btcutil.NewAddressWitnessPubKeyHash(
		btcutil.Hash160(priv.PubKey().SerializeCompressed()), t.Param)
	if err != nil {
		fmt.Printf("GetAddress %d made nil pub\n", idx)
		return nil
	}
	return adr
}

// GetUsePrive generates a private key for the given use case & keypath
func (t *TxStore) GetUsePriv(kg portxo.KeyGen, use uint32) *btcec.PrivateKey {
	kg.Step[2] = use
	return t.PathPrivkey(kg)
}

// GetUsePub generates a pubkey for the given use case & keypath
func (t *TxStore) GetUsePub(kg portxo.KeyGen, use uint32) [33]byte {
	var b [33]byte
	pub := t.GetUsePriv(kg, use).PubKey()
	if pub != nil {
		copy(b[:], pub.SerializeCompressed())
	}
	return b
}

// GetElkremRoot gives the Elkrem sender root hash for a channel.
func (t *TxStore) GetElkremRoot(kg portxo.KeyGen) wire.ShaHash {
	kg.Step[2] = UseChannelElkrem
	priv := t.PathPrivkey(kg)
	return wire.DoubleSha256SH(priv.Serialize())
}

// IdKey returns the identity private key
func (t *TxStore) IdKey() *btcec.PrivateKey {
	var kg portxo.KeyGen
	kg.Depth = 5
	kg.Step[0] = 44 + 0x80000000
	kg.Step[1] = 0 + 0x80000000
	kg.Step[2] = UseIdKey
	kg.Step[3] = 0 + 0x80000000
	kg.Step[4] = 0 + 0x80000000
	return t.PathPrivkey(kg)
}

func (t *TxStore) IdPub() [33]byte {
	var b [33]byte
	k := t.IdKey().PubKey()
	if k != nil {
		copy(b[:], k.SerializeCompressed())
	}
	return b
}

// END of use these now
// =====================================================================

// GetAddress generates and returns the pubkeyhash address for a given path.
// It will return nil if there's an error / problem.
//func (t *TxStore) GetAddress(
//	use, peerIdx, cIdx uint32) *btcutil.AddressWitnessPubKeyHash {
//	pub := t.GetPubkey(use, peerIdx, cIdx)
//	if pub == nil {
//		fmt.Printf("GetAddress %d,%d,%d made nil pub\n", use, peerIdx, cIdx)
//		return nil
//	}
//}

// GetPrivkey generates and returns a private key derived from the seed.
// It will return nil if there's an error / problem, but there shouldn't be
// unless the root key itself isn't there or something.
// All other specialized derivation functions should call this.
//func (t *TxStore) GetPrivkeyx(use, peerIdx, cIdx uint32) *btcec.PrivateKey {
//	multiRoot, err := t.rootPrivKey.Child(use + hdkeychain.HardenedKeyStart)
//	if err != nil {
//		fmt.Printf("GetPrivkey err %s", err.Error())
//		return nil
//	}
//	peerRoot, err := multiRoot.Child(peerIdx + hdkeychain.HardenedKeyStart)
//	if err != nil {
//		fmt.Printf("GetPrivkey err %s", err.Error())
//		return nil
//	}
//	multiChild, err := peerRoot.Child(cIdx + hdkeychain.HardenedKeyStart)
//	if err != nil {
//		fmt.Printf("GetPrivkey err %s", err.Error())
//		return nil
//	}
//	priv, err := multiChild.ECPrivKey()
//	if err != nil {
//		fmt.Printf("GetPrivkey err %s", err.Error())
//		return nil
//	}
//	//	pubbyte := priv.PubKey().SerializeCompressed()
//	//	fmt.Printf("- - -generated %d,%d,%d %x\n",
//	//		use, peerIdx, cIdx, pubbyte[:8])
//	return priv
//}

// GetPubkey generates and returns the pubkey for a given path.
// It will return nil if there's an error / problem.
//func (t *TxStore) GetPubkey(use, peerIdx, cIdx uint32) *btcec.PublicKey {
//	priv := t.GetPrivkey(use, peerIdx, cIdx)
//	if priv == nil {
//		fmt.Printf("GetPubkey peer %d idx %d failed", peerIdx, cIdx)
//		return nil
//	}
//	return priv.PubKey()
//}

// ----- Get fund priv/pub replaced with channel / CKDH? -------------------

// ---------------------------------------------------------

// CreateChannelNonce returns the channel nonce used to get a CKDH.
// Maybe later this nonce can be the hash of some
// provable info, or a merkle root or something.
func (t *TxStore) CreateChanNonce(kg portxo.KeyGen) [20]byte {
	priv := t.GetUsePriv(kg, UseChannelNonce)
	var nonce [20]byte
	copy(nonce[:], btcutil.Hash160(priv.Serialize()))
	return nonce
}

// CalcCKDH calculates the channel key derivation hash from the two
// f is funder ID pub, r is receiver ID pub, cn is channel nonce.
func CalcCKDH(f, r [33]byte, cn [20]byte) wire.ShaHash {
	pre := make([]byte, 86)
	copy(pre[:33], f[:])
	copy(pre[33:66], r[:])
	copy(pre[66:], cn[:])
	return wire.DoubleSha256SH(pre)
}

// CalcChannelPub calculates the two channel pubkeys given a channel nonce.
// f is funder ID pub, r is receiver ID pub, cn is channel nonce.
func CalcChanPubs(f, r [33]byte, cn [20]byte) ([33]byte, [33]byte, error) {
	ckdh := CalcCKDH(f, r, cn)
	err := PubKeyArrAddBytes(&f, ckdh.Bytes())
	if err != nil {
		return f, r, err
	}
	err = PubKeyArrAddBytes(&r, ckdh.Bytes())
	return f, r, err
}

// GetFundAddress... like GetFundPubkey but hashes.  Useless/remove?
//func (ts *TxStore) GetFundAddress(
//	peerIdx, cIdx uint32) *btcutil.AddressWitnessPubKeyHash {
//	return ts.GetAddress(UseChannelFund, peerIdx, cIdx)
//}
