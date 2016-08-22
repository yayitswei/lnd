package portxo

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/roasbeef/btcd/wire"
)

type TxoMode uint8

// Constants defining txo modes
const (
	// Flags which combined can turn into full utxo modes
	FlagTxoPubKeyHash   TxoMode = 0x01
	FlagTxoScript       TxoMode = 0x02
	FlagTxoWitness      TxoMode = 0x04
	FlagTxoCompressed   TxoMode = 0x08
	FlagTxoUncompressed TxoMode = 0x10

	// fully specified tx output modes
	// raw pubkey outputs (old school)
	TxoP2PKUncomp = FlagTxoUncompressed
	TxoP2PKComp   = FlagTxoCompressed

	// pub key hash outputs, standard p2pkh (common)
	TxoP2PKHUncomp = FlagTxoPubKeyHash | FlagTxoUncompressed
	TxoP2PKHComp   = FlagTxoCompressed | FlagTxoPubKeyHash

	// script hash
	TxoP2SHUncomp = FlagTxoScript | FlagTxoUncompressed
	TxoP2SHComp   = FlagTxoScript | FlagTxoCompressed

	// witness p2wpkh modes
	TxoP2WPKHUncomp = FlagTxoWitness | FlagTxoPubKeyHash | FlagTxoUncompressed
	TxoP2WPKHComp   = FlagTxoWitness | FlagTxoPubKeyHash | FlagTxoCompressed

	// witness script hash
	TxoP2WSHUncomp = FlagTxoWitness | FlagTxoScript | FlagTxoUncompressed
	TxoP2WSHComp   = FlagTxoWitness | FlagTxoScript | FlagTxoCompressed

	// unknown
	TxoUnknownMode = 0x80
)

var modeStrings = map[TxoMode]string{
	TxoP2PKUncomp: "raw pubkey uncompressed",
	TxoP2PKComp:   "raw pubkey compressed",

	TxoP2PKHUncomp: "pubkey hash uncompressed",
	TxoP2PKHComp:   "pubkey hash compressed",

	TxoP2SHUncomp: "script hash uncompressed",
	TxoP2SHComp:   "script hash compressed",

	TxoP2WPKHUncomp: "witness pubkey hash uncompressed",
	TxoP2WPKHComp:   "witness pubkey hash compressed",

	TxoP2WSHUncomp: "witness script hash uncompressed",
	TxoP2WSHComp:   "witness script hash compressed",
}

// String returns the InvType in human-readable form.
func (m TxoMode) String() string {
	s, ok := modeStrings[m]
	if ok {
		return s
	}
	return fmt.Sprintf("unknown TxoMode %x", uint8(m))
}

// KeyDerivationPath describes how to get to the key from the master / seed.
// it can be used with bip44 or other custom schemes (up to 5 levels deep)
// Depth must be 0 to 5 inclusive.  Child indexes of 0 are OK, so we can't just
// terminate at the first 0.
type KeyGen struct {
	Depth   uint8     // how many levels of the path to use
	Step    [5]uint32 // bip 32 / 44 path numbers
	PrivKey [32]byte  // private key
}

// Bytes returns the 53 byte serialized key derivation path.
// always works
func (k KeyGen) Bytes() []byte {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, k.Depth)
	binary.Write(&buf, binary.BigEndian, k.Step[0])
	binary.Write(&buf, binary.BigEndian, k.Step[1])
	binary.Write(&buf, binary.BigEndian, k.Step[2])
	binary.Write(&buf, binary.BigEndian, k.Step[3])
	binary.Write(&buf, binary.BigEndian, k.Step[4])
	buf.Write(k.PrivKey[:])
	return buf.Bytes()
}

// turns a 53 byte array into a key derivation path.  Always works
// (note a depth > 5 path is invalid, but this just deserializes & doesn't check)
func KeyGenFromBytes(b [53]byte) (k KeyGen) {
	buf := bytes.NewBuffer(b[:])
	binary.Read(buf, binary.BigEndian, &k.Depth)
	binary.Read(buf, binary.BigEndian, &k.Step[0])
	binary.Read(buf, binary.BigEndian, &k.Step[1])
	binary.Read(buf, binary.BigEndian, &k.Step[2])
	binary.Read(buf, binary.BigEndian, &k.Step[3])
	binary.Read(buf, binary.BigEndian, &k.Step[4])
	copy(k.PrivKey[:], buf.Next(32))
	return
}

/* Utxos specify a utxo, and all the information needed to spend it.
The first 3 fields (Op, Amt, Mode) are required in all cases.
If KeyGen.Depth != 0, that means no key path is supplied, and PrivKey
is probably empty / ignored.  Having both a KeyGen and a PrivKey is redunant.
Having neither KeyGen nor PrivKey means there's no private key, and no
indication of how to get it; in that case get the private key from somewhere else.

If BOTH KeyGen AND PrivKey are filled in, add em up!  Add the two private keys,
modulo the curve order.

PkScript can also be left empty depending on the mode.  Basically only script-hash
modes need it, as the previous pkscript can be generated
*/

type PorTxo struct {
	// got rid of NetID.  If you want to specify different networks / coins,
	// use KeyGen.Step[1], that's what it's for.
	// Heck, set KeyGen.Depth to 0 and still use Step[1] as the network / coin...
	//	NetID  byte          // indicates what network / coin utxo is in
	Op     wire.OutPoint // unique outpoint
	Value  int64         // higher is better
	Height int32         // block height of utxo (not needed? nice to know?)
	Seq    uint32        // used for relative timelock
	Mode   TxoMode

	KeyGen

	PkScript []byte // if empty, try to generate based on mode and priv key
}

// Compare deep-compares two portable utxos, returning true if they're the same
func (u *PorTxo) Equal(z *PorTxo) bool {
	if u == nil || z == nil {
		return false
	}

	if !u.Op.Hash.IsEqual(&z.Op.Hash) {
		return false
	}
	if u.Op.Index != z.Op.Index {
		return false
	}
	if u.Value != z.Value || u.Seq != z.Seq || u.Mode != z.Mode || u.Height != z.Height {
		return false
	}
	if u.KeyGen.PrivKey != z.KeyGen.PrivKey {
		return false
	}
	if !bytes.Equal(u.KeyGen.Bytes(), z.KeyGen.Bytes()) {
		return false
	}
	if !bytes.Equal(u.PkScript, z.PkScript) {
		return false
	}

	return true
}

func (k KeyGen) String() string {
	var s string
	//	s = fmt.Sprintf("\tkey derivation path: m")
	for i := uint8(0); i < k.Depth; i++ {
		if k.Step[i]&0x80000000 != 0 { // high bit means hardened
			s += fmt.Sprintf(" / %d'", k.Step[i]&0x7fffffff)
		} else {
			s += fmt.Sprintf(" / %d", k.Step[i])
		}
	}
	return s
}

func (u *PorTxo) String() string {
	var s string
	var empty [32]byte
	if u == nil {
		return "nil utxo"
	}
	s = u.Op.String()
	s += fmt.Sprintf("\n\ta:%d h:%d seq:%d %s\n",
		u.Value, u.Height, u.Seq, u.Mode.String())

	if u.KeyGen.PrivKey == empty {
		s += fmt.Sprintf("\tprivate key not available (zero)\n")
	} else {
		s += fmt.Sprintf("\tprivate key available (non-zero)\n")
	}
	if u.KeyGen.Depth == 0 || u.KeyGen.Depth > 5 {
		s += fmt.Sprintf("\tno key derivation path\n")
	} else {
		s += fmt.Sprintf("%s\n", u.KeyGen.String())
	}
	s += fmt.Sprintf("\tPkScript (len %d): %x\n", len(u.PkScript), u.PkScript)
	return s
}

/* serialized (im/ex)Portable Utxos are 106 up to 357 bytes.
Op 36
Amt 8
Height 4
Seq 4
Mode 1
Priv 32
Path 21
Script (0 to 255) starts at byte 106, ends at 106+PKlen
*/

func PorTxoFromBytes(b []byte) (*PorTxo, error) {
	if len(b) < 106 || len(b) > 361 {
		return nil, fmt.Errorf("%d bytes, need 106-361", len(b))
	}

	buf := bytes.NewBuffer(b)

	var u PorTxo
	var err error

	err = u.Op.Hash.SetBytes(buf.Next(32))
	if err != nil {
		return nil, err
	}
	err = binary.Read(buf, binary.BigEndian, &u.Op.Index)
	if err != nil {
		return nil, err
	}
	err = binary.Read(buf, binary.BigEndian, &u.Value)
	if err != nil {
		return nil, err
	}
	err = binary.Read(buf, binary.BigEndian, &u.Height)
	if err != nil {
		return nil, err
	}
	err = binary.Read(buf, binary.BigEndian, &u.Seq)
	if err != nil {
		return nil, err
	}
	err = binary.Read(buf, binary.BigEndian, &u.Mode)
	if err != nil {
		return nil, err
	}

	var kgenarr [53]byte
	copy(kgenarr[:], buf.Next(53))
	u.KeyGen = KeyGenFromBytes(kgenarr)

	u.PkScript = buf.Bytes()
	return &u, nil
}

func (u *PorTxo) Bytes() ([]byte, error) {
	if u == nil {
		return nil, errors.New("Can't serialize nil Utxo")
	}

	var buf bytes.Buffer

	_, err := buf.Write(u.Op.Hash.Bytes())
	if err != nil {
		return nil, err
	}

	err = binary.Write(&buf, binary.BigEndian, u.Op.Index)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&buf, binary.BigEndian, u.Value)
	if err != nil {
		return nil, err
	}
	err = binary.Write(&buf, binary.BigEndian, u.Height)
	if err != nil {
		return nil, err
	}
	err = binary.Write(&buf, binary.BigEndian, u.Seq)
	if err != nil {
		return nil, err
	}
	err = binary.Write(&buf, binary.BigEndian, u.Mode) // mode
	if err != nil {
		return nil, err
	}
	_, err = buf.Write(u.KeyGen.Bytes()) // keypath
	if err != nil {
		return nil, err
	}
	if len(u.PkScript) > 255 {
		return nil, errors.New("PkScript too long (255 byte max)")
	}
	//	err = binary.Write(&buf, binary.BigEndian, uint8(len(u.PkScript))) // PKlen @ 101
	//	if err != nil {
	//		return nil, err
	//	}

	_, err = buf.Write(u.PkScript)
	return buf.Bytes(), nil
}
