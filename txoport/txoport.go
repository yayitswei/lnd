package txoport

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/wire"
)

type TxoMode uint32

// Constants defining txo modes
const (
	// Flags which combined can turn into full utxo modes
	FlagTxoPubKeyHash TxoMode = 0x01
	FlagTxoCompress   TxoMode = 0x02
	FlagTxoScript     TxoMode = 0x04
	FlagTxoWitness    TxoMode = 0x08

	// selectable tx output modes
	// raw pubkey outputs (old school)
	TxoP2PKUncomp = 0
	TxoP2PKComp   = FlagTxoCompress

	// pub key hash outputs, standard p2pkh (common)
	TxoP2PKHUncomp = FlagTxoPubKeyHash
	TxoP2PKHComp   = FlagTxoCompress | FlagTxoPubKeyHash

	// script hash
	TxoP2SHUncomp = FlagTxoScript
	TxoP2SHComp   = FlagTxoScript | FlagTxoCompress

	// witness p2wpkh modes
	TxoP2WPKHUncomp = FlagTxoWitness | FlagTxoPubKeyHash
	TxoP2WPKHComp   = FlagTxoWitness | FlagTxoPubKeyHash | FlagTxoCompress

	// witness script hash
	TxoP2WSHUncomp = FlagTxoWitness | FlagTxoScript
	TxoP2WSHComp   = FlagTxoWitness | FlagTxoScript | FlagTxoCompress
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
	return fmt.Sprintf("unknown TxoMode %x", uint32(m))
}

// KeyDerivationPath describes how to get to the key from the master / seed.
// it can be used with bip44 or other custom schemes (up to 5 levels deep)
// Depth must be 0 to 5 inclusive.  Child indexes of 0 are OK, so we can't just
// terminate at the first 0.
type KeyDerivationPath struct {
	Depth uint8
	Level [5]uint32
}

// Bytes returns the 21 byte serialized key derivation path.
// always works
func (k KeyDerivationPath) Bytes() []byte {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, k.Depth)
	binary.Write(&buf, binary.BigEndian, k.Level[0])
	binary.Write(&buf, binary.BigEndian, k.Level[1])
	binary.Write(&buf, binary.BigEndian, k.Level[2])
	binary.Write(&buf, binary.BigEndian, k.Level[3])
	binary.Write(&buf, binary.BigEndian, k.Level[4])
	return buf.Bytes()
}

// turns a 21 byte array into a key derivation path.  Always works
// (note a depth > 5 path is invalid, but this just deserializes & doesn't check.
func KeyDerivationPathFromBytes(b [21]byte) (k KeyDerivationPath) {
	buf := bytes.NewBuffer(b[:])
	binary.Read(buf, binary.BigEndian, &k.Depth)
	binary.Read(buf, binary.BigEndian, &k.Level[0])
	binary.Read(buf, binary.BigEndian, &k.Level[1])
	binary.Read(buf, binary.BigEndian, &k.Level[2])
	binary.Read(buf, binary.BigEndian, &k.Level[3])
	binary.Read(buf, binary.BigEndian, &k.Level[4])
	return
}

/* Utxos specify a utxo, and all the information needed to spend it.
The first 3 fields (Op, Amt, Mode) are required in all cases.
If KeyPath.Depth != 0, that means no key path is supplied, and PrivKey
is probably empty / ignored.  Having both a KeyPath and a PrivKey is redunant.
Having neither KeyPath nor PrivKey means there's no private key, and no
indication of how to get it; in that case get the private key from somewhere else.

PkScript can also be left empty depending on the mode.  Basically only script-hash
modes need it, as the previous pkscript can be generated
*/

type PortUtxo struct {
	Op   wire.OutPoint // unique outpoint
	Amt  int64         // higher is better
	Seq  uint32        // used for relative timelock
	Mode TxoMode

	PrivKey [32]byte
	KeyPath KeyDerivationPath

	PkScript []byte // for script-hash
}

// Compare deep-compares two portable utxos, returning true if they're the same
func (u *PortUtxo) Equal(z *PortUtxo) bool {
	if u == nil || z == nil {
		return false
	}
	if !u.Op.Hash.IsEqual(&z.Op.Hash) {
		return false
	}
	if u.Op.Index != z.Op.Index {
		return false
	}
	if u.Amt != z.Amt || u.Seq != z.Seq || u.Mode != z.Mode {
		return false
	}
	if u.PrivKey != z.PrivKey {
		return false
	}
	if !bytes.Equal(u.KeyPath.Bytes(), z.KeyPath.Bytes()) {
		return false
	}
	if !bytes.Equal(u.PkScript, z.PkScript) {
		return false
	}

	return true
}

func (u *PortUtxo) String() string {
	var s string
	var empty [32]byte
	if u == nil {
		return "nil utxo"
	}
	s = u.Op.String()
	s += fmt.Sprintf("\n\ta:%d seq:%d %s\n", u.Amt, u.Seq, u.Mode.String())
	if u.PrivKey == empty {
		s += fmt.Sprintf("\tprivate key not available (zero)\n")
	} else {
		s += fmt.Sprintf("\tprivate key available (non-zero)\n")
	}
	if u.KeyPath.Depth == 0 || u.KeyPath.Depth > 5 {
		s += fmt.Sprintf("\tno key derivation path\n")
	} else {
		s += fmt.Sprintf("\tkey derivation path: m")
		for i := uint8(0); i < u.KeyPath.Depth; i++ {
			if u.KeyPath.Level[i]&0x80000000 != 0 { // high bit means hardened
				s += fmt.Sprintf(" / %d'", u.KeyPath.Level[i]&0x7fffffff)
			} else {
				s += fmt.Sprintf(" / %d", u.KeyPath.Level[i])
			}
		}
		s += fmt.Sprintf("\n")
	}
	s += fmt.Sprintf("\tPkScript (len %d): %x\n", len(u.PkScript), u.PkScript)
	return s
}

/* serialized (im/ex)Portable Utxos are 102 up to 357 bytes.
Op 36
Amt 8
Seq 4
Mode 4
Priv 32
Path 21
PKSLen 1
Script (0 to 255) starts at byte 107, ends at 106+PKlen
*/

func PortUtxoFromBytes(b []byte) (*PortUtxo, error) {
	if len(b) < 106 {
		return nil, errors.New("Slice too short (min 106 butes)")
	}

	buf := bytes.NewBuffer(b)

	var u PortUtxo

	err := u.Op.Hash.SetBytes(buf.Next(32))
	if err != nil {
		return nil, err
	}
	err = binary.Read(buf, binary.BigEndian, &u.Op.Index)
	if err != nil {
		return nil, err
	}
	err = binary.Read(buf, binary.BigEndian, &u.Amt)
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
	copy(u.PrivKey[:], buf.Next(32))

	var kdparr [21]byte
	copy(kdparr[:], buf.Next(21))
	u.KeyPath = KeyDerivationPathFromBytes(kdparr)

	// skip length, redundant here since we already know the slice length
	buf.Next(1)

	u.PkScript = buf.Bytes()
	return &u, nil
}

func (u *PortUtxo) Bytes() ([]byte, error) {
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

	err = binary.Write(&buf, binary.BigEndian, u.Amt)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&buf, binary.BigEndian, u.Seq)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&buf, binary.BigEndian, u.Mode) // mode @ offset 44
	if err != nil {
		return nil, err
	}

	_, err = buf.Write(u.PrivKey[:]) // privkey @ offset 69
	if err != nil {
		return nil, err
	}

	_, err = buf.Write(u.KeyPath.Bytes()) // keypath @ offset 48
	if err != nil {
		return nil, err
	}

	if len(u.PkScript) > 255 {
		return nil, errors.New("PkScript too long (255 byte max)")
	}
	err = binary.Write(&buf, binary.BigEndian, uint8(len(u.PkScript))) // PKlen @ 101
	if err != nil {
		return nil, err
	}

	_, err = buf.Write(u.PkScript)
	return buf.Bytes(), nil
}
