package lnutil

import (
	"bytes"
	"encoding/binary"

	"github.com/btcsuite/fastsha256"
	"github.com/roasbeef/btcd/txscript"
	"github.com/roasbeef/btcd/wire"
	"github.com/roasbeef/btcutil"
)

// need this because before I was comparing pointers maybe?
// so they were the same outpoint but stored in 2 places so false negative?
func OutPointsEqual(a, b wire.OutPoint) bool {
	if !a.Hash.IsEqual(&b.Hash) {
		return false
	}
	return a.Index == b.Index
}

/*----- serialization for tx outputs ------- */

// outPointToBytes turns an outpoint into 36 bytes.
func OutPointToBytes(op wire.OutPoint) (b [36]byte) {
	var buf bytes.Buffer
	_, err := buf.Write(op.Hash.Bytes())
	if err != nil {
		return
	}
	// write 4 byte outpoint index within the tx to spend
	err = binary.Write(&buf, binary.BigEndian, op.Index)
	if err != nil {
		return
	}
	copy(b[:], buf.Bytes())

	return
}

// OutPointFromBytes gives you an outpoint from 36 bytes.
// since 36 is enforced, it doesn't error
func OutPointFromBytes(b [36]byte) *wire.OutPoint {
	op := new(wire.OutPoint)
	_ = op.Hash.SetBytes(b[:32])
	op.Index = BtU32(b[32:])
	return op
}

func P2WSHify(scriptBytes []byte) []byte {
	bldr := txscript.NewScriptBuilder()
	bldr.AddOp(txscript.OP_0)
	wsh := fastsha256.Sum256(scriptBytes)
	bldr.AddData(wsh[:])
	b, _ := bldr.Script() // ignore script errors
	return b
}

func DirectWPKHScript(pub [33]byte) []byte {
	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_0).AddData(btcutil.Hash160(pub[:]))
	b, _ := builder.Script()
	return b
}
