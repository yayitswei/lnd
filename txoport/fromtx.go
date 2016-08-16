package txoport

import (
	"fmt"

	"github.com/btcsuite/btcd/wire"
)

func ExtractFromTx(tx *wire.MsgTx, idx uint32) (*PortUtxo, error) {
	if tx == nil {
		return nil, fmt.Errorf("nil tx")
	}
	if int(idx) > len(tx.TxOut)-1 {
		return nil, fmt.Errorf("extract txo %d but tx has %d outputs",
			idx, len(tx.TxOut))
	}

	u := new(PortUtxo)

	u.Op.Hash = tx.TxSha()
	u.Op.Index = idx

	u.Amt = tx.TxOut[idx].Value

	/*
		pks := tx.TxOut[idx].PkScript

			if len(pks) == 25 && pks[0] == 0x76 && pks[1] == 0xa9 && pks[2] == 0x14 &&
				pks[23] == 0x88 && pks[24] == 0xac { // it's p2pkh
				if comp {
					u.Mode = TxoP2PKHComp
				} else {
					u.Mode = TxoP2PKHUncomp
				}
			} else {
	*/

	u.Mode = TxoUnknownMode // dunno about setting mode yet... can't really tell from pkscript

	u.PkScript = tx.TxOut[idx].PkScript
	return u, nil
}
