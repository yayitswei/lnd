package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/txoport"
)

/* idea here is to convert output from bitcoind / btcd into a portable utxo

specify a tx hex file, and which output you want. Hex comes out.
P2PKH only for now.

*/

func usage() {
	fmt.Printf("Usage:\n./txofromhex tx.file index compressed\n")
	fmt.Printf("example: ./txofromhex mytx.hex 1 1\n")
}

func main() {
	if len(os.Args) < 4 {
		usage()
		return
	}

	filename := os.Args[1]
	idxint, err := strconv.ParseInt(os.Args[2], 10, 32)
	if err != nil {
		log.Fatal(err)
	}
	idx := uint32(idxint)
	compInt, err := strconv.ParseInt(os.Args[3], 10, 8)
	if err != nil {
		log.Fatal(err)
	}
	var comp bool
	if compInt != 0 {
		comp = true
	}
	txhex, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}
	txhex = []byte(strings.TrimSpace(string(txhex)))

	txbytes, err := hex.DecodeString(string(txhex))
	if err != nil {
		log.Fatal(err)
	}
	txbuf := bytes.NewBuffer(txbytes)
	fmt.Printf("txhex: %x\n index: %d comp: %v\n", txbytes, idx, comp)
	tx := wire.NewMsgTx()
	err = tx.DeserializeWitness(txbuf)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s has %d txouts\n", tx.TxSha().String(), len(tx.TxOut))

	if idx > uint32(len(tx.TxOut)) {
		log.Fatalf("txout %d selected, but only %d txouts\n", idx, len(tx.TxOut))
	}
	fmt.Printf("amt: %d\n", tx.TxOut[idx].Value)

	var u txoport.PortUtxo

	u.Op.Hash = tx.TxSha()
	u.Op.Index = idx

	u.Amt = tx.TxOut[idx].Value

	pks := tx.TxOut[idx].PkScript

	if len(pks) == 25 && pks[0] == 0x76 && pks[1] == 0xa9 && pks[2] == 0x14 &&
		pks[23] == 0x88 && pks[24] == 0xac { // it's p2pkh
		if comp {
			u.Mode = txoport.TxoP2PKHComp
		} else {
			u.Mode = txoport.TxoP2PKHUncomp
		}
	} else {
		u.Mode = 0xaa
	}

	fmt.Println(u.String())

	return
}
