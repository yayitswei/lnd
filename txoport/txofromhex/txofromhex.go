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
	"github.com/roasbeef/btcutil"
)

/* idea here is to convert output from bitcoind / btcd into a portable utxo

specify a tx hex file, and which output you want. Hex comes out.
P2PKH only for now.

*/

func usage() {
	fmt.Printf("Usage:\n./txofromhex tx.file index compressed\n")
	fmt.Printf("Usage:\n./txofromhex utxo.file WIF_Key\n")
	fmt.Printf("example: ./txofromhex mytx.hex 1 1\n")
}

// insert a private key into a portable utxo
func insert() {

	uthexo, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	uthexo = []byte(strings.TrimSpace(string(uthexo)))

	utxbytes, err := hex.DecodeString(string(uthexo))
	if err != nil {
		log.Fatal(err)
	}

	u, err := txoport.PortUtxoFromBytes(utxbytes)
	if err != nil {
		log.Fatal(err)
	}

	wif, err := btcutil.DecodeWIF(os.Args[2])
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("insert wif: %s\n%s\n", wif.String(), u.String())
}

func extract() {
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
	//	fmt.Printf("index: %d comp: %v\n", idx, comp)
	tx := wire.NewMsgTx()
	err = tx.DeserializeWitness(txbuf)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s has %d txouts\n", tx.TxSha().String(), len(tx.TxOut))

	if idx > uint32(len(tx.TxOut)-1) {
		log.Fatalf("txout:%d selected, but only %d txouts\n", idx, len(tx.TxOut))
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
		u.Mode = 0x000000aa
	}
	fmt.Println(u.String())
	b, _ := u.Bytes()
	fmt.Printf("utxo hex:\n%x\n", b)
	return
}

func main() {
	if len(os.Args) < 3 || len(os.Args) > 4 {
		usage()
		return
	}
	// insert key
	if len(os.Args) == 3 {
		insert()
		return
	}

	// get txo from tx
	if len(os.Args) == 4 {
		extract()
		return
	}
	return
}
