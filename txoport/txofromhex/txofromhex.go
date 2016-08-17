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
	fmt.Printf("Usage:\n./txofromhex tx.file index\n")
	fmt.Printf("Usage:\n./txofromhex utxo.file WIF_Key\n")
	fmt.Printf("example: ./txofromhex mytx.hex 1 1\n")
}

func main() {
	if len(os.Args) < 3 || len(os.Args) > 4 {
		usage()
		return
	}

	tx := wire.NewMsgTx()
	u := new(txoport.PortUtxo)

	// load file from disk
	filehex, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	// trim spaces
	filehex = []byte(strings.TrimSpace(string(filehex)))

	// convert to bytes
	fileslice, err := hex.DecodeString(string(filehex))
	if err != nil {
		log.Fatal(err)
	}

	// make buffer
	txbuf := bytes.NewBuffer(fileslice)

	err = tx.DeserializeWitness(txbuf)
	if err != nil { // ok, didn't work as a tx, try a utxo

		u, err = txoport.PortUtxoFromBytes(fileslice)
		if err != nil {
			log.Fatal("file wasn't a tx, and wasn't a utxo! %s\n", err.Error())
		}
		wif, err := btcutil.DecodeWIF(os.Args[2])
		if err != nil {
			log.Fatal(err)
		}
		err = u.AddWIF(*wif)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s\n", u.String())
		b, _ := u.Bytes()
		fmt.Printf("%x\n", b)
		return
	}
	// tx did work, get index and try extracting utxo

	idxint, err := strconv.ParseInt(os.Args[2], 10, 32)
	if err != nil {
		log.Fatal(err)
	}
	idx := uint32(idxint)

	u, err = txoport.ExtractFromTx(tx, idx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", u.String())
	b, err := u.Bytes()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%x\n", b)
	return
}
