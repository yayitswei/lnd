package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/roasbeef/btcd/chaincfg"
	"github.com/roasbeef/btcd/txscript"
	"github.com/roasbeef/btcd/wire"
	"github.com/roasbeef/btcutil"

	"github.com/lightningnetwork/lnd/lndc"
	"github.com/lightningnetwork/lnd/uspv"
)

/* this is a CLI shell for testing out LND.  Right now it's only for uspv
testing.  It can send and receive coins.
*/

const (
	keyFileName    = "testkey.hex"
	headerFileName = "headers.bin"
	dbFileName     = "utxo.db"
	// this is my local testnet node, replace it with your own close by.
	// Random internet testnet nodes usually work but sometimes don't, so
	// maybe I should test against different versions out there.
	SPVHostAdr = "rp2:28901"
)

var (
	Params         = &chaincfg.SegNet4Params
	SCon           uspv.SPVCon   // global here for now
	GlobalOmniChan chan []byte   // channel for omnihandler
	RemoteCon      *lndc.LNDConn // one because simple

)

func shell(deadend string, deadend2 *chaincfg.Params) {
	fmt.Printf("LND spv shell v0.0\n")
	fmt.Printf("Not yet well integrated, but soon.\n")
	GlobalOmniChan = make(chan []byte, 10)
	go OmniHandler(GlobalOmniChan)
	// read key file (generate if not found)
	rootPriv, err := uspv.ReadKeyFileToECPriv(keyFileName, Params)
	if err != nil {
		log.Fatal(err)
	}
	// setup TxStore first (before spvcon)
	Store := uspv.NewTxStore(rootPriv, Params)
	// setup spvCon

	SCon, err = uspv.OpenSPV(
		SPVHostAdr, headerFileName, dbFileName, &Store, true, false, Params)
	if err != nil {
		log.Printf("can't connect: %s", err.Error())
		log.Fatal(err) // back to fatal when can't connect
	}

	tip, err := SCon.TS.GetDBSyncHeight() // ask for sync height
	if err != nil {
		log.Fatal(err)
	}
	if tip == 0 { // DB has never been used, set to birthday
		tip = 33500 // hardcoded; later base on keyfile date?
		err = SCon.TS.SetDBSyncHeight(tip)
		if err != nil {
			log.Fatal(err)
		}
	}

	// once we're connected, initiate headers sync
	err = SCon.AskForHeaders()
	if err != nil {
		log.Fatal(err)
	}

	//	rpcShellListen()

	// main shell loop
	for {
		// setup reader with max 4K input chars
		reader := bufio.NewReaderSize(os.Stdin, 4000)
		fmt.Printf("LND# ")                 // prompt
		msg, err := reader.ReadString('\n') // input finishes on enter key
		if err != nil {
			log.Fatal(err)
		}

		cmdslice := strings.Fields(msg) // chop input up on whitespace
		if len(cmdslice) < 1 {
			continue // no input, just prompt again
		}
		fmt.Printf("entered command: %s\n", msg) // immediate feedback
		err = Shellparse(cmdslice)
		if err != nil { // only error should be user exit
			log.Fatal(err)
		}
	}
	return
}

// Shellparse parses user input and hands it to command functions if matching
func Shellparse(cmdslice []string) error {
	var err error
	var args []string
	cmd := cmdslice[0]
	if len(cmdslice) > 1 {
		args = cmdslice[1:]
	}
	if cmd == "exit" || cmd == "quit" {
		return fmt.Errorf("User exit")
	}
	// help gives you really terse help.  Just a list of commands.
	if cmd == "help" {
		err = Help(args)
		if err != nil {
			fmt.Printf("help error: %s\n", err)
		}
		return nil
	}
	// adr generates a new address and displays it
	if cmd == "adr" {
		err = Adr(args)
		if err != nil {
			fmt.Printf("adr error: %s\n", err)
		}
		return nil
	}
	if cmd == "fake" { // give yourself fake utxos.
		err = Fake(args)
		if err != nil {
			fmt.Printf("fake error: %s\n", err)
		}
		return nil
	}
	// bal shows the current set of utxos, addresses and score
	if cmd == "bal" {
		err = Bal(args)
		if err != nil {
			fmt.Printf("bal error: %s\n", err)
		}
		return nil
	}

	// send sends coins to the address specified
	if cmd == "send" {
		err = Send(args)
		if err != nil {
			fmt.Printf("send error: %s\n", err)
		}
		return nil
	}
	if cmd == "fan" { // fan-out tx
		err = Fan(args)
		if err != nil {
			fmt.Printf("fan error: %s\n", err)
		}
		return nil
	}
	if cmd == "sweep" { // make lots of 1-in 1-out txs
		err = Sweep(args)
		if err != nil {
			fmt.Printf("sweep error: %s\n", err)
		}
		return nil
	}
	if cmd == "txs" { // show all txs
		err = Txs(args)
		if err != nil {
			fmt.Printf("txs error: %s\n", err)
		}
		return nil
	}
	if cmd == "con" { // connect to lnd host
		err = Con(args)
		if err != nil {
			fmt.Printf("con error: %s\n", err)
		}
		return nil
	}
	if cmd == "lis" { // listen for lnd peers
		err = Lis(args)
		if err != nil {
			fmt.Printf("lis error: %s\n", err)
		}
		return nil
	}
	// Peer to peer actions
	// send text message
	if cmd == "say" {
		err = Say(args)
		if err != nil {
			fmt.Printf("say error: %s\n", err)
		}
		return nil
	}
	// fund and create a new channel
	if cmd == "fund" {
		err = FundChannel(args)
		if err != nil {
			fmt.Printf("fund error: %s\n", err)
		}
		return nil
	}
	// push money in a channel away from you
	if cmd == "push" {
		err = Push(args)
		if err != nil {
			fmt.Printf("push error: %s\n", err)
		}
		return nil
	}
	// cooperateive close of a channel
	if cmd == "cclose" {
		err = CloseChannel(args)
		if err != nil {
			fmt.Printf("cclose error: %s\n", err)
		}
		return nil
	}
	if cmd == "break" {
		err = BreakChannel(args)
		if err != nil {
			fmt.Printf("break error: %s\n", err)
		}
		return nil
	}
	if cmd == "grab" {
		err = Grab(args)
		if err != nil {
			fmt.Printf("grab error: %s\n", err)
		}
		return nil
	}
	if cmd == "fix" {
		err = Resume(args)
		if err != nil {
			fmt.Printf("fix error: %s\n", err)
		}
		return nil
	}
	if cmd == "math" {
		err = Math(args)
		if err != nil {
			fmt.Printf("math error: %s\n", err)
		}
		return nil
	}
	fmt.Printf("Command not recognized. type help for command list.\n")
	return nil
}

// Lis starts listening.  Takes no args for now.
func Lis(args []string) error {
	go TCPListener()
	return nil
}

func TCPListener() {
	idPriv := SCon.TS.IdKey()

	listener, err := lndc.NewListener(idPriv, ":2448")
	if err != nil {
		log.Printf(err.Error())
		return
	}

	myId := btcutil.Hash160(idPriv.PubKey().SerializeCompressed())
	lisAdr, err := btcutil.NewAddressPubKeyHash(myId, Params)
	fmt.Printf("Listening on %s\n", listener.Addr().String())
	fmt.Printf("Listening with base58 address: %s lnid: %x\n",
		lisAdr.String(), myId[:16])

	for {
		netConn, err := listener.Accept() // this blocks
		if err != nil {
			log.Printf("Listener error: %s\n", err.Error())
			continue
		}
		newConn, ok := netConn.(*lndc.LNDConn)
		if !ok {
			fmt.Printf("Got something that wasn't a LNDC")
			continue
		}

		idslice := btcutil.Hash160(newConn.RemotePub.SerializeCompressed())
		var newId [16]byte
		copy(newId[:], idslice[:16])
		fmt.Printf("Authed incoming connection from remote %s lnid %x OK\n",
			newConn.RemoteAddr().String(), newId)

		go LNDCReceiver(newConn, newId, GlobalOmniChan)
		RemoteCon = newConn
	}
}

func Con(args []string) error {
	var err error

	if len(args) == 0 {
		return fmt.Errorf("need: con pubkeyhash@hostname:port")
	}

	newNode, err := lndc.LnAddrFromString(args[0])
	if err != nil {
		return err
	}

	idPriv := SCon.TS.IdKey()

	RemoteCon = new(lndc.LNDConn)

	err = RemoteCon.Dial(
		idPriv, newNode.NetAddr.String(), newNode.Base58Adr.ScriptAddress())
	if err != nil {
		return err
	}
	// store this peer
	_, err = SCon.TS.NewPeer(RemoteCon.RemotePub)
	if err != nil {
		return err
	}

	idslice := btcutil.Hash160(RemoteCon.RemotePub.SerializeCompressed())
	var newId [16]byte
	copy(newId[:], idslice[:16])
	go LNDCReceiver(RemoteCon, newId, GlobalOmniChan)

	return nil
}

// Say sends a text string
// For fun / testing.  Syntax: say hello world
func Say(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("you have to say something")
	}
	if RemoteCon == nil {
		return fmt.Errorf("Not connected to anyone\n")
	}

	var chat string
	for _, s := range args {
		chat += s + " "
	}
	msg := append([]byte{uspv.MSGID_TEXTCHAT}, []byte(chat)...)

	_, err := RemoteCon.Write(msg)
	return err
}

func Txs(args []string) error {
	alltx, err := SCon.TS.GetAllTxs()
	if err != nil {
		return err
	}
	for i, tx := range alltx {
		fmt.Printf("tx %d %s\n", i, uspv.TxToString(tx))
	}
	return nil
}

// Fake generates a fake tx and ingests it.  Needed in airplane mode.
// syntax is the same as send, but the inputs are invalid.
func Fake(args []string) error {

	// need args, fail
	if len(args) < 2 {
		return fmt.Errorf("need args: ssend address amount(satoshis) wit?")
	}
	adr, err := btcutil.DecodeAddress(args[0], SCon.TS.Param)
	if err != nil {
		fmt.Printf("error parsing %s as address\t", args[0])
		return err
	}

	amt, err := strconv.ParseInt(args[1], 10, 64)
	if err != nil {
		return err
	}

	tx := wire.NewMsgTx() // make new tx
	// make address script 76a914...88ac or 0014...
	outAdrScript, err := txscript.PayToAddrScript(adr)
	if err != nil {
		return err
	}
	// make user specified txout and add to tx
	txout := wire.NewTxOut(amt, outAdrScript)
	tx.AddTxOut(txout)

	hash, err := wire.NewShaHashFromStr("23")
	if err != nil {
		return err
	}
	op := wire.NewOutPoint(hash, 25)
	txin := wire.NewTxIn(op, nil, nil)
	tx.AddTxIn(txin)

	_, err = SCon.TS.Ingest(tx, 0)
	if err != nil {
		return err
	}

	return nil
}

// Bal prints out your score.
func Bal(args []string) error {
	if SCon.TS == nil {
		return fmt.Errorf("Can't get balance, spv connection broken")
	}

	if len(args) > 1 {
		peerIdx, err := strconv.ParseInt(args[0], 10, 32)
		if err != nil {
			return err
		}
		cIdx, err := strconv.ParseInt(args[1], 10, 32)
		if err != nil {
			return err
		}

		qc, err := SCon.TS.GetQchanByIdx(uint32(peerIdx), uint32(cIdx))
		if err != nil {
			return err
		}
		return SCon.TS.QchanInfo(qc)
	}

	fmt.Printf(" ----- Account Balance ----- \n")
	fmt.Printf(" ----- Channels ----- \n")
	qcs, err := SCon.TS.GetAllQchans()
	if err != nil {
		return err
	}

	for _, q := range qcs {
		if q.CloseData.Closed {
			fmt.Printf("CLOSED ")

		} else {
			fmt.Printf("CHANNEL")
		}
		fmt.Printf(" %s h:%d (%d,%d) cap: %d\n",
			q.Op.Hash.String(), q.AtHeight, q.PeerIdx, q.KeyIdx, q.Value)
	}
	fmt.Printf(" ----- utxos ----- \n")
	var allUtxos uspv.SortableUtxoSlice
	allUtxos, err = SCon.TS.GetAllUtxos()
	if err != nil {
		return err
	}
	// smallest and unconfirmed last (because it's reversed)
	sort.Sort(sort.Reverse(allUtxos))

	var score, confScore int64
	for i, u := range allUtxos {
		fmt.Printf("utxo %d %s h:%d k:%d a %d",
			i, u.Op.String(), u.AtHeight, u.KeyIdx, u.Value)
		if u.SpendLag > 0 {
			fmt.Printf(" s:%d", u.SpendLag)
		}
		if u.FromPeer != 0 {
			fmt.Printf(" p:%d", u.FromPeer)
		}
		fmt.Printf("\n")
		score += u.Value
		if u.AtHeight != 0 {
			confScore += u.Value
		}
	}

	height, err := SCon.TS.GetDBSyncHeight()
	if err != nil {
		return err
	}
	atx, err := SCon.TS.GetAllTxs()
	if err != nil {
		return err
	}
	stxos, err := SCon.TS.GetAllStxos()
	if err != nil {
		return err
	}

	for i, a := range SCon.TS.Adrs {
		oa, err := btcutil.NewAddressPubKeyHash(
			a.PkhAdr.ScriptAddress(), Params)
		if err != nil {
			return err
		}
		fmt.Printf("address %d %s OR %s\n", i, oa.String(), a.PkhAdr.String())
	}

	fmt.Printf("Total known txs: %d\n", len(atx))
	fmt.Printf("Known utxos: %d\tPreviously spent txos: %d\n",
		len(allUtxos), len(stxos))
	fmt.Printf("Total coin: %d confirmed: %d\n", score, confScore)
	fmt.Printf("DB sync height: %d\n", height)

	return nil
}

// Adr makes a new address.
func Adr(args []string) error {

	// if there's an arg, make 10 adrs
	if len(args) > 0 {
		for i := 0; i < 10; i++ {
			_, err := SCon.TS.NewAdr()
			if err != nil {
				return err
			}
		}
	}
	if len(args) > 1 {
		for i := 0; i < 1000; i++ {
			_, err := SCon.TS.NewAdr()
			if err != nil {
				return err
			}
		}
	}

	// always make one
	a, err := SCon.TS.NewAdr()
	if err != nil {
		return err
	}
	fmt.Printf("made new address %s\n",
		a.String())

	return nil
}

// Sweep sends every confirmed uxto in your wallet to an address.
// it does them all individually to there are a lot of txs generated.
// syntax: sweep adr
func Sweep(args []string) error {
	var err error
	var adr btcutil.Address
	if len(args) < 2 {
		return fmt.Errorf("sweep syntax: sweep adr howmany (drop)")
	}

	adr, err = btcutil.DecodeAddress(args[0], SCon.TS.Param)
	if err != nil {
		fmt.Printf("error parsing %s as address\t", args[0])
		return err
	}

	numTxs, err := strconv.ParseInt(args[1], 10, 64)
	if err != nil {
		return err
	}
	if numTxs < 1 {
		return fmt.Errorf("can't send %d txs", numTxs)
	}

	var allUtxos uspv.SortableUtxoSlice
	allUtxos, err = SCon.TS.GetAllUtxos()
	if err != nil {
		return err
	}
	// smallest and unconfirmed last (because it's reversed)
	sort.Sort(sort.Reverse(allUtxos))

	if len(args) == 2 {
		for i, u := range allUtxos {
			if u.AtHeight != 0 && u.Value > 10000 {
				_, err = SCon.SendOne(*allUtxos[i], adr)
				if err != nil {
					return err
				}
				numTxs--
				if numTxs == 0 {
					return nil
				}
			}
		}
		fmt.Printf("spent all confirmed utxos; not enough by %d\n", numTxs)
		return nil
	}
	// now do bigSig drop drop drop
	for i, u := range allUtxos {
		if u.AtHeight != 0 {
			_, err = SCon.SendDrop(*allUtxos[i], adr)
			if err != nil {
				return err
			}
			numTxs--
			if numTxs == 0 {
				return nil
			}
		}
	}

	return nil
}

// Fan generates a bunch of fanout.  Only for testing, can be expensive.
// syntax: fan adr numOutputs valOutputs witty
func Fan(args []string) error {
	if len(args) < 3 {
		return fmt.Errorf("fan syntax: fan adr numOutputs valOutputs")
	}
	adr, err := btcutil.DecodeAddress(args[0], SCon.TS.Param)
	if err != nil {
		fmt.Printf("error parsing %s as address\t", args[0])
		return err
	}
	numOutputs, err := strconv.ParseInt(args[1], 10, 64)
	if err != nil {
		return err
	}
	valOutputs, err := strconv.ParseInt(args[2], 10, 64)
	if err != nil {
		return err
	}

	adrs := make([]btcutil.Address, numOutputs)
	amts := make([]int64, numOutputs)

	for i := int64(0); i < numOutputs; i++ {
		adrs[i] = adr
		amts[i] = valOutputs + i
	}
	_, err = SCon.SendCoins(adrs, amts)
	return err
}

// Send sends coins.
func Send(args []string) error {
	if SCon.RBytes == 0 {
		return fmt.Errorf("Can't send, spv connection broken")
	}
	// get all utxos from the database
	allUtxos, err := SCon.TS.GetAllUtxos()
	if err != nil {
		return err
	}
	var score int64 // score is the sum of all utxo amounts.  highest score wins.
	// add all the utxos up to get the score
	for _, u := range allUtxos {
		score += u.Value
	}

	// score is 0, cannot unlock 'send coins' acheivement
	if score == 0 {
		return fmt.Errorf("You don't have money.  Work hard.")
	}
	// need args, fail
	if len(args) < 2 {
		return fmt.Errorf("need args: ssend address amount(satoshis) wit?")
	}
	adr, err := btcutil.DecodeAddress(args[0], SCon.TS.Param)
	if err != nil {
		fmt.Printf("error parsing %s as address\t", args[0])
		return err
	}
	amt, err := strconv.ParseInt(args[1], 10, 64)
	if err != nil {
		return err
	}
	if amt < 1000 {
		return fmt.Errorf("can't send %d, too small", amt)
	}

	fmt.Printf("send %d to address: %s \n",
		amt, adr.String())

	var adrs []btcutil.Address
	var amts []int64

	adrs = append(adrs, adr)
	amts = append(amts, amt)
	_, err = SCon.SendCoins(adrs, amts)
	if err != nil {
		return err
	}
	return nil
}

func Help(args []string) error {
	fmt.Printf("commands:\n")
	fmt.Printf("help adr bal send fake fan sweep lis con fund push cclose break exit\n")
	return nil
}
