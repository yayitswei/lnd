package main

import (
	"fmt"
	"log"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
	"sort"

	"github.com/lightningnetwork/lnd/uspv"

	"github.com/roasbeef/btcutil"
)

type LNRpc struct {
	// nothing...?
}

type AdrArgs struct {
	NumToMake uint32
}
type AdrReply struct {
	PreviousAddresses []string
	NewAddresses      []string
}

func (r *LNRpc) Address(args *AdrArgs, reply *AdrReply) error {
	reply.PreviousAddresses = make([]string, len(SCon.TS.Adrs))
	reply.NewAddresses = make([]string, args.NumToMake)

	for i, a := range SCon.TS.Adrs {
		reply.PreviousAddresses[i] = a.PkhAdr.String()
	}

	nokori := args.NumToMake
	for nokori > 0 {
		a, err := SCon.TS.NewAdr()
		if err != nil {
			return err
		}
		reply.NewAddresses[nokori-1] = a.String()
		nokori--
	}

	return nil
}

type BalReply struct {
	TotalScore int64
	Txos       []BalTxo
	Qchans     []string
}

type BalTxo struct {
	OutPoint string
	Height   int32
	Amt      int64
}

type BalQchan struct {
	OutPoint   string
	Capacity   int64
	MyBalance  int64
	StateIndex uint64
}

type BalArgs struct {
	// nothin
}

func (r *LNRpc) Bal(args *BalArgs, reply *BalReply) error {
	var err error

	allTxos, err := SCon.TS.GetAllUtxos()
	if err != nil {
		return err
	}

	reply.Txos = make([]BalTxo, len(allTxos))

	for i, u := range allTxos {
		reply.Txos[i].Amt = u.Value
		reply.Txos[i].Height = u.AtHeight
		reply.Txos[i].OutPoint = u.Op.String()
		reply.TotalScore += u.Value
	}

	qcs, err := SCon.TS.GetAllQchans()
	if err != nil {
		return err
	}
	for _, q := range qcs {
		reply.Qchans = append(reply.Qchans, q.Op.String())
	}

	//	*reply = fmt.Sprintf("you have %d utxos", len(rawUtxos))
	return nil
}

type SweepArgs struct {
	DestAdr string
	NumTx   int
	Drop    bool
}

type TxidsReply struct {
	Txids []string
}

func (r *LNRpc) Sweep(args SweepArgs, reply *TxidsReply) error {
	adr, err := btcutil.DecodeAddress(args.DestAdr, SCon.TS.Param)
	if err != nil {
		fmt.Printf("error parsing %s as address\t", args.DestAdr)
		return err
	}
	fmt.Printf("numtx: %d\n", args.NumTx)
	if args.NumTx < 1 {
		return fmt.Errorf("can't send %d txs", args.NumTx)
	}
	nokori := args.NumTx

	rawUtxos, err := SCon.TS.GetAllUtxos()
	if err != nil {
		return err
	}
	var allUtxos uspv.SortableUtxoSlice
	for _, utxo := range rawUtxos {
		allUtxos = append(allUtxos, *utxo)
	}
	// smallest and unconfirmed last (because it's reversed)
	sort.Sort(sort.Reverse(allUtxos))

	for i, u := range allUtxos {
		if u.AtHeight != 0 && u.Value > 10000 {
			txid, err := SCon.SendOne(allUtxos[i], adr)
			if err != nil {
				return err
			}
			reply.Txids = append(reply.Txids, txid.String())
			nokori--
			if nokori == 0 {
				return nil
			}
		}
	}

	fmt.Printf("spent all confirmed utxos; not enough by %d\n", nokori)
	return nil
}

//return fmt.Errorf("fan syntax: fan adr numOutputs valOutputs")

type FanArgs struct {
	DestAdr      string
	NumOutputs   uint32
	AmtPerOutput int64
}

func (r *LNRpc) Fanout(args FanArgs, reply *TxidsReply) error {
	if args.NumOutputs < 1 {
		return fmt.Errorf("Must have at least 1 output")
	}
	if args.AmtPerOutput < 5000 {
		return fmt.Errorf("Minimum 5000 per output")
	}
	adr, err := btcutil.DecodeAddress(args.DestAdr, SCon.TS.Param)
	if err != nil {
		fmt.Printf("error parsing %s as address\t", args.DestAdr)
		return err
	}
	adrs := make([]btcutil.Address, args.NumOutputs)
	amts := make([]int64, args.NumOutputs)

	for i := int64(0); i < int64(args.NumOutputs); i++ {
		adrs[i] = adr
		amts[i] = args.AmtPerOutput + i
	}
	txid, err := SCon.SendCoins(adrs, amts)
	if err != nil {
		return err
	}
	reply.Txids = append(reply.Txids, txid.String())
	return nil
}

type LisReply struct {
	Status string
}

func (r *LNRpc) Lis(args BalArgs, reply *LisReply) error {
	go TCPListener()
	reply.Status = "listening"
	return nil
}

func rpcShellListen() error {
	rpcl := new(LNRpc)
	server := rpc.NewServer()
	server.Register(rpcl)
	server.HandleHTTP("/jsonrpc", "/debug/jsonrpc")
	listener, e := net.Listen("tcp", ":1234")
	if e != nil {
		log.Fatal("listen error:", e)
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Fatal("accept error: " + err.Error())
			} else {
				log.Printf("new connection from %s\n", conn.RemoteAddr().String())
				go server.ServeCodec(jsonrpc.NewServerCodec(conn))
			}
		}
	}()

	return nil
}
