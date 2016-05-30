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

type BalReply struct {
	TotalScore int64
	Ops        []string
	Qchans     []string
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

	for _, u := range allTxos {
		reply.TotalScore += u.Value
		reply.Ops = append(reply.Ops, u.Op.String())
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

type SweepReply struct {
	Txids []string
}

func (r *LNRpc) Sweep(args SweepArgs, reply *SweepReply) error {
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
