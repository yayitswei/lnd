package uspvnotify

import (
	"github.com/lightningnetwork/lnd/chainntfs"
	"github.com/lightningnetwork/lnd/uspv"
	"github.com/roasbeef/btcd/chaincfg"
	"github.com/roasbeef/btcd/wire"
)

var (
	Params = &chaincfg.SegNet4Params
)

type UspvNotifier struct {
	sCon uspv.SPVCon

	confTxids []*wire.ShaHash
}

func (u *UspvNotifier) RegisterConfirmationsNtfn(txid *wire.ShaHash, numConfs uint32) (*chainntfs.ConfirmationEvent, error) {
	//ce:= new(chainntfs.)
	return nil, nil
}

func (u *UspvNotifier) RegisterSpendNtfn(outpoint *wire.OutPoint) (*chainntfs.SpendEvent, error) {
	return nil, nil
}

func (u *UspvNotifier) Start() error {
	return nil
}

func (u *UspvNotifier) Stop() error {
	return nil
}

func InitUSPV(u *uspv.SPVCon) (*UspvNotifier, error) {

	return nil, nil
}

//SCon, err = uspv.OpenSPV(
//		SPVHostAdr, headerFileName, dbFileName, &Store, true, false, Params)
