package uwire

// spend -- spend from a joint multisig output

// spend request is the message you send to request a signature
type SpendMultiReq struct {
	ToWPKH [20]byte // requested output PKH
}

// Signature in response which allows multisig spending
type SpendMultiResp struct {
	Sig []byte // Responder's sig
}
