package uwire

type CloseRequest struct {
	CloseWPKH [20]byte // requested close output PKH
}

type CloseResponse struct {
	CloseWPKH [20]byte // requested close output PKH
	Sig       []byte   // Responder's sig
}
