package uwire

//  message type identifyer bytes
const (
	MSGID_PUBREQ  = 0x30
	MSGID_PUBRESP = 0x31

	MSGID_CHANDESC = 0x32

	MSGID_MULTIDESC = 0x3A
	MSGID_MULTIACK  = 0x3B

	MSGID_CLOSEREQ  = 0x40
	MSGID_CLOSERESP = 0x41

	MSGID_TEXTCHAT = 0x70

	MSGID_SIGPUSH = 0x80 // pushing funds in channel; giving sig
	MSGID_SIGPULL = 0x81 // pulling funds in channel; giving sig
	MSGID_REVOC   = 0x82 // pushing or pulling funds; revoking old state

	MSGID_FWDMSG     = 0x20
	MSGID_FWDAUTHREQ = 0x21
)
