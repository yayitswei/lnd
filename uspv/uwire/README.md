# uwire - micro LN protocol

This is a simplified and minimized single hop LN protocol.  It's bare-bones but will help with implementing fancier stuff later.

## Channel creation

Channels have 2 participants, the Funder and the Acceptor.

There is no fund request, instead a pubkey request. (This request is empty, and sent by the Funder)

The Acceptor responds with a pubkey.

The Funder then sends a ChannelDescription, which includes the fund TX outpoint, the channel capacity, and the funder's pubkey.

The funder also sends a SigPush, which sends money to the Acceptor within the not yet broadcast channel.  The Acceptor responds with a SigPull.

The funder can then sign and broadcast the funding TX, opening the channel.

For channel updates, the party sending funds sends a SigPush message with the amount being pushed in the channel.  The receiver of funds sends a SigPull message.  Once sigs have been exchanged, the revocation messages are also exchanged.  After revocations are exchanged the state is updated and the old state is removed.

