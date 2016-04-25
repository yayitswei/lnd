# Push / pull - flow for channel state updates

Here's how channels ("qChans" in the code, because you can't start anything with "chan" in go and nothing else started with q...) are updated.

There's one state at a time, with 2 variables which indicate aspects of a next or previous state: delta and prevRH.  

States look like this

prev 	cur 		next
-------|-------|-------
		idx
		amt		delta
prevRH	revH
		sig	

When nothing is inflight, delta is 0 and prevRev is an empty 20 byte array.

4 messages: RTS, ACKSIG, SIGREV, REV.  
Pusher is the side which initiate the payment.  Payments are always "push" and requesting a "pull" is out of the scope of this protocol.  Puller is the one who recives funds.

Pusher - RTS: Request to send

Puller - ACKSIG: Acknowledge update, provide signature

Pusher - SIGREV: Sign new state, revoke old state

Puller - REV: Revoke old state

There's only 1 struct in ram so there's a bunch of overwrites.  But there's data on the disk in the DB, so if something fails, like signature verification, you restore from the DB.  It's safe in that you only ever have one state on the DB so you know what to broadcast.  You overwrite their sig, which is the dangerous part (don't want to keep track of sigs where you've revoked that state)

There's only one state in ram, and only one state on disk.  However, in terms of "previous / current / next", the state on disk may be earlier than the state in ram.  Ram is "ahead"; you're not sure from looking at the disk if you've sent the message or not, but you can just send again if you're not sure.  From looking at the state on disk, it is clear what the is next step and mesages to send.

## Message and DB sequence:

### Pusher: UI trigger (destination, amountToSend)
RAM state: set delta to -amountToSend (delta is negative for pusher)
##### save to DB (only negative delta is new)
idx++
send RTS (idx, amountToSend)

### Puller: Receive RTS
check RTS(idx) == idx+1
check RTS(amount) > 0
delta = RTS(amount)
##### Save to DB(only positive delta is new)
idx++
create theirRevH(idx)
create tx(theirs)
sign tx
send ACKSIG(sig, revH)

### Pusher: Receive ACKSIG
copy(prevRH, revH)
amt += delta
delta = 0
revH = SIGACK(revH)
sig = SIGACK(sig)
create tx(mine)
verify sig (if fails, restore from DB, try RTS again..?)
##### Save to DB(all fields new; prevRH populated, delta = 0)
create theirRevH(idx)
create tx(theirs)
sign tx
create elk(idx-1)
send SIGREV(sig, theirRevH, elk)

### Puller: Receive SIGREV
verify hash160(SIGREV(elk[:16])) == revH
verify elk insertion (do this first because we overwrite revH)
amt += delta
delta = 0
revH = SIGREV(revH)
sig = SIGREV(sig)
clear theirRevH
create tx(mine)
verify sig (if fails, reload from DB, send ACKSIG again..? or record error?)
##### Save to DB(all fields new, prevRH empty, delta = 0)
create elk(idx-1)
send REV(elk)

### Pusher: Receive REV
verify hash160(REV(elk[:16])) == prevRH
verify elk insertion
set prevRH to empty
##### Save to DB(prevRH empty)

## Explanation

The genral sequence is to take in data, use it to modify the state in RAM, and  verify it.  If it's OK, then save it to the DB, then after saving construct and send the response.  This way if something goes wrong and you pull the plug, you might not be sure if you sent a message or not, but you can safely construct and send it again, based on the data in the DB.  Based on the DB state you'll know where in the process you stopped and can hopefully resume.











