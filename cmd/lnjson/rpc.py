import socket
import json
import random

def main():

    s = socket.create_connection(("127.0.0.1", 1234))
    
    amt1 = random.randint(100000, 200000000)
    amt2 = random.randint(100000, 289900000)
    
    rpc_input = {
           "method": "LNRpc.Send",
           "params": [{
	   "DestAddrs": [
	   #~ "GgKoNkRcfz99oAbey3Fy35nHWUPUjk3Viod5",
	   "GgKiMfQCEud9SSLAyk67NhPxmJ2jT85m87td",
	   "GgKvQDhUbuLzpvjpxcmqXXHLZzDWxDBnFgJG",],
	   "Amts": [
	   #~ 40000000,
	   amt1,
	   amt2,]
	   }]
    }    
    #~ 
    #~ rpc_input = {
           #~ "method": "LNRpc.Sweep",
           #~ "params": [{
	   #~ "NumTx": 1,
	   #~ "DestAdr": "GgL26pL4qPKJBrk2ZFy97bNU6do26FKWoMyt",
	   #~ "Drop": True,
	   #~ }]
    #~ }
    
    #~ rpc_input = {
           #~ "method": "LNRpc.Fanout",
           #~ "params": [{
	   #~ "NumOutputs": 2,
	   #~ "DestAdr": "GgKoNkRcfz99oAbey3Fy35nHWUPUjk3Viod5",
	   #~ "AmtPerOutput": 4000000,
	    #~ }]
    #~ }    

    #~ rpc_input = {
           #~ "method": "LNRpc.Bal",
           #~ "params": [{
	   #~ }]
    #~ }

    #~ rpc_input = {
           #~ "method": "LNRpc.Address",
           #~ "params": [{
	   #~ "NumToMake": 0,
	   #~ }]
    #~ }

    # add standard rpc values
    rpc_input.update({"jsonrpc": "2.0", "id": "99"})
    print(json.dumps(rpc_input))
    
    s.sendall(json.dumps(rpc_input))
    print(s.recv(8000000).decode("utf-8"))
   
    # pretty print json output
    #~ print(json.dumps(response.json(), indent=4))

if __name__ == "__main__":
    main()
