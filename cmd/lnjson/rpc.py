import socket
import json

def main():

    s = socket.create_connection(("127.0.0.1", 1234))
    #~ rpc_input = {
           #~ "method": "LNRpc.Sweep",
           #~ "params": [{
	   #~ "NumTx": 2,
	   #~ "DestAdr": "GgKoNkRcfz99oAbey3Fy35nHWUPUjk3Viod5",
	   #~ "Drop": True,
	   #~ }]
    #~ }
    #~ 
    #~ rpc_input = {
           #~ "method": "LNRpc.Fanout",
           #~ "params": [{
	   #~ "NumOutputs": 20,
	   #~ "DestAdr": "GgKoNkRcfz99oAbey3Fy35nHWUPUjk3Viod5",
	   #~ "AmtPerOutput": 10000000,
	    #~ }]
    #~ }    

    rpc_input = {
           "method": "LNRpc.Bal",
           "params": [{
	   }]
    }

    #~ rpc_input = {
           #~ "method": "LNRpc.Address",
           #~ "params": [{
	   #~ "NumToMake": 0,
	   #~ }]
    #~ }

    # add standard rpc values
    rpc_input.update({"jsonrpc": "2.0", "id": "99"})

    print(json.dumps(rpc_input))

    r = s.sendall(json.dumps(rpc_input))
    
    print(s.recv(1000000))
   
    # pretty print json output
    #~ print(json.dumps(response.json(), indent=4))

if __name__ == "__main__":
    main()
