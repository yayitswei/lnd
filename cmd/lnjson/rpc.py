import socket
import json

def main():

    s = socket.create_connection(("127.0.0.1", 1234))
    
    
    rpc_input = {
           "method": "LNRpc.Send",
           "params": [{
	   "DestAddrs": [
	   #~ "GgKoNkRcfz99oAbey3Fy35nHWUPUjk3Viod5",
	   #~ "GgKsNWh62xHcqGibWNArMDwLeW8uhur2uNrc",
	   "GgKqCtLtgjH9LEkUJX2hewqiSpten9xczQbL",],
	   "Amts": [
	   #~ 40000000,
	   #~ 41000000,
	   44000000,]
	   }]
    }    
    #~ 
    #~ rpc_input = {
           #~ "method": "LNRpc.Sweep",
           #~ "params": [{
	   #~ "NumTx": 1,
	   #~ "DestAdr": "GgKoNkRcfz99oAbey3Fy35nHWUPUjk3Viod5",
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
    
    s.sendall(bytes(json.dumps(rpc_input), "utf-8"))
    print(s.recv(8000000).decode("utf-8"))
   
    # pretty print json output
    #~ print(json.dumps(response.json(), indent=4))

if __name__ == "__main__":
    main()
