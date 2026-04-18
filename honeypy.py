#Importing the arg parse library and ssh_honeypot.py file.
#Libraries 
import argparse
from ssh_honeypot import * #Import all functions
from web_honeypot import * #Import all functions

#Parse Arguments

if __name__ == '__main__': #If we're executing from this file do following.
    parser = argparse.ArgumentParser() #Create new instance of argparse.

    parser.add_argument('-a', '--address', type=str, required=True) #Add argument for address, type string, required.
    parser.add_argument('-p', '--port', type=int, required=True) #Add argument for port, type int, required.
    parser.add_argument('-u', '--username', type=str) # """""""""" doesn't need to be required.
    parser.add_argument('-pw', '--password', type=str) # """""""""" doesn't need to be required.

    #Two arguments one for ssh and for https. Allow for multiple instance of honeypot.

    parser.add_argument('-s', '--ssh', action='store_true') #If argument supplied true. Smt stored its stored.
    parser.add_argument('-w', '--http', action='store_true') #-h is for help in argparse. Don't use.

    args = parser.parse_args() #Collect all arguments above and store in args variable.

    try:
        if args.ssh:
            print('[-]  Running SSH Honeypot...') #Output to console that we're running ssh honeypot.
            honeypot(args.address, args.port, args.username, args.password) 
        
            if not args.username: #
                username = None
            if not args.password:
                password = None
        elif args.http:
            print('[-] Running HTTP WordPress Honeypot...')

            #If no username/password supplied then we need to supply username/password.
            
            if not args.username: #
                args.username = 'admin' #Default username if not supplied.
            if not args.password:
                args.password = 'password' #Default password if not supplied.

            print(f'Port: {args.port} Username: {args.username} Password: {args.password}') #Output to console the port, username, and password we're using for honeypot.
            run_web_honeypot(args.port, args.username, args.password)

            pass
        else:
            print('[!] Choose a honeypot type (SSH --ssh) or (HTTP --http).')
    except:
        print('\n Exiting HONEYPY...\n') #Ctrl C
