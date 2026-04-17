#Libraries
import logging #Log ip address, username, and passsword. Part of the standard python library. Don't rlly need this here.
from logging.handlers import RotatingFileHandler #Set where we are going to log to.
import socket
import paramiko
import socket
import threading 

#Constants
logging_format = logging.Formatter('%(message)s') #How messages will be formated in the log file.
SSH_BANNER = "SSH-2.0-OpenSSH_1.0" #When an incoming connection/client is attempting to connect, SSH_BANNER will send info verssion,runnign,any meta data about the ssh server.

#host_key = 'server.key' #Public private key pair generated. this is the private part of that component. keep secret or local.
host_key = paramiko.RSAKey(filename='server.key')

#Loggers & Logging Files
funnel_logger = logging.getLogger('FunnelLogger') #This is capture the username, password, and ip addresses.
funnel_logger.setLevel(logging.INFO) #Will provide the info logger. Different levels of logs will use info to get general information.
funnel_handler = RotatingFileHandler('audits.log',maxBytes=2000, backupCount=5) #Set the log file, max size, and backup count.
funnel_handler.setFormatter(logging_format) #Set the format to the funnel handler.
funnel_logger.addHandler(funnel_handler) #Add all this to our funnler_logger object in the beginning.

#Capture emulted shell, what commands are being used during the honeypot session.
creds_logger = logging.getLogger('CredsLogger')
creds_logger.setLevel(logging.INFO)
creds_handler = RotatingFileHandler('cmd_audits.log',maxBytes=2000, backupCount=5)
creds_handler.setFormatter(logging_format)
creds_logger.addHandler(creds_handler) 

#Emulated Shell
def emulated_shell(channel, client_ip):
    channel.send(b'corporate-jumpbox2$ ') #Channel is our way to send messages or strings over the SSH connection.
    command = b"" #Listening for user input.
    while True: #
        char = channel.recv(1) #Listening for user input.
        channel.send(char) #Send that in char.
        if not char:
            channel.close() #If no character then close the channel.

        command += char #Add chars to one singular string.

        if char == b'\r': #.strip for raw input no formatting.
            if command.strip() == b'exit': #If exit then close channel.
                response = b'\n Godbye!\n'
                channel.close()
            elif command.strip() == b'pwd': #Print working directory.
                response = b'\n' + b'\n\\usr\\local' + b'\r\n'
                creds_logger.info(f'Command {command.strip()}' + 'executed by ' + f'{client_ip}')
            elif command.strip() == b'whoami': #Print username.
                response = b'\n' + b"corpuser1" + b'\r\n'
                creds_logger.info(f'Command {command.strip()}' + 'executed by ' + f'{client_ip}')
            elif command.strip() == b'ls': #List files in the directory.
                response = b'\n' + b'jumpbox1.conf' + b"\r\n" #Spoofable file
                creds_logger.info(f'Command {command.strip()}' + 'executed by ' + f'{client_ip}')
            elif command.strip() == b'cat jumpbox1.conf': #If attacks wants to see contents of this config file.
                response = b'\n' + b'Go to deeboodah.com.' + b'\r\n'
                creds_logger.info(f'Command {command.strip()}' + 'executed by ' + f'{client_ip}')
            else:
                response = b'\n' + bytes(command.strip()) + b'\r\n' #If user doesn't use above commands then echo back whatever they type.
                creds_logger.info(f'Command {command.strip()}' + 'executed by ' + f'{client_ip}')
            channel.send(response)
            channel.send(b'corporate-jumpbox2$ ')
            command = b""

#SSH Server + Sockets

class Server(paramiko.ServerInterface):

    def __init__(self, client_ip, input_username=None, input_password=None):
        self.event = threading.Event() #Calculate or create new event.
        self.client_ip = client_ip
        self.input_username = input_username
        self.input_password = input_password

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED #If the channel type is session then open connection.
        
    def get_allowed_auths(self):
        return 'password' #Basic auth(SSH can support more)
    
    def check_auth_password(self, username, password): #Default username password
        funnel_logger.info(f'Client {self.client_ip} attempted connection with ' + f'username: {username}' + f'password: {password}')
        creds_logger.info(f'{self.client_ip}, {username}, {password}')
        if self.input_username is not None and self.input_password is not None:
            if username == self.input_username and password == self.input_password: #Any username/password accepted.
                return paramiko.AUTH_SUCCESSFUL
            else:
                return paramiko.AUTH_FAILED
        else:
            return paramiko.AUTH_SUCCESSFUL #No username/password thats fine.
            
    def check_channel_shell_request(self, channel): #If the channel request is for a shell then open the connection.
        self.event.set()
        return True
    
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes): #If the channel request is for a pseudo terminal then open the connection.
        return True
    
    def check_channel_exe_request(self, channel, command): #Where we handle the commands being inputed.
        command = str(command)
        return True
    
def client_handler(client, addr, username, password):
    client_ip = addr[0]
    print(f'{client_ip} has connected to the server.') #See client has connected and output to console.

    try:
        transport = paramiko.Transport(client) #Handle the lowlevel ssh session.
        transport.local_version = SSH_BANNER #Custom banner.
        server = Server(client_ip=client_ip, input_username=username, input_password=password) #Create instance of server.

        transport.add_server_key(host_key) #Pass in ssh session into server class. #Host key is public private key pair which allows incoming connection/clients to verify that the server is who they say they are.
        transport.start_server(server=server)

        channel = transport.accept(100) #Wait 100 miliseconds for client to open channel.
        if channel is None: #If client does not establish channel connection.
            print('No channel was opened.')
        
        standard_banner = 'Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.4.0-42-generic x86_64)\r\n' #New session has been established.
        channel.send(standard_banner)
        emulated_shell(channel, client_ip=client_ip) #Send instance of our emulated shell, to start capturing commands.

    except Exception as error:
        print(error)
        print('Error handling client connection!')
    finally:
        try:
            transport.close()
        except Exception as error:
            print(error)
            print('Error closing transport!')
        client.close()

#Provision SSH=based Honeypot

def honeypot(address, port, username, password): #Main function to be interfacting from.
    socks = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #IPv4 addresses that we are gonna be listening using the TCP port. Stateful connection port.
    socks.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) #Can resuse same adress even if its come in before.
    socks.bind((address, port)) #Bind the socket to the address and port.

    socks.listen(100) #Limit of 100 connections.
    print(f'SSH is listening on port {port}.')

    while True:
        try: #Start thread to handle concurent connections so server is not locked into one session at a time.
            client, addr  = socks.accept() #Accept client and address.
            ssh_honeypot_thread = threading.Thread(target=client_handler, args=(client, addr, username, password))
            ssh_honeypot_thread.start()
        except Exception as error:
            print(error)
            print('Error accepting client connection!')

honeypot('127.0.0.1', 2223, 'username', 'password')