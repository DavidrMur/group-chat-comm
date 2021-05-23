#!/usr/bin/env python3


import socket
import argparse
import threading
import sys
import os 
import time
import re
import random
from os import listdir
from os.path import isfile, join

from config import *


########################################################################

# Define all of the packet protocol field lengths. See the
# corresponding packet formats below.
CMD_FIELD_LEN = 1 # 1 byte commands sent from the client.
FILE_SIZE_FIELD_LEN  = 8 # 8 byte file size field.



CMD = { "getdir" : 1, "makeroom": 2, "deleteroom": 3, "bye": 4, "chat":5 }

MSG_ENCODING = "utf-8"
    
########################################################################
# SERVER
########################################################################

class Server:

    HOSTNAME = "127.0.0.1"

    PORT = 30001
    RECV_SIZE = 1024
    BACKLOG = 5
    ADDRESS_PORT = (HOSTNAME, PORT)

    BRD_CST_HOST = "0.0.0.0"
    BRD_CST_PORT = 30000

    #BRD_CST_ADDRESS_PORT = ("0.0.0.0", Sender.BROADCAST_PORT)
    #BRD_CST_ADDRESS_PORT = (BRD_CST_HOST, BRD_CST_PORT)
    BRD_CST_ADDRESS_PORT = (HOSTNAME, BRD_CST_PORT)


    #MSG_ENCODED = MSG.encode(MSG_ENCODING)

    # This is the file that the client will request using a GET.
    #REMOTE_FILE_NAME = "remotefile.txt"

    def __init__(self):
        self.thread_list = []
        # Directory of format: {<chat room name>:{"address":<string>, "port":<int>}}
        self.chat_room_directory = {}
        self.create_listen_socket()
        self.process_connections_forever()
    
    def create_listen_socket(self):
        try:
            # Create the TCP server listen socket in the usual way.
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((Server.HOSTNAME, Server.PORT))
            self.socket.listen(Server.BACKLOG)
            print("Listening for CSDP connections on port {} ...".format(Server.PORT))

        except Exception as msg:
            print(msg)
            exit()

    def process_connections_forever(self):
        try:
            while True:
                # TODO: Use threads to process client connections
                new_client = self.socket.accept()

                # A new client has connected. Create a new thread and
                # have it process the client using the connection
                # handler function.
                new_thread = threading.Thread(target=self.command_handler,
                                                args=(new_client,))

                # Record the new thread.
                self.thread_list.append(new_thread)

                # Start the new thread running.
                print("Starting serving thread: ", new_thread.name)
                new_thread.daemon = True
                new_thread.start()
        
        except KeyboardInterrupt:
            print()
        finally:
            self.socket.close()

    def command_handler(self,client):
        connection,address = client
        print("-" * 72)
        print("Connection received from {}.".format(address))
        print("User is connected to Chat Room Directory Server (CRDS)")
        # Read the command and see if it is a GET.
        while True:
            try:

                cmd = int.from_bytes(connection.recv(CMD_FIELD_LEN), byteorder='big')
                if (cmd == CMD["getdir"]):
                    self.getdir_handler(client)
                elif(cmd == CMD["makeroom"]):
                    self.make_handler(client)
                elif(cmd == CMD["deleteroom"]):
                    self.delete_handler(client)
                elif(cmd == CMD["bye"]):
                    connection.close()
                    print("Connection to {} closed".format(address))
                    sys.exit()
                elif(cmd == CMD["chat"]):
                    self.chat_handler(client)
            except socket.error:
                connection.close()
                print("Connection to {} closed".format(address))
                sys.exit()

    #somebody come get dirr lol
    def getdir_handler(self, client):
        print("getdir handler")
        connection, address = client
        print("-" * 72)
        print("Connection received from {}.".format(address))
        connection.sendall(str(self.chat_room_directory).encode(MSG_ENCODING))

    def make_handler(self, client):
        print("makeroom handler")
        self.new_chat_room(client)
        # create new multicast chatroom via thread?
        
    def new_chat_room(self,client):
        connection, address = client
        params = connection.recv(Server.RECV_SIZE).decode(MSG_ENCODING).split('|')
        chat_room_name = params[1]
        ip = params[2]
        port = params[3]
        if(chat_room_name in self.chat_room_directory.keys()):
            print("Error! Duplicate room")
        elif {'address': ip, 'port': port} in self.chat_room_directory.values():
            print("Error. IP and port combination already exist")
        else:
            self.chat_room_directory[chat_room_name] = {'address': ip, 'port': port}


    def delete_handler(self, client):
        print("deleteroom handler")
        connection, address = client
        room = connection.recv(Server.RECV_SIZE).decode(MSG_ENCODING)
        print(f"Attempting to delete room {room}")
        try:
            self.chat_room_directory.pop(room)
        except KeyError:
            print(f"Room {room} does not exist")
        
    def chat_handler(self, client):
        connection, address = client
        room = connection.recv(Server.RECV_SIZE).decode(MSG_ENCODING)
        return_packet = "0"
        if (room in self.chat_room_directory):
            return_packet = self.chat_room_directory[room]["address"] + "|" + self.chat_room_directory[room]["port"]
        connection.sendall(return_packet.encode(MSG_ENCODING))

            

class Client:

    RECV_SIZE = 1024
# HOSTNAME = socket.gethostbyname('')
    HOSTNAME = 'localhost'

    TIMEOUT = 2
    
    MSG_ENCODING = "utf-8"
    # MESSAGE =  HOSTNAME + "multicast beacon: "

    TTL = 1 # Hops
    TTL_SIZE = 1 # Bytes
    TTL_BYTE = TTL.to_bytes(TTL_SIZE, byteorder='big')
    # OR: TTL_BYTE = struct.pack('B', TTL)

    def __init__(self):
        self.thread_list = []
        self.chat_name = "User" + str(random.randint(0,99)) 
        self.get_socket_TCP()
        self.receive_command()



    def get_socket_TCP(self):
        try:
            # Create an IPv4 TCP socket.
            self.socket_TCP = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def connect_to_server_TCP(self):
        try:
            # Connect to the server using its socket address tuple.
            self.socket_TCP.connect((Server.HOSTNAME, Server.PORT))
            print("Connected to CRDS")
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def close_server_connection_TCP(self):
        try:
            self.socket_TCP.close()
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def connection_receive_TCP(self):
        try:
            # Receive and print out text. The received bytes objects
            # must be decoded into string objects.
            recvd_bytes = self.socket_TCP.recv(Client.RECV_SIZE)

            # recv will block if nothing is available. If we receive
            # zero bytes, the connection has been closed from the
            # other end. In that case, close the connection on this
            # end and exit.
            if len(recvd_bytes) == 0:
                print("Closing server connection ... ")
                self.socket.close() 
                sys.exit(1)

            self.received_text = recvd_bytes.decode(MSG_ENCODING)

        except Exception as msg:
            print(msg)
            sys.exit(1)

    def get_socket_UDP(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)

            # Bind to an address/port. In multicast, this is viewed as
            # a "filter" that determines what packets make it to the
            # UDP app.

            BIND_ADDRESS_PORT = (RX_BIND_ADDRESS, MULTICAST_PORT)
            self.socket.bind(BIND_ADDRESS_PORT)

            ############################################################
            # The multicast_request must contain a bytes object
            # consisting of 8 bytes. The first 4 bytes are the
            # multicast group address. The second 4 bytes are the
            # interface address to be used. An all zeros I/F address
            # means all network interfaces.
            ############################################################
                        
            multicast_group_bytes = socket.inet_aton(MULTICAST_ADDRESS)

            print("Multicast Group: ", MULTICAST_ADDRESS)

            # Set up the interface to be used.
            multicast_if_bytes = socket.inet_aton(RX_IFACE_ADDRESS)

            # Form the multicast request.
            multicast_request = multicast_group_bytes + multicast_if_bytes

            # You can use struct.pack to create the request, but it is more complicated, e.g.,
            # 'struct.pack("<4sl", multicast_group_bytes,
            # int.from_bytes(multicast_if_bytes, byteorder='little'))'
            # or 'struct.pack("<4sl", multicast_group_bytes, socket.INADDR_ANY)'

            # Issue the Multicast IP Add Membership request.
            print("Adding membership (address/interface): ", MULTICAST_ADDRESS,"/", RX_IFACE_ADDRESS)
            self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, multicast_request)
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def get_console_input(self):
        # In this version we keep prompting the user until a non-blank
        # line is entered.
        while True:
            self.input_text = input("")
            if self.input_text != "":
                break

    def connect_to_chatroom(self, message):
        try:
            # Send string objects over the connection. The string must
            # be encoded into bytes objects first.
            self.socket.sendall(message.encode(MSG_ENCODING))
        except Exception as e:
            print(e)
            sys.exit(1)

    def connection_send_TCP(self, message):
        try:
            # Send string objects over the connection. The string must
            # be encoded into bytes objects first.
            self.socket_TCP.sendall(message)
        except Exception as e:
            print(e)
            sys.exit(1)

    def connection_send_multicast(self, message, multicast):
        try:
            
            self.socket.sendto(message.encode(MSG_ENCODING),multicast)
        except Exception as e:
            print(e)
            sys.exit(1)

    def receive_command(self):
        print("Enter command: ")
        while (True):
            self.get_console_input()
            print("Command entered: {}".format(self.input_text))
            command = self.input_text.split(" ")
            if(command[0] == "connect"):
                self.connect()
            elif(command[0] == "bye"):
                self.bye()
            elif(command[0] == "name"):
                self.name(command[1])
            elif(command[0] == "chat"):
                self.chat(command[1])
            elif(command[0] == "getdir"):
                self.getdir()
            elif(command[0] == "makeroom"):
                self.makeroom(command[1:])
            elif(command[0] == "deleteroom"):
                self.deleteroom(command[1])

    def connect(self):
        self.get_socket_TCP()
        self.connect_to_server_TCP()

    def bye(self):
        self.connection_send_TCP(CMD["bye"].to_bytes(CMD_FIELD_LEN,byteorder='big'))
        self.close_server_connection_TCP()

    def name(self, chat_name):
        # sets the name of the user when chatting
        self.chat_name = chat_name
        print("New name: {}".format(self.chat_name))

    def chat(self, chat_room_name):
        #Connecting to Server
        chat_packet = CMD["chat"].to_bytes(CMD_FIELD_LEN,byteorder='big')
        full_packet = chat_packet + chat_room_name.encode(MSG_ENCODING)
        self.connection_send_TCP(full_packet)
        self.connection_receive_TCP()
        if(self.received_text == "0"):
            print("Error! invalid chat room entered!")
            return
        chat_room_address = self.received_text.split("|")
        address = chat_room_address[0]
        port = int(chat_room_address[1])
        print(f'address:{address} port:{port}')

        #TODO: create 2 sockets, one for sending and one for recieving  
        # receiving socket should be bound to the multicast IP and port

        #sending chat messages to server
        #print('Entering chat mode entered')
        self.create_chat_sockets(address,port)
        self.create_sending_socket(address,port)

    def create_chat_sockets(self,address,port):
        try: 
            # create threads for listening and sending
            listening_thread = threading.Thread(target=self.create_listen_socket, args=(address, port))

            self.thread_list.append(listening_thread)
            #print("Starting listening thread: ", listening_thread.name)
            listening_thread.daemon = True
            listening_thread.start()


            # sender_thread = threading.Thread(target=self.create_sending_socket)

            # self.thread_list.append(sender_thread)
            # print("Starting listening thread: ", sender_thread.name)
            # sender_thread.daemon = True
            # sender_thread.start()

        except Exception as msg:
            print(msg)
            sys.exit(1)

    def create_listen_socket(self, address, port):
        try:
            self.listening_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.listening_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)

            # Bind to an address/port. In multicast, this is viewed as
            # a "filter" that determines what packets make it to the
            # UDP app.

            BIND_ADDRESS_PORT = (RX_BIND_ADDRESS, port)

            self.listening_socket.bind(BIND_ADDRESS_PORT)

            ############################################################
            # The multicast_request must contain a bytes object
            # consisting of 8 bytes. The first 4 bytes are the
            # multicast group address. The second 4 bytes are the
            # interface address to be used. An all zeros I/F address
            # means all network interfaces.
            ############################################################
                        
            multicast_group_bytes = socket.inet_aton(address)

            print("Multicast Group: ", address)
            print("address: ", address)
            print("port: ", port)


            # Set up the interface to be used.
            multicast_if_bytes = socket.inet_aton(RX_IFACE_ADDRESS)

            # Form the multicast request.
            multicast_request = multicast_group_bytes + multicast_if_bytes

            # You can use struct.pack to create the request, but it is more complicated, e.g.,
            # 'struct.pack("<4sl", multicast_group_bytes,
            # int.from_bytes(multicast_if_bytes, byteorder='little'))'
            # or 'struct.pack("<4sl", multicast_group_bytes, socket.INADDR_ANY)'

            # Issue the Multicast IP Add Membership request.
            print("Adding membership (address/interface): ", address,"/", RX_IFACE_ADDRESS)
            self.listening_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, multicast_request)
            self.receive_forever()
        except Exception as msg:
            print(msg)
            sys.exit(1)
    
    def create_sending_socket(self,address,port):
        try:
            self.sending_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sending_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, Client.TTL_BYTE)
            # self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, Sender.TTL)  # this works fine too
            # self.socket.bind(("192.168.2.37", 0))  # This line may be needed.
            self.send_messages_forever(address,port)
        except Exception as msg:
            print(msg)
            sys.exit(1)


    def receive_forever(self):
        #print("waiting...")
        while True:
            #print("looping")
            try:
                #print("trying")
                data, address_port = self.listening_socket.recvfrom(Client.RECV_SIZE)
                address, port = address_port
                msg = data.decode('utf-8')
                if(msg[0:len(self.chat_name)+1] != (self.chat_name + ":")):
                    print(data.decode('utf-8'))
            except KeyboardInterrupt:
                print(); exit()
            except Exception as msg:
                print(msg)
                sys.exit(1)

    def send_messages_forever(self, address, port):
        print("In chat mode")
        stripped_msg = ""
        try:
            msg = sys.stdin.readline()
            stripped_msg = msg.replace("\n", "")
            while(stripped_msg != "exit"):
                full_message = f"{self.chat_name}: {msg}"
                MULTICAST_ADDRESS_PORT = (address, port)
                self.sending_socket.sendto(full_message.encode('utf-8'), MULTICAST_ADDRESS_PORT)
                sys.stdout.flush() 
                time.sleep(Client.TIMEOUT)

                msg = sys.stdin.readline()
                stripped_msg = re.sub(r'\W+', '', msg)
            self.receive_command()
        except Exception as msg:
            print(msg)
        except KeyboardInterrupt:
            print()
        finally:
            self.sending_socket.close()
            sys.exit(1)


    def getdir(self):
        self.connection_send_TCP(CMD["getdir"].to_bytes(CMD_FIELD_LEN,byteorder='big'))
        self.connection_receive_TCP()
        print("Chat Room Directory: {}".format(self.received_text))

    def makeroom(self, info):
        if(len(info) != 3):
            print("Error! makeroom command must be entered as:\n makeroom <chat_room_name> <ip_address> <port>")
            return
        packet = CMD["makeroom"].to_bytes(CMD_FIELD_LEN, byteorder='big')
        divider_packet = "|".encode(MSG_ENCODING)
        for i in range(3):
            packet += divider_packet + info[i].encode(MSG_ENCODING)
        self.connection_send_TCP(packet)

    def deleteroom(self, room_name):
        deleteroom_cmd = CMD["deleteroom"].to_bytes(CMD_FIELD_LEN, byteorder='big')
        self.connection_send_TCP(deleteroom_cmd + room_name.encode(MSG_ENCODING))

########################################################################

if __name__ == '__main__':
    roles = {'client': Client,'server': Server}
    parser = argparse.ArgumentParser()

    parser.add_argument('-r', '--role',
                        choices=roles, 
                        help='server or client role',
                        required=True, type=str)

    args = parser.parse_args()
    roles[args.role]()

########################################################################
