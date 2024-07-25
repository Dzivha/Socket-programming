"""
-> This file is used to create a client for the server.
-> The client is used to send messages to the client
-> The client is used to send messages to all the clients
"""

import ast
from socket import *
import hashlib
import json
import sys
from threading import Thread
import threading
from time import sleep
import auth
#import keyboard

class colors:
    """
    This class provides named constants for common terminal colors and formatting styles.
    """

    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    BLINKING = '\033[5m'
    GREEN_HIGHLIGHTED = '\033[102m'
    YELLOW_HIGHLIGHTED = '\033[43m'
    RED_HIGHLIGHTED = '\033[101m'  # Corrected for red highlighted color
    BLUE_HIGHLIGHTED = '\033[104m'
    WHITE_HIGHLIGHTED = '\033[7m'

# Improved variable and structure naming
server_name = gethostname()
server_port = 2001
client_socket = socket(AF_INET, SOCK_STREAM)
client_socket.connect((server_name, server_port))

# Improve structure definition and type hinting
online_clients: dict[str, str] = {
    "username": "",
    "password": "",
}
def receive_messages(sock):
    while True:
        data, addr = sock.recvfrom(1024)
        print(f"Received message from {addr}: {data.decode('utf-8')}")

def send_messages(sock, dest_ip, dest_port):
    while True:
        message = input("Enter message: ")
        sock.sendto(message.encode('utf-8'), (dest_ip, dest_port))
        

def get_socket_details(socket_obj):
    # Get the socket's own address information
    socket_address = socket_obj.getsockname()

    # Extract IP address and port from the socket address
    ip_address = socket_address[0]
    port = socket_address[1]

    return ip_address, port
def print_welcome_message():
    welcome_message = """
    █     █░▓█████  ██▓     ▄████▄   ▒█████   ███▄ ▄███▓▓█████ 
    ▓█░ █ ░█░▓█   ▀ ▓██▒    ▒██▀ ▀█  ▒██▒  ██▒▓██▒▀█▀ ██▒▓█   ▀ 
    ▒█░ █ ░█ ▒███   ▒██░    ▒▓█    ▄ ▒██░  ██▒▓██    ▓██░▒███   
    ░█░ █ ░█ ▒▓█  ▄ ▒██░    ▒▓▓▄ ▄██▒▒██   ██░▒██    ▒██ ▒▓█  ▄ 
    ░░██▒██▓ ░▒████▒░██████▒▒ ▓███▀ ░░ ████▓▒░▒██▒   ░██▒░▒████▒
    ░ ▓░▒ ▒  ░░ ▒░ ░░ ▒░▓  ░░ ░▒ ▒  ░░ ▒░▒░▒░ ░ ▒░   ░  ░░░ ▒░ ░
    ▒ ░ ░   ░ ░  ░░ ░ ▒  ░  ░  ▒     ░ ▒ ▒░ ░  ░      ░ ░ ░  ░
    ░   ░     ░     ░ ░   ░        ░ ░ ░ ▒  ░      ░      ░   
        ░       ░  ░    ░  ░░ ░          ░ ░         ░      ░  ░
                            ░                                   
    """

    print(welcome_message)

def display_commands():
    print("Available commands: {} | {} | {} | {} | {} | {}".format(
        colors.YELLOW + "message" + colors.ENDC,
        colors.YELLOW + "message*" + colors.ENDC,
        colors.CYAN + "contacts" + colors.ENDC,
        colors.BLUE + "logout" + colors.ENDC,
        colors.RED + "quit" + colors.ENDC,
        colors.BLUE + "help" + colors.ENDC))

def connect_to_client(message = {}):
    """
    -> This function is used to connect to the server and establish a connection
    -> The function is used to send messages to the server
    """

    received_data_structure = {
        "header": {
            "command": "LOGIN",
            "message_type": "INITIATE_SESSION",
            "recipient_data": (server_name, server_port),
        },
        "body": message,
    }

    message_json = json.dumps(received_data_structure)
    message_json_encoded = message_json.encode('utf-8')
    # hash the message
    hash_value = hashlib.sha256(message_json_encoded)
    # store the hash value in a variable
    message_hash_value = hash_value.hexdigest()
    # store the message and hash value in a variable
    # this is a message that is ready to be sent
    ready_to_send_message = str([message_json, message_hash_value]).encode()
    # send the message
    client_socket.sendall(ready_to_send_message)

def send_message_to_online_client(message = {}):
    """
    -> This function is used to send messages to online clients
    -> The function is used to send messages to the server
    """

    received_data_structure = {
        "header": {
            "command": "SEND_MESSAGE",
            "message_type": "MESSAGE",
            "recipient_data": (server_name, server_port),
        },
        "body": message,
    }
    message_json = json.dumps(received_data_structure)
    message_json_encoded = message_json.encode('utf-8')
    # hash the message
    hash_value = hashlib.sha256(message_json_encoded)
    # store the hash value in a variable
    message_hash_value = hash_value.hexdigest()
    # store the message and hash value in a variable
    # this is a message that is ready to be sent
    ready_to_send_message = str([message_json, message_hash_value]).encode()
    # send the message
    client_socket.sendall(ready_to_send_message)
    response = client_socket.recv(1024).decode()

    addr = response.strip("()").split(',')
    dest_ip_address = addr[0].strip("'")
    dest_port_number = addr[1].strip()

    # Get destination IP and port after choosing to connect
    dest_ip = dest_ip_address
    dest_port = int(dest_port_number)

    # Get the socket's own IP address and port
    own_ip_address, own_port = get_socket_details(client_socket)
    
    # Create UDP socket
    udp_host = own_ip_address
    udp_port = int(own_port)
    sock = socket(AF_INET, SOCK_DGRAM)
    sock.bind((udp_host, udp_port))

    # Start receive thread
    receive_thread = threading.Thread(target=receive_messages, args=(sock,))
    receive_thread.daemon = True
    receive_thread.start()

    # Start send thread
    send_thread = threading.Thread(target=send_messages, args=(sock, dest_ip, dest_port))
    send_thread.daemon = True
    send_thread.start()
    
    while True:
        pass
        # if keyboard.is_pressed('esc'):
        #     sock.close()
        #     break

def broadcast_message(message = {}):
    """
    -> This function is used to broadcast messages to all the clients
    -> The function is used to send messages to the server
    """

    received_data_structure = {
        "header": {
            "command": "BROADCAST",
            "message_type": "MESSAGE",
            "recipient_data": (server_name, server_port),
        },
        "body": message,
    }

    # Check if the sender is the same as the online client, skip sending the message
    # if message.get("sender_username") == online_clients["username"]:
    #     return
    

    message_json = json.dumps(received_data_structure)
    message_json_encoded = message_json.encode('utf-8')
    # hash the message
    hash_value = hashlib.sha256(message_json_encoded)
    # store the hash value in a variable
    message_hash_value = hash_value.hexdigest()
    # store the message and hash value in a variable
    # this is a message that is ready to be sent
    ready_to_send_message = str([message_json_encoded, message_hash_value]).encode()
    # send the message
    client_socket.sendall(ready_to_send_message)

def display_online_clients(message = {}):
    """
    -> This function is used to display online clients
    -> The function is used to send messages to the server
    """

    received_data_structure = {
        "header": {
            "command": "CLIENTS",
            "message_type": "DISPLAY_ONLINE_CLIENTS",
            "recipient_data": "",
        },
        "body": message,
    }
    message_json = json.dumps(received_data_structure)
    message_json_encoded = message_json.encode('utf-8')
    # hash the message
    hash_value = hashlib.sha256(message_json_encoded)
    # store the hash value in a variable
    message_hash_value = hash_value.hexdigest()
    # store the message and hash value in a variable
    # this is a message that is ready to be sent
    ready_to_send_message = str([message_json, message_hash_value]).encode()
    # send the message
    client_socket.sendall(ready_to_send_message)

def logout_client(message = {}):
    """
    -> This function is used to logout a client
    -> The function is used to send messages to the server
    """

    received_data_structure = {
        "header": {
            "command": "LOGOUT",
            "message_type": "CLOSE_CHAT",
            "recipient_data": (server_name, server_port),
        },
        "body": message,
    }
    message_json = json.dumps(received_data_structure)
    message_json_encoded = message_json.encode('utf-8')
    # hash the message
    hash_value = hashlib.sha256(message_json_encoded)
    # store the hash value in a variable
    message_hash_value = hash_value.hexdigest()
    # store the message and hash value in a variable
    # this is a message that is ready to be sent
    ready_to_send_message = str([message_json, message_hash_value]).encode()
    # send the message
    client_socket.sendall(ready_to_send_message)

def send_acknowledgement(message = {}):
    """
    -> This function is used to send an acknowledgement
    -> The function is used to send messages to the client
    """
    received_data_structure = {
        "header": {
            "command": "",
            "message_type": "ACKNOWLEDGEMENT",
            "recipient_data": (server_name, server_port),
        },
        "body": message,
    }
    message_json = json.dumps(received_data_structure)
    message_json_encoded = message_json.encode('utf-8')
    # hash the message
    hash_value = hashlib.sha256(message_json_encoded)
    # store the hash value in a variable
    message_hash_value = hash_value.hexdigest()
    # store the message and hash value in a variable
    # this is a message that is ready to be sent
    ready_to_send_message = str([message_json, message_hash_value]).encode()
    # send the message
    client_socket.sendall(ready_to_send_message)

def receive_message():
    """
    -> This function is used to receive messages
    """

    while True:
        try:

            """
            -> this function runs a separate thread to receive messages from the client
            -> uses client commands to perform actions
            """
            message= client_socket.recv(2048)
            stored_message = ast.literal_eval(message.decode())

            header = stored_message["header"]
            message_type = header["message_type"]
            command = header["command"]
            message_body = stored_message["body"]


            if len(command) == 0 or command == "":
                if message_type == "INITIATE_SESSION":
                    print(f"{colors.OKGREEN}Connection established with server{colors.ENDC}")
                    send_acknowledgement()
                    continue
                elif message_type == "ACKNOWLEDGEMENT":
                    (f"{colors.OKGREEN}Acknowledgement: {message_body}{colors.ENDC}")
                    continue
                elif message_type == "DISPLAY_ONLINE_CLIENTS":
                    print(f"{colors.OKGREEN}Online Clients: {message_body}{colors.ENDC}")
                    continue
                elif message_type == "CLOSE_CHAT":
                    print(f"{colors.RED }Chat closed: {message_body}{colors.ENDC}")
                    continue
                elif message_type == "ALERT":
                    print(f"{colors.YELLOW_HIGHLIGHTED}Message: {message_body}{colors.ENDC}")
                    continue

            if message_type == "MESSAGE":
                username = message_body.split(" ")[3].split(":")[0]
                message = {
                    "username": username,
                    "message": "Message received by " + online_clients["username"],
                }
                print(f"{colors.BOLD}Message: {message_body}{colors.ENDC}")
                send_acknowledgement(message)
            
            elif message_type == "BROADCAST":
                username = message_body.split(" ")[3].split(":")[0]
                message = {
                    "username": username,
                    "message": "Message received by " + online_clients["username"],
                }
                print(f"{colors.BOLD}Message: {message_body}{colors.ENDC}")
                send_acknowledgement(message)

            if message_type == "ACKNOWLEDGEMENT":
                print(f"{colors.OKGREEN}Acknowledgement: {message_body}{colors.ENDC}")

            elif message_type == "WELCOME":
                print(f"{colors.GREEN_HIGHLIGHTED}{message_body}{colors.ENDC}")
                display_commands()

            elif message_type == "CLIENT_LIST":
                print(f"{colors.GREEN}Online Clients: {message_body}{colors.ENDC}")
           
        except OSError:
            print(f"{colors.FAIL}Error: OSError!{colors.ENDC}")
            break

def establish_connection():
    """ This function runs on a seperate thread to take user commands and 
        do some operations { login & establishing connections, logout, messaging } 
    """

    print("avaible commands: {} | {} ".format(colors.GREEN + "login" + colors.ENDC, colors.RED + "quit"))

    while True:
        sleep(1)
        # take in the command from the user... login, logout, message, contacts
        user_input = input("\n" + colors.BLINKING + ">>> " + colors.ENDC).split(" ")

        command = user_input[0]

        if command == "login":

            # check if user not logged in already
            if online_clients["username"] != "":
                print("already logged in... as " + online_clients["username"])
                continue

            username = input("enter username: ")

            # check if username is not already in use

            user = auth.findUser(username)

            if user["success"]:
                
                # try user password until user loggs in
                while len(online_clients["username"]) == 0:

                    # compare password
                    password = input("enter password: ")

                    if auth.password_equal(password, user["password"]):

                        # found user, proceed with login
                        userCredentials = {"username": username, "password": auth.hash_password(password)}

                        print("loging in....")
                        print()
                        sleep(1)
                        connect_to_client(userCredentials)
                        
                        # store user locally
                        online_clients["username"] = username 
                        online_clients["password"] = auth.hash_password(password) 
                        display_commands()
                        break
                    else:
                        print("Wrong password!")
            
            # user not found 
            else:
                print("User record doesn't exist")
                answer = input("sign up ? Y/N... ")
                
                if answer in ["Y", "Yes", "y", "yes"]:
                    password = input("enter password: ")

                    print("signing up...")
                    sleep(1)

                    # add user to database
                    auth.addUser(username, password)

                    userCredentials = {"username": username, "password": auth.hash_password(password)}

                    print("loging in....")
                    sleep(1)
                    connect_to_client(userCredentials)
                    
                    # store user locally
                    online_clients["username"] = username 
                    online_clients["password"] = auth.hash_password(password)
                   

                else:
                    print("quiting....")
                    break
                # user not found, automitaclly register on database and login

        elif command == "quit":
            print("quitting...")
            sleep(1)
            print("Application closed!")
            

            online_clients["username"] = "" 
            online_clients["password"] = "" 
            logout_client() 
            break
        
        elif command in ["message", "contacts", "logout", "message*", "help"]: # commands reserved for logged in users

            # error if user enters commands valid for logged in user if they are not logged in
            if online_clients["username"] == "":
                print(colors.RED + "not authenticated" + colors.ENDC)

            else:

                if command == "logout":
                    print("logging out...")
                    sleep(1)

                    online_clients["username"] = "" 
                    online_clients["password"] = "" 
                    logout_client() 
                    print("avaible commands: {} | {} ".format(colors.GREEN + "login" + colors.ENDC, colors.RED + "quit" + colors.ENDC))

                elif command == "message":
                    receiver_username = user_input[1]
                    text = " ".join(user_input[2:])
                    
                    if receiver_username == online_clients["username"]:
                        print("messages to one-self not allowed!")
                    else:
                        message = {
                            "sender_username": online_clients["username"],
                            "receiver_username": receiver_username,
                            "text": text
                        }
                        send_message_to_online_client(message)
                    display_commands()
                    
                elif command == "message*":
                    text = " ".join(user_input[1:])
                
                    message = {
                    "sender_username": online_clients["username"],
                    "receiver_username": "",
                    "text": text
                    }
                    broadcast_message(message)
                    display_commands()

                elif command == "contacts":
                    display_online_clients()
                    sleep(1)
                    display_commands()

                elif command == "help":
                    print("Logout: This command is used to logout from the server,\nMessage: This command is used to send a message to a client,\nMessage*: This command is used to broadcast a message to all the clients,\nContacts: This command is used to display online clients,\nQuit: This command is used to quit the server.")
                    continue
                
        else:
            if online_clients["username"] == "":
                print("valid commands: {} | {} ".format(colors.GREEN + "login" + colors.ENDC, colors.RED + "quit" + colors.ENDC)) 
            else:
                display_commands()
    
    
    sys.exit()


if __name__ == "__main__":
    print_welcome_message()
    # create a thread to receive messages
    Thread(target = receive_message).start()
    Thread(target = establish_connection).start()
