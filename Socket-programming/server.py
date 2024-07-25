"""
-> This client file is used to send messages from client to client
-> The server is used to facilitate the communication between the clients
"""
from socket import *
import json
import ast
import hashlib
import threading
from auth import create_database

class Server:
    def __init__(self, port):
        self.server_port = port
        self.client_socket = socket(AF_INET, SOCK_STREAM)
        self.clients = []
        self.client_sockets = {}
        create_database()

    def start(self):
        self.client_socket.bind(('', self.server_port))
        self.client_socket.listen(1)
        print("The server is ready to establish connection ....")

        while True:
            client_socket, client_address = self.client_socket.accept()
            self.client_sockets[client_address] = client_socket
            print("Connected to:", client_address)
            threading.Thread(target=self.client_communication, args=(client_socket, client_address)).start()

    def client_communication(self, client_socket, client_address):

        while True:
            try:
                # Receive a packet of data from the network, storing the data in @received_data and storing the sender's address in @client_sender_address
                received_data = client_socket.recv(2048)
                if not received_data:
                    break
                received_data = bytes(received_data)
                # Use json.loads to parse the JSON string
                decoded_data = json.loads(ast.literal_eval(received_data.decode())[0])

                if isinstance(decoded_data, dict):
                    # If the decoded data is a dictionary, convert it to a JSON-formatted string
                    json_string = json.dumps(decoded_data)
                    # Hash the JSON-formatted string
                    data_hash_value = hashlib.sha256(json_string.encode()).hexdigest()
                    print(data_hash_value)

                # Decode data from the client and store it in a dictionary
                client_data_storage = ast.literal_eval(received_data.decode()) # this data is a bit format
                client_data_hash_value = ast.literal_eval(received_data.decode())[1]
                message_stored_dict = json.loads(client_data_storage[0])
            
                #client_data_storage["header"] = dict(message_stored_tuple)

                # Encode the received message before hashing
                encoded_data = json.dumps(decoded_data).encode()

                # Hash the encoded data
                data_hash_value = hashlib.sha256(encoded_data).hexdigest()

                # Compare the hash value of the received message with the hash value of the message
                if client_data_hash_value != data_hash_value:
                    # Send an error message for incorrect message
                    received_data_structure = {
                        "header": {
                            "command": "",
                            "message_type": "ERROR",
                            "recipient_data": client_address,
                        },
                        "body": "Incorrect message structure!",
                    }
                    ready_to_send_message = str(received_data_structure).encode()
                    client_socket.sendall(ready_to_send_message)
                    continue

                # Store the command in a variable
            
                command = message_stored_dict["header"]["command"]

                # Store the message type in a variable
                message_type = message_stored_dict["header"]["message_type"]

                # Process the rest of your code with the validated data

                """
                -> This is a login command that is used to login a user
                -> The user credentials are stored in a dictionary 
                -> The user credentials are then stored in a list
                """
                if command == "LOGIN":
                    """ 
                        -> add some form of security protocol
                        -> login user and store user credentials together with client address
                        -> set up parameters for communication between clients before normal communication begins
                    """
                    client_data = message_stored_dict["body"]

                    if "username" in client_data and "password" in client_data:
                        username = client_data["username"]
                        password = client_data["password"]

                        # store user in user-dictionary
                        client = {
                            "username": username,
                            "password": password,
                            "sender_address": client_address,
                        }
                        self.clients.append(client)

                        # send a welcome message to the client
                        welcome_message_structure = {
                            "header": {
                                "command": "",
                                "message_type": "WELCOME",
                                "recipient_data": client_address,
                            },
                            "body": "Welcome, You have successfully logged in!",
                        }

                        # encode the message that is ready to be sent to the user
                        ready_to_send_message = str(welcome_message_structure).encode()
                        # send the message to the user
                        client_socket.sendall(ready_to_send_message)

                    else:
                        print("Incomplete client data. Unable to log in.")

                        """
                        -> send a message to all the clients that a user has logged in
                        -> This message is sent to all the clients except the client that just logged in
                        -> serves as an indication that a user X has logged in
                        """
                        for client in self.clients:
                            if client["client_socket"] != client_socket:
                                alert_message_structure = {
                                    "header": {
                                        "command": "",
                                        "message_type": "ALERT",
                                        "recipient_data": client_address,
                                    },
                                    "body": "{} {}".format(username, "is online!")
                                }
                                ready_to_send_message = str(alert_message_structure).encode()
                                client["client_socket"].sendall(ready_to_send_message)
                    
                elif command == "SEND_MESSAGE":
                    """
                    -> This command is used to send a message from one client to another
                    -> The message is sent to the receiver's address
                    """
                    message_details = message_stored_dict["body"]
                    sender_username = message_details.get("sender_username")
                    receiver_username = message_details.get("receiver_username")
                    text_to_be_sent = message_details.get("text")


                    if sender_username and receiver_username and text_to_be_sent:
                        for client in self.clients:
                            if receiver_username == client["username"]:
                                receiver_address = client["sender_address"]
                                received_data_structure = {
                                    "header": {
                                        "command": "",
                                        "message_type": "MESSAGE",
                                        "recipient_data": receiver_address,
                                    },
                                    "body": f"{sender_username} sent you a message: {text_to_be_sent}",
                                }
                                ready_to_send_message = str(receiver_address).encode()
                                notification_message_to_reciever = str(received_data_structure).encode()
                                receiver_socket = self.client_sockets.get(receiver_address)
                                client_socket.sendall(ready_to_send_message)
                                receiver_socket.sendall(notification_message_to_reciever)
                                break
                    else:
                        print("Incomplete message details. Unable to send message.")
                
                elif command == "BROADCAST":
                    """
                    -> This command is used to send a message to all the clients
                    -> The message is sent to all the clients except the sender
                    """
                    message_details = message_stored_dict["body"]
                    sender_username = message_details["sender_username"]
                    text_to_be_sent = message_details["text"]

                    for client in self.clients:
                        receiver_address = client["sender_address"]
                        if receiver_address != client_address:
                            received_data_structure = {
                                "header": {
                                    "command": "",
                                    "message_type": "MESSAGE",
                                    "recipient_data": receiver_address,
                                },
                                "body": " This message is broadcasted by {0}: {1}".format(sender_username, text_to_be_sent),
                            }
                            ready_to_send_message = str(received_data_structure).encode()
                            receiver_socket  = self.client_sockets.get(receiver_address)
                            receiver_socket.sendall(ready_to_send_message)
                            

                elif command == "CLIENTS":
                    """
                    -> This command is used to list all the clients that are online
                    -> The list of clients is sent to the sender
                    """
                    online_clients_list = [
                        f"{c['username']} : {c['sender_address']} is online!"
                        for c in self.clients
                        if c["sender_address"] != client_address
                    ]

                    if online_clients_list:
                        received_data_structure = {
                            "header": {
                                "command": "",
                                "message_type": "CLIENT_LIST",
                                "recipient_data": client_address,
                            },
                            "body": "\n".join(online_clients_list),
                        }
                        ready_to_send_message = str(received_data_structure).encode()
                        client_socket.sendall(ready_to_send_message)
                    else:
                        
                        message = {
                            "header": {
                                "command": "",
                                "message_type": "CLIENT_LIST",
                                "recipient_data": client_address,
                            },
                            "body": "No online clients.",
                        }
                        ready_to_send_message = str(message).encode()
                        client_socket.sendall(ready_to_send_message)
            
                elif command == "LOGOUT":
                    """
                    -> This command is used to logout a user
                    -> The user is removed from the list of clients
                    -> A message is sent to all the clients to indicate that a user has logged out
                    """
                    for client in self.clients:
                        if client["sender_address"] == client_address:
                            username = client["username"]
                            self.clients.remove(client)
                            print(self.clients)
                            for client in self.clients:
                                client_address = client["sender_address"]
                                received_data_structure = {
                                    "header": {
                                        "command": "",
                                        "message_type": "ALERT",
                                        "recipient_data": client_address,
                                    },
                                    "body": "{} {}".format(username, "is offline!")
                                }

                                ready_to_send_message = str(received_data_structure).encode()
                                receiver_socket  = self.client_sockets.get(client_address)
                                receiver_socket.sendall(ready_to_send_message)
                            break

                elif command ==  "" and message_type == "ACKNOWLEDGEMENT":
                    username = message_stored_dict["body"]["username"]
                    message = message_stored_dict["body"]["message"]

                    for client in self.clients:
                        if client["username"] == username:
                            client_address = client["sender_address"]
                            received_data_structure = {
                                "header": {
                                    "command": "",
                                    "message_type": "ACKNOWLEDGEMENT",
                                    "recipient_data": client_address,
                                },
                                "body": message,
                            }
                            ready_to_send_message = str(received_data_structure).encode()
                            client_socket.sendall(ready_to_send_message)
            except Exception as e:
                print("Error:", e)
                break


if __name__ == "__main__":
    server = Server(2001)
    server.start()
