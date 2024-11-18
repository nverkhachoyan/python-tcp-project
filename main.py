# COMP429
# Group Project 1
# Nver Khachoyan and Pedro Reis

import socket
import sys
import os
import threading
from utils import is_valid_ip_addr

connections = {}
connections_lock = threading.Lock()
exit_event = threading.Event()
connection_id_counter = 1


def display_help():
    print("""
Available commands:
    1. help
    2. myip
    3. myport
    4. connect <destination> <port no>
    5. list
    6. terminate <connection id>
    7. send <connection id> <message>
    8. exit
    """)


def get_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(('8.8.8.8', 80))
            ip_addr = s.getsockname()[0]
    except Exception as e:
        print(f"Unable to retrieve IP address: {e}")
        ip_addr = '127.0.0.1'
    return ip_addr


def connect_peer(dest_ip, port, my_port):
    global connection_id_counter
    if (dest_ip == get_ip() and port == my_port):
        print("Self-connections are not allowed")
        return

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((dest_ip, port))
        with connections_lock:
            conn_id = connection_id_counter
            connections[conn_id] = client_socket
            connection_id_counter += 1
        print(f"Successfully connected to {dest_ip}:{port}")
        threading.Thread(target=handle_conn, args=(client_socket, (dest_ip, port)), daemon=True).start()
    except socket.error as e:
        print(f"Failed to connect to {dest_ip}:{port}. Error: {e}")


def list_connections():
    with connections_lock:
        if not connections:
            print("No active connections")
            return
        print(f"ID:\tIP Addr\t\tPort No.")
        for conn_id, conn in connections.items():
            remote_addr = conn.getpeername()
            print(f"{conn_id}\t{remote_addr[0]}\t{remote_addr[1]}")


def terminate_conn(conn_id):
    with connections_lock:
        if conn_id not in connections:
            print(f"Connection {conn_id} not found")
            return
        client = connections[conn_id]
        del connections[conn_id]
        client.close()
        print(f"Connection {conn_id} terminated")


def send_conn_message(conn_id, msg):
    with connections_lock:
        if conn_id in connections:
            client = connections[conn_id]
            client.sendall(msg.encode("utf-8"))
            print(f"Message sent to connection {conn_id}")
        else:
            print(f"Connection {conn_id} not found")


def handle_conn(conn, addr):
    while conn and not exit_event.is_set():
        try:
            data = conn.recv(1024).decode("utf-8")
            if data:
                print(f"Message from {addr}: {data}")
            else:
                print(f"Connection {addr} closed by the peer.")
                break
        except socket.error as e:
            if exit_event.is_set():
                break 
            print(f"Connection {addr} encountered an error. {e}")
            break
    
    with connections_lock:
        for key, val in list(connections.items()):
            if val == conn:
                del connections[key]
                break
    conn.close()


def start_server(port):
    global connection_id_counter
    server_socket = None
    try:
        server_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
        server_socket.bind(("", int(port)))
        server_socket.listen(5)
        server_socket.settimeout(1.0)
    except socket.error as e: 
        print(f"Failed to start the server. {e.strerror}.")
        terminate_all_connections()
        os._exit(1)
        
    while not exit_event.is_set():
        try:
            conn, addr = server_socket.accept()
            print("Connected to ", addr)
            with connections_lock:
                conn_id = connection_id_counter
                connections[conn_id] = conn
                connection_id_counter += 1
            threading.Thread(target=handle_conn, args=(conn, addr), daemon=True).start()
        except socket.timeout:
            continue
        except socket.error as e:
            if not exit_event.is_set():
                print(f"Server socket error: {e}")
            break
    server_socket.close()


def terminate_all_connections():
    with connections_lock:
        for conn_id, conn in list(connections.items()):
            try:
                conn.close()
                print(f"Connection {conn_id} closed.")
            except socket.error as e:
                print(f"Error closing connection {conn_id}: {e}")
            finally:
                del connections[conn_id]

def run_menu(my_port):
    valid_options = ['1', '2', '3', '4', '5', '6', '7', '8', 
                  'help', 'myip', 'myport', 'connect', 
                  'list', 'terminate', 'send', 'exit',
                  'h', 'ip', 'port', 'c', 'ls', 't', 's', 'q']
        
    while True:
        options = input(">> ").strip().split(" ")

        if options[0] not in valid_options:
            print("Command not found. Type 'help' for a list of valid commands.")
       
        match options[0]:
            case '1' | 'help' | 'h':
                display_help()
            case '2' | 'myip' | 'ip':
                print(f"My IP address: {get_ip()}")
            case '3' | 'myport' | 'port':
                print(f"Process port: {my_port}")
            case '4' | 'connect' | 'c':
                if len(options) != 3:
                    print("You must provide dest IP address and PORT")
                    continue
                _, ip, port = options
                if not is_valid_ip_addr(ip):
                    print("Destination must be a valid IP address")
                    continue
                if not port or not port.isnumeric(): 
                    print("Destination PORT must be number between 1 and 65535")
                    continue
                connect_peer(ip, int(port), my_port)
            case '5' | 'list' | 'ls':
                list_connections()
            case '6' | 'terminate' | 't':
                if len(options) != 2:
                    print("You must provide a connection ID")
                    continue
                conn_id = options[1]
                if not conn_id or not conn_id.isnumeric():
                    print("Connection ID cannot be empty or non-numeric")
                    continue
                terminate_conn(int(conn_id))
            case '7' | 'send' | 's':
                if len(options) != 3:
                    print("You must provide a conn ID and a message")
                    continue
                _, conn_id, msg = options
                if not conn_id or not conn_id.isnumeric():
                    print("Connection ID cannot be empty or non-numeric")
                    continue
                if not msg:
                    print("Message cannot be empty")
                    continue
                send_conn_message(int(conn_id), msg)
            case '8' | 'exit' | 'q':
                exit_event.set()
                terminate_all_connections()
                break
            case _:
                continue


def main():
    if len(sys.argv) != 2:
        print("Usage: chatapp <port>")
        return

    port = sys.argv[1]
    if not port.isdigit() or not (1 <= int(port) <= 65535):
        print("Port must be a number between 1 and 65535.")
        return
    
    server_thread = threading.Thread(target=start_server, args=(port,), daemon=True)
    server_thread.start()
    
    print("Welcome to ChatApp!")
    display_help()

    try:
        run_menu(my_port=int(port))
    except (KeyboardInterrupt, SystemExit):
        print("<< Quitting...")
    finally:
        exit_event.set()
        terminate_all_connections()
        server_thread.join(timeout=1) 
        sys.exit(0)


if __name__ == "__main__":
    main()