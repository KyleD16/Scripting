import socket
import sqlite3
import ssl
import json

con = sqlite3.connect('/home/kyle/routers.db')
cursor = con.cursor()

server_cert = "/home/kyle/Scripting/Home Assignment/server.crt"
client_certs = "/home/kyle/Scripting/Home Assignment/client.crt"
server_key = "/home/kyle/Scripting/Home Assignment/server.key"

host = "127.0.0.1"
port = 12345


def add_router_to_db(router_info):
    try:
        id = router_info.split(",")[1]
        name = router_info.split(",")[2]
        ip = router_info.split(",")[3]
        username = router_info.split(",")[4]
        password = router_info.split(",")[5]
        print(id, name, ip, username,password)
        cursor.execute('Select * FROM Routers WHERE ip=?', (ip,))
        existing_router = cursor.fetchone()
        if existing_router:
            return "IP Address already exists. Router not added."

        cursor.execute('INSERT INTO Routers (id, name, ip, username, password) VALUES (?, ?, ?, ?, ?)',
                       (id, name, ip, username, password))

        con.commit()
        return "Router added Successfully"

    except sqlite3.Error as e:
        return f"Error adding Router: {str(e)}"



def list_routers_from_db():
    try:
        cursor.execute('SELECT name, ip, username, password FROM Routers')
        routers = cursor.fetchall()
        router_dicts = []
        for router in routers:
            router_dict = {
                'name': router[0],
                'ip': router[1],
                'username': router[2],
                'password': router[3]
            }
            router_dicts.append(router_dict)
        return router_dicts

    except sqlite3.Error as e:
        return f"Error listing Routers: {str(e)}"


def delete_router_by_ip(ip):
    try:
        ip = ip.strip("'\" ")
        cursor.execute('DELETE FROM Routers WHERE ip=?', (ip,))
        con.commit()

        if cursor.rowcount > 0:
            return "Router deleted successfully"
        else:
            return "Router with specified IP not found"

    except sqlite3.Error as e:
        return f"Error deleting Router: {str(e)}"

   

def handle_client_request(c_socket):
    data = c_socket.recv(1024).decode()
    print(data)
    parts = data.split(',')
    operation = parts[0]

    if operation == 'add':
        response = add_router_to_db(data)
    elif operation == 'delete':
        ip_to_delete = parts[1]
        response = delete_router_by_ip(ip_to_delete)
    elif operation == 'list':
        response = list_routers_from_db()
    else:
        response = 'Invalid operation'

    c_socket.sendall(str(response).encode())


def serve():
    try:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_cert_chain(certfile=server_cert, keyfile=server_key)
        context.load_verify_locations(cafile=client_certs)

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((host, port))
        s.listen()
        while(True):
            client_sock_unencrypted, addr = s.accept()
            with context.wrap_socket(client_sock_unencrypted, server_side=True) as client_sock:
                handle_client_request(client_sock)

    except ssl.SSLError as e:
        print(f"SSL Error: {str(e)}")
    except Exception as e:
        print(f"Error: {str(e)}")


if __name__ == "__main__":
    serve()

con.close()

