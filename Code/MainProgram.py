import matplotlib.pyplot as plt
import socket
import ssl
import sqlite3
import requests
from netmiko import ConnectHandler
import time
import difflib
import os
from datetime import datetime

server_cert = "/home/kyle/Scripting/Home Assignment/server.crt"
client_cert = "/home/kyle/Scripting/Home Assignment/client.crt"
client_key = "/home/kyle/Scripting/Home Assignment/client.key"

host = "127.0.0.1"
port = 12345
github_api_url = "https://api.github.com/repos/KyleD16/Scripting/contents/router_configs"

def send_request(operation, data=None):
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=server_cert)
    context.load_cert_chain(certfile=client_cert, keyfile=client_key)

    with socket.create_connection((host, port)) as sock:
        with context.wrap_socket(sock, server_hostname='example.com') as ssock:
            if data:
                request = f"{operation.strip()}, {data.strip()}" if operation != 'list' else operation
            else:
                request = operation.strip()
            print(f"Sending request: {request}")
            ssock.sendall(request.encode())
            response = ssock.recv(1024).decode()
            print(f"Received response: {response}")
    return response


def execute_command(ssh_client, command):
    print(f"Executing command: {command}")
    output = ssh_client.send_command(command, expect_string=r'[>#]', delay_factor=2)
    print(output)
    

def set_netflow_settings(ip_address):
    try:
        conn = sqlite3.connect('/home/kyle/routers.db')
        cursor = conn.cursor()
        cursor.execute("SELECT username, password, ip FROM routers WHERE ip=?", (ip_address,))
        router_info = cursor.fetchone()
        conn.close()

        if router_info:
            username, password, router_ip = router_info
            print(f"Establishing SSH connection with router at {router_ip}...")
            ssh_client = ConnectHandler(
                device_type='cisco_ios',
                ip=router_ip,
                username=username,
                password=password,
                global_delay_factor=2,
            )
            print(f"SSH connection established with router at {router_ip}")
        

            commands = [
                "conf t",
                "int fa0/0",
                "ip flow ingress",
                "ip flow egress",
                "exit",
                "ip flow-cache timeout inactive 10",
                "ip flow-cache timeout active 1",
                "ip flow-export source FastEthernet0/0",
                "ip flow-export version 9",
                f"ip flow-export destination 192.168.122.1 2055",
                "exit",
                "write mem"  
            ]
            for command in commands:
                execute_command(ssh_client, command)
                time.sleep(1)

            ssh_client.disconnect()
            print(f"SSH connection closed with router at {router_ip}")
        else:
            print(f"No router found with IP {ip_address}.")
    except Exception as e:
        print(f"An error occurred: {e}")


def remove_netflow_settings(ip_address):
    try:
        conn = sqlite3.connect('/home/kyle/routers.db')
        cursor = conn.cursor()
        cursor.execute("SELECT username, password, ip FROM routers WHERE ip=?", (ip_address,))
        router_info = cursor.fetchone()
        conn.close()

        if router_info:
            username, password, router_ip = router_info
            print(f"Establishing SSH connection with router at {router_ip}...")
            ssh_client = ConnectHandler(
                device_type='cisco_ios',
                ip=router_ip,
                username=username,
                password=password,
                global_delay_factor=2,
            )
            print(f"SSH connection established with router at {router_ip}")

            commands = [
                "conf t",
                "int FastEthernet0/0",
                "no ip flow ingress",
                "no ip flow egress",
                "exit",
                "no ip flow-export source FastEthernet0/0",
                "no ip flow-export destination 192.168.122.1 2055",
                "exit",
                "write mem" 
            ]
            for command in commands:
                execute_command(ssh_client, command)
                time.sleep(1)

            ssh_client.disconnect()
            print(f"SSH connection closed with router at {router_ip}")
        else:
            print(f"No router found with IP {ip_address}.")
    except Exception as e:
        print(f"An error occurred: {e}")


def fetch_router_config():
    try:
        router_ip = input("Enter the IP address of the router: ")
        response = requests.get(github_api_url)
        content = response.json()

        for item in content:
            if item["name"] == f"{router_ip}_config.txt":
                download_url = item["download_url"]
                config_response = requests.get(download_url)
                config_content = config_response.text
                print(f"Router Configuration for {router_ip}:")
                print(config_content)
                break
        else:
            print(f"Configuration file for {router_ip} not found.")
    except Exception as e:
        print(f"Error fetching router configuration: {str(e)}")
        

def add_router():
    id = input("Enter Unique ID: ")
    name = input("Enter Router Name: ")
    ip = input("Enter IP Address: ")
    username = input("Enter Username: ")
    password = input("Enter Password: ")

    router_info = "add," + id + "," + name + "," + ip + "," + username + "," + password

    result = send_request(router_info)
    print(result)


def list_routers():
    result = send_request('list')
    if isinstance(result, list):
        for router in result:
            print(f"Router Name: {router['name']}, IP Address: {router['ip']}, "
                  f"Username: {router['username']}, Password: {router['password']}")
    else:
        print(result)


def delete_router():
    ip_to_delete = input("Enter IP Address to delete: ")
    result = send_request('delete', ip_to_delete)
    print(result)


def setup_backup_time():
    try:
        conn = sqlite3.connect('/home/kyle/routers.db')
        cursor = conn.cursor()

    
        backup_time = input("Enter the backup time (HH:MM): ")

       
        cursor.execute("INSERT INTO BackupSchedule (backup_time) VALUES (?)", (backup_time,))
        conn.commit()

        print("Backup time added successfully.")

        conn.close()
    except sqlite3.Error as e:
        print(f"SQLite error: {e}")
        
        
        
def set_snmp_settings(ip_address):
    try:
        conn = sqlite3.connect('/home/kyle/routers.db')
        cursor = conn.cursor()
        cursor.execute("SELECT username, password, ip FROM routers WHERE ip=?", (ip_address,))
        router_info = cursor.fetchone()
        conn.close()

        if router_info:
            username, password, router_ip = router_info
            print(f"Establishing SSH connection with router at {router_ip}...")
            ssh_client = ConnectHandler(
                device_type='cisco_ios',
                ip=router_ip,
                username=username,
                password=password,
                global_delay_factor=2,
            )
            print(f"SSH connection established with router at {router_ip}")

            commands = [
                "conf t",
                "logging history debugging",
                "snmp-server community SFN RO",
                "snmp-server ifindex persist",
                "snmp-server enable traps snmp linkdown linkup",
                "snmp-server enable traps syslog",
                "snmp-server host 192.168.122.1 version 2c SFN",
                "exit",
                "write mem"  
            ]
            for command in commands:
                execute_command(ssh_client, command)
                time.sleep(1)

            ssh_client.disconnect()
            print(f"SSH connection closed with router at {router_ip}")
        else:
            print(f"No router found with IP {ip_address}.")
    except Exception as e:
        print(f"An error occurred: {e}")


def remove_snmp_settings(ip_address):
    try:
        conn = sqlite3.connect('/home/kyle/routers.db')
        cursor = conn.cursor()
        cursor.execute("SELECT username, password, ip FROM routers WHERE ip=?", (ip_address,))
        router_info = cursor.fetchone()
        conn.close()

        if router_info:
            username, password, router_ip = router_info
            print(f"Establishing SSH connection with router at {router_ip}...")
            ssh_client = ConnectHandler(
                device_type='cisco_ios',
                ip=router_ip,
                username=username,
                password=password,
                global_delay_factor=2,
            )
            print(f"SSH connection established with router at {router_ip}")

            commands = [
                "conf t",
                "no logging history debugging",
                "no snmp-server community SFN RO",
                "no snmp-server ifindex persist",
                "no snmp-server enable traps snmp linkdown linkup",
                "no snmp-server enable traps syslog",
                "no snmp-server host 192.168.122.1 version 2c SFN",
                "exit",
                "write mem" 
            ]
            for command in commands:
                execute_command(ssh_client, command)
                time.sleep(1)

            ssh_client.disconnect()
            print(f"SSH connection closed with router at {router_ip}")
        else:
            print(f"No router found with IP {ip_address}.")
    except Exception as e:
        print(f"An error occurred: {e}")       
        
        
        
def calculate_packet_percentage(router_ip):
    try:
        conn = sqlite3.connect('/home/kyle/routers.db')
        cursor = conn.cursor()
        cursor.execute("SELECT protocol, COUNT(*) FROM netflow_data WHERE Router_ip=? GROUP BY protocol", (router_ip,))
        protocol_counts = cursor.fetchall()
        conn.close()

        if protocol_counts:
            protocols = [row[0] for row in protocol_counts]
            counts = [row[1] for row in protocol_counts]
            total_packets = sum(counts)
            percentages = [(count / total_packets) * 100 for count in counts]

          
            plt.figure(figsize=(8, 8))
            plt.pie(percentages, labels=protocols, autopct='%1.1f%%')
            plt.title(f"Packet Distribution for Router IP: {router_ip}")
            plt.axis('equal')  
            plt.show()
        else:
            print(f"No data found for router with IP {router_ip}.")
    except Exception as e:
        print(f"An error occurred: {e}")        
        
        
def get_current_config(ip_address):
    try:
        conn = sqlite3.connect('/home/kyle/routers.db')
        cursor = conn.cursor()
        cursor.execute("SELECT username, password, ip FROM routers WHERE ip=?", (ip_address,))
        router_info = cursor.fetchone()
        conn.close()

        if router_info:
            username, password, router_ip = router_info
            print(f"Establishing SSH connection with router at {router_ip}...")
            ssh_client = ConnectHandler(
                device_type='cisco_ios',
                ip=router_ip,
                username=username,
                password=password,
                global_delay_factor=2,
            )
            print(f"SSH connection established with router at {router_ip}")

            commands = [
                "sh run",
            ]
            
            current_config = ""
            for command in commands:
                output = execute_command(ssh_client, command)
                current_config += output if output else ""  
                time.sleep(1)

            ssh_client.disconnect()
            print(f"SSH connection closed with router at {router_ip}")
            print(current_config)  
            return current_config  
        else:
            print(f"No router found with IP {ip_address}.")
            return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None
        
def fetch_router_backup_config(router_ip, backup_date):
    try:
        backup_directory = "/home/kyle/Scripting/Home Assignment"
        backup_files = os.listdir(backup_directory)

        backup_filename = f"{router_ip}_{backup_date}.config"
        backup_filepath = None

        for filename in backup_files:
            if filename == backup_filename:
                backup_filepath = os.path.join(backup_directory, filename)
                break

        if backup_filepath:
            with open(backup_filepath, 'r') as backup_file:
                backup_config = backup_file.read() 
                current_config = get_current_config(router_ip) 
                
              
                diff = difflib.unified_diff(current_config.splitlines(), backup_config.splitlines(), lineterm='')
                
              
                return '\n'.join(diff) if diff else "No differences found."
        else:
            print(f"No backup configuration found for router {router_ip} on {backup_date}.")
            return None
    except Exception as e:
        print(f"Error fetching router configuration: {str(e)}")
        return None
        
    

def compare_configs(router_ip, backup_date):
    try:
        current_config = get_current_config(router_ip)
        backup_config = fetch_router_backup_config(router_ip, backup_date)

        if current_config is not None and backup_config is not None:
           
            diff = difflib.unified_diff(current_config.splitlines(), backup_config.splitlines(), lineterm='')
            print(f"Differences between current configuration and backup configuration on {backup_date}:")
            for line in diff:
                print(line)
        else:
            print("Current configuration or backup configuration is not available.")
    except Exception as e:
        print(f"An error occurred: {e}")


def main():
    while True:
        print("\nOptions:")
        print("a. Add Router")
        print("b. Delete Router")
        print("c. List Routers")
        print("d. Set Backup Time")
        print("e. Set NetFlow Settings")
        print("f. Remove NetFlow Settings")
        print("g. Set SNMP Settings")
        print("h. Remove SNMP Settings")
        print("i. Show Router Config")
        print("j. Compare Configurations")
        print("k. Show Packet Distribution")
        print("z. Exit")
        
        option = input("Select an option: ")
        
        if option == 'a':
            add_router()
        elif option == 'b':
            delete_router()
        elif option == 'c':
            list_routers()
        elif option == 'd':
            setup_backup_time()
        elif option == 'e':
            ip_address = input("Enter the IP address of the router: ")
            set_netflow_settings(ip_address)
        elif option == 'f':
            ip_address = input("Enter the IP address of the router: ")
            remove_netflow_settings(ip_address)
        elif option == 'g':
            ip_address = input("Enter the IP address of the router: ")
            set_snmp_settings(ip_address)
        elif option == 'h':
            ip_address = input("Enter the IP address of the router: ")
            remove_snmp_settings(ip_address)    
        elif option == 'i':
            fetch_router_config()
        elif option == 'j':
            router_ip = input("Enter the IP address of the router: ")
            backup_date = input("Enter the backup date (YYYY-MM-DD): ")
            compare_configs(router_ip, backup_date)
        elif option == 'k':
            ip_address = input("Enter the IP address of the router: ")
            calculate_packet_percentage(ip_address)
        elif option == 'z':
            break
        else:
            print("Invalid option. Please select again.")

if __name__ == "__main__":
    main()
