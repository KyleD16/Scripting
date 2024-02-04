from scapy.all import *
import socket
import sqlite3
import paramiko
import time

# Function to retrieve router credentials from the database
def get_router_credentials(router_ip):
    try:
        conn = sqlite3.connect('/home/kyle/routers.db')
        cursor = conn.cursor()
        cursor.execute("SELECT username, password FROM routers WHERE ip=?", (router_ip,))
        router_info = cursor.fetchone()
        conn.close()
        return router_info
    except sqlite3.Error as e:
        print(f"SQLite error: {e}")
        return None

# Function to connect to the router using Paramiko
def connect_to_router(ip, username, password):
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh_client.connect(hostname=ip, username=username, password=password)
        print(f"Successfully connected to router at {ip}!")
        return ssh_client
    except paramiko.AuthenticationException:
        print(f"Failed to authenticate to router at {ip}. Invalid credentials.")
    except paramiko.SSHException as e:
        print(f"Error occurred while connecting to router at {ip}: {e}")
    return None

# Function to start packet sniffing
def start_sniffing(interface, db_connection):
    print("Starting packet sniffing...")
    try:
        sniff(filter="udp and port 2055", iface=interface, prn=lambda pkt: process_netflow_packet(pkt, db_connection))
    except Exception as e:
        print(f"Error occurred during packet sniffing: {e}")

# Sniffing function to process NetFlow packets
def process_netflow_packet(packet, db_connection):
    try:
        # Check if packet is NetFlow version 5
        if packet.haslayer(UDP) and packet[UDP].dport == 2055:
            # Get current date and time
            current_date = time.strftime("%Y-%m-%d")
            current_time = time.strftime("%H:%M:%S")

            # Extract packet information
            source_ip = packet[IP].src
            dest_ip = packet[IP].dst
            source_port = packet[UDP].sport
            dest_port = packet[UDP].dport
            protocol = packet[IP].proto
            num_packets = len(packet)
            Router_ip = packet[IP].src

            # Print extracted information
            print("Packet Details:")
            print(f"Date: {current_date}")
            print(f"Time: {current_time}")
            print(f"Router IP: {Router_ip}")
            print(f"Number of Packets: {num_packets}")
            print(f"Source IP: {source_ip}, Source Port: {source_port}")
            print(f"Destination IP: {dest_ip}, Destination Port: {dest_port}")
            print(f"Protocol: {protocol}")

            # Store packet information in the database
            cursor = db_connection.cursor()
            cursor.execute("INSERT INTO netflow_data (Date, Time, Router_ip, source_ip, dest_ip, source_port, dest_port, protocol, num_packets) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                           (current_date, current_time, Router_ip, source_ip, dest_ip, source_port, dest_port, protocol, num_packets))
            db_connection.commit()
            print("Packet information inserted into the database.")
    except Exception as e:
        print(f"Error occurred while processing NetFlow packet: {e}")

# Create a socket listening on port 2055
def create_netflow_socket():
    try:
        netflow_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        netflow_socket.bind(('127.0.0.1', 2055))
        return netflow_socket
    except Exception as e:
        print(f"Error occurred while creating NetFlow socket: {e}")
        return None

# Main function
def main():
    try:
        # Prompt user to enter the IP address of the router
        router_ip = input("Enter the IP address of the router you want to connect to: ")

        # Get router credentials from the database
        credentials = get_router_credentials(router_ip)
        if credentials:
            username, password = credentials

            # Connect to the router using Paramiko
            ssh_client = connect_to_router(router_ip, username, password)
            if ssh_client:
                # Create database connection
                db_connection = sqlite3.connect('/home/kyle/routers.db')

                # Start packet sniffing if the connection to the router is successful
                start_sniffing("virbr0", db_connection)
            else:
                print("Failed to connect to the router. Exiting...")
        else:
            print(f"No credentials found for router with IP {router_ip}. Exiting...")
    except Exception as e:
        print(f"An error occurred: {e}")

# Execute the main function if the script is run directly
if __name__ == "__main__":
    main()
