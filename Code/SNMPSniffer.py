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


def start_sniffing(interface, db_connection):
    print("Starting SNMP trap message sniffing...")
    try:
        # Adjust the filter to capture SNMP trap packets (UDP port 161)
        sniff(filter="udp and port 162", iface=interface, prn=lambda pkt: process_snmp_trap(pkt, db_connection))
    except Exception as e:
        print(f"Error occurred during packet sniffing: {e}")
        
def process_snmp_trap(packet, db_connection):
    try:
        if packet.haslayer(UDP):
            # Check if packet is SNMP trap (UDP port 161)
            if packet[UDP].dport == 162:
                # SNMP trap processing logic
                current_date = time.strftime("%Y-%m-%d")
                current_time = time.strftime("%H:%M:%S")
                Router_ip = packet[IP].src
                
                # Print packet details
                print("Captured Packet Details:")
                print(f"Date: {current_date}")
                print(f"Time: {current_time}")
                print(f"Router IP: {Router_ip}")

                # Print full packet structure for debugging
                print("Full Packet Structure:")
                packet.show()

                # Check if it's a SYSLOG trap
                if 'syslog' in packet:
                    # Extract SYSLOG trap information
                    print("SYSLOG trap detected.")
                    message = packet['syslog'].community.decode('utf-8')

                    # Print message for debugging
                    print(f"Message: {message}")

                    # Store SYSLOG trap information in the database
                    cursor = db_connection.cursor()
                    cursor.execute("INSERT INTO syslog_data (Date, Time, Router_IP, Message) VALUES (?, ?, ?, ?)",
                                   (current_date, current_time, Router_ip, message))
                    db_connection.commit()
                    print("SYSLOG trap information inserted into the database.")

                # Check if it's a LINK UP or LINK DOWN trap
                elif 'IF-MIB' in packet:
                    # Extract LINK UP or LINK DOWN trap information
                    interface_name = packet['IF-MIB'].physAddress
                    state = packet['IF-MIB'].ifAdminStatus

                    # Store LINK UP or LINK DOWN trap information in the database
                    cursor = db_connection.cursor()
                    cursor.execute("INSERT INTO link_trap_data (Date, Time, Router_IP, Interface_Name, State) VALUES (?, ?, ?, ?, ?)",
                                   (current_date, current_time, Router_ip, interface_name, state))
                    db_connection.commit()
                    print("LINK UP or LINK DOWN trap information inserted into the database.")
                    print(f"Interface Name: {interface_name}")
                    print(f"State: {state}")

                else:
                    print("No known trap type detected in the packet.")

    except Exception as e:
        print(f"Error occurred while processing packet: {e}")
        

def main():
    try:
        router_ip = input("Enter the IP address of the router you want to connect to: ")

        credentials = get_router_credentials(router_ip)
        if credentials:
            username, password = credentials
          
            ssh_client = connect_to_router(router_ip, username, password)
            if ssh_client:
                db_connection = sqlite3.connect('/home/kyle/routers.db')

                start_sniffing("virbr0", db_connection)
            else:
                print("Failed to connect to the router. Exiting...")
        else:
            print(f"No credentials found for router with IP {router_ip}. Exiting...")
    except Exception as e:
        print(f"An error occurred: {e}")
        

if __name__ == "__main__":
    main()       
        

