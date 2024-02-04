import sqlite3
from netmiko import ConnectHandler
import datetime
import time
from github import Github

def get_router_credentials():
    try:
        conn = sqlite3.connect('/home/kyle/routers.db')
        cursor = conn.cursor()
        
        # Select username, password, and IP from routers table
        cursor.execute("SELECT ip, username, password FROM routers")
        router_credentials = cursor.fetchall()
        
        # Select backup time from BackupSchedule table
        cursor.execute("SELECT backup_time FROM BackupSchedule")
        backup_times = cursor.fetchall()
        
        # Combine the results
        routers = [(ip, username, password, backup_time[0]) 
                   for ip, username, password in router_credentials 
                   for backup_time in backup_times]
        
        conn.close()
        return routers
    except sqlite3.Error as e:
        print(f"SQLite error: {e}")
        return []

def perform_backup(ip, username, password):
    try:
        # Create a dictionary with device information for netmiko
        device = {
            'device_type': 'cisco_ios',
            'ip': ip,
            'username': username,
            'password': password,
        }

        # Connect to the device
        with ConnectHandler(**device) as net_connect:
            # Send command to retrieve running configuration
            running_config = net_connect.send_command("show running-config")

            # Define the path to store the configuration file
            config_filename = f"{ip}.config"
            local_filepath = f"./{config_filename}"

            # Write running configuration to a local file
            with open(local_filepath, "w") as f:
                f.write(running_config)

            print(f"Backup completed for {ip}. Configuration saved to {local_filepath}")

            # Upload configuration to GitHub
            upload_to_github(local_filepath, ip)

    except Exception as e:
        print(f"Error performing backup for {ip}: {e}")

def upload_to_github(local_filepath, router_ip):
    try:
        # GitHub authentication
        github_token = "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"
        g = Github(github_token)
        
        # Specify repository details
        repo_owner = "KyleD16"
        repo_name = "Scripting"
        
        # Get repository
        repo = g.get_user(repo_owner).get_repo(repo_name)

        # Read file content
        with open(local_filepath, "r") as file:
            file_content = file.read()

        # Upload file to repository
        repo.create_file(f"router_configs/{router_ip}_config.txt", f"Backup for {router_ip}", file_content, branch="main")

        print(f"Configuration for {router_ip} uploaded to GitHub.")
    except Exception as e:
        print(f"Error uploading configuration for {router_ip} to GitHub: {e}")

def main():
    try:
        while True:
            # Show current time
            current_time = datetime.datetime.now().time().strftime('%H:%M')

            # Retrieve routers data from the database
            routers = get_router_credentials()

            for router in routers:
                ip, username, password, backup_time = router
                if current_time == backup_time:
                    perform_backup(ip, username, password)

            # Sleep for 60 seconds
            time.sleep(60)

    except sqlite3.Error as e:
        print(f"SQLite error: {e}")

if __name__ == "__main__":
    main()
