import socket
import pandas as pd
import matplotlib.pyplot as plt
import csv
import os

# Capture Packets Function
def capture_packets(packet_count=10, output_file='packet_log.csv'):
    try:
        # Create a raw socket for IPv4 traffic
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        sock.bind(("0.0.0.0", 0))  # Bind to all interfaces

        # Include IP headers
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        # Enable promiscuous mode for Windows (if applicable)
        try:
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        except AttributeError:
            pass  # For non-Windows systems

        captured_data = []

        print(f"Capturing {packet_count} packets...")

        for _ in range(packet_count):
            packet = sock.recvfrom(65565)
            packet_data = packet[0]

            # Extract source and destination IP addresses from the packet
            source_ip = '.'.join(map(str, packet_data[12:16]))
            destination_ip = '.'.join(map(str, packet_data[16:20]))

            captured_data.append([source_ip, destination_ip])

        # Save captured data to CSV
        with open(output_file, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['Source IP', 'Destination IP'])
            writer.writerows(captured_data)

        print(f"\nPacket capture completed. Data saved to {output_file}.")

        # Disable promiscuous mode after capturing (for Windows)
        try:
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        except AttributeError:
            pass  # For non-Windows systems

        sock.close()
    except PermissionError:
        print("Permission denied: Please run the script as Administrator.")

# Display Packet Data
def display_data(file_path='packet_log.csv'):
    if not os.path.exists(file_path):
        print("No packet data found. Please capture packets first.")
        return
    
    data = pd.read_csv(file_path)
    print("\n--- Packet Data ---")
    print(data)

# Visualize Packet Data
def visualize_data(file_path='packet_log.csv'):
    if not os.path.exists(file_path):
        print("No packet data found. Please capture packets first.")
        return
    
    data = pd.read_csv(file_path)
    ip_counts = data['Source IP'].value_counts()

    plt.figure(figsize=(10, 6))
    ip_counts.plot(kind='bar')
    plt.title('Packet Source IP Distribution')
    plt.xlabel('Source IP Address')
    plt.ylabel('Number of Packets')
    plt.show()

# Command Line Interface
def main():
    while True:
        print("\n--- Network Monitoring Tool ---")
        print("1. Capture Packets")
        print("2. Display Captured Data")
        print("3. Visualize Packet Distribution")
        print("4. Exit")
        
        choice = input("Enter your choice: ")
        
        if choice == '1':
            try:
                packet_count = int(input("Enter number of packets to capture: "))
                capture_packets(packet_count)
            except ValueError:
                print("Invalid input. Please enter a number.")
        elif choice == '2':
            display_data()
        elif choice == '3':
            visualize_data()
        elif choice == '4':
            print("Exiting the tool. Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
