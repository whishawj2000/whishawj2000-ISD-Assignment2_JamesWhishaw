import socket
import pandas as pd
import matplotlib.pyplot as plt
import csv
import os

# Capture Packets Function
def capture_packets(packet_count=10, output_file='packet_log.csv'):
    sock = None # Initialize sock to None
    captured_data = [] # Initialize captured_data
    try:
        # Create socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        sock.bind(("0.0.0.0", 0)) # Bind
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1) # Set option

        # Promiscuous mode setup (Windows)
        try:
            if os.name == 'nt': # Check if OS is Windows
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        except (AttributeError, OSError): # Catch potential errors
             if os.name == 'nt':
                  # Warn if promiscuous mode fails on Windows
                  print("Warning: Could not enable promiscuous mode.")

        print(f"Capturing {packet_count} packets...")

        # Capture loop
        for _ in range(packet_count):
            try: # Added try/except around individual packet processing
                packet = sock.recvfrom(65565) # Receive packet
                packet_data = packet[0]

                # Check minimum IPv4 header length
                if len(packet_data) >= 20:
                     try:
                         # --- Refactored IP Extraction ---
                         # Use standard socket function for conversion
                         source_ip = socket.inet_ntoa(packet_data[12:16])
                         destination_ip = socket.inet_ntoa(packet_data[16:20])
                         captured_data.append([source_ip, destination_ip])
                         # ----------------------------------
                     except OSError:
                         # Handle potential errors during IP conversion
                         print("\nWarning: Skipping packet, IP parsing error.")

            except socket.error as e:
                 # Handle potential errors during socket.recvfrom
                 print(f"\nSocket error during packet receive: {e}")


        # Check if any valid data was actually captured
        if captured_data:
            print(f"\nPacket capture completed. Saving {len(captured_data)} packets...")
            try:
                # Save to CSV
                with open(output_file, mode='w', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow(['Source IP', 'Destination IP']) # Header
                    writer.writerows(captured_data) # Data
                print(f"Data saved to {output_file}.") # Confirmation
            except IOError as e:
                # Handle file writing errors
                print(f"Error saving data: {e}")
        else:
             # Feedback if nothing was captured
            print("\nPacket capture completed. No valid packets captured.")

    except PermissionError:
        # Clearer permission error message
        print("Permission denied: Please run the script as Administrator.")
    except KeyboardInterrupt: # Added handler for Ctrl+C during capture
         print("\nCapture interrupted by user.")
    except socket.error as e: # Catch errors during initial socket setup
         print(f"Socket setup error: {e}")
    except Exception as e: # Catch other unexpected errors during setup
         print(f"An unexpected error occurred: {e}")

    finally:
        if sock: # Check if socket was successfully created
            try:
                 # Attempt to disable promiscuous mode on Windows
                 if os.name == 'nt':
                     sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except (AttributeError, OSError):
                 # Ignore errors if disabling fails
                 pass
            try:
                 # Ensure the socket is closed
                 sock.close()
            except socket.error as e:
                 # Report errors during socket closing
                 print(f"Error closing socket: {e}")

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
