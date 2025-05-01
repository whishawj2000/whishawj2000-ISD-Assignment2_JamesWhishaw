import socket
import pandas as pd
import matplotlib.pyplot as plt
import csv
import os

# Capture Packets Function
def capture_packets(packet_count=10, output_file='packet_log.csv'):
    sock = None
    captured_data = []
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        sock.bind(("0.0.0.0", 0))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        try:
            if os.name == 'nt':
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        except (AttributeError, OSError):
             if os.name == 'nt':
                  print("Warning: Could not enable promiscuous mode.")

        print(f"Capturing {packet_count} packets...")

        for _ in range(packet_count):
            try:
                packet = sock.recvfrom(65565)
                packet_data = packet[0]

                if len(packet_data) >= 20:
                     try:
                         source_ip = socket.inet_ntoa(packet_data[12:16])
                         destination_ip = socket.inet_ntoa(packet_data[16:20])
                         captured_data.append([source_ip, destination_ip])
                     except OSError:
                         print("\nWarning: Skipping packet, IP parsing error.")
            except socket.error as e:
                 print(f"\nSocket error during packet receive: {e}")

        if captured_data:
            print(f"\nPacket capture completed. Saving {len(captured_data)} packets...")
            try:
                with open(output_file, mode='w', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow(['Source IP', 'Destination IP'])
                    writer.writerows(captured_data)
                print(f"Data saved to {output_file}.")
            except IOError as e:
                print(f"Error saving data: {e}")
        else:
            print("\nPacket capture completed. No valid packets captured.")

    except PermissionError:
        print("Permission denied: Please run the script as Administrator.")
    except KeyboardInterrupt:
         print("\nCapture interrupted by user.")
    except socket.error as e:
         print(f"Socket setup error: {e}")
    except Exception as e:
         print(f"An unexpected error occurred: {e}")

    finally:
        if sock:
            try:
                 if os.name == 'nt':
                     sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except (AttributeError, OSError):
                 pass
            try:
                 sock.close()
            except socket.error as e:
                 print(f"Error closing socket: {e}")


# Display Packet Data (Improved)
def display_data(file_path='packet_log.csv'):
    # Check file existence first
    if not os.path.exists(file_path):
        print("No packet data found. Please capture packets first.")
        return

    try: # Add try/except around pandas operations
        # Read the CSV data
        data = pd.read_csv(file_path)

        # --- Added Check for Empty DataFrame ---
        # Checks if the file was read but contained no data rows
        if data.empty:
             print("Packet data file is empty.")
        # ------------------------------------
        else:
             # Print data if not empty
             print("\n--- Packet Data ---")
             print(data)
    except pd.errors.EmptyDataError:
        # Specifically catch error if CSV file is completely empty (no columns/header)
        print(f"Error: The file '{file_path}' is empty or improperly formatted.")
    except Exception as e:
        # Catch other potential errors during file read or display
        print(f"Error reading or displaying data: {e}")


# Visualize Packet Data (Improved)
def visualize_data(file_path='packet_log.csv'):
    # Check file existence first
    if not os.path.exists(file_path):
        print("No packet data found. Please capture packets first.")
        return

    try: # Add try/except around pandas and plotting operations
        # Read the CSV data
        data = pd.read_csv(file_path)

        # --- Added Check for Empty DataFrame ---
        if data.empty:
             print("Packet data file is empty, cannot visualize.")
             return # Stop if no data

        # --- Added Check for Required Column ---
        # Ensure the column we need for visualisation actually exists
        if 'Source IP' not in data.columns:
             print("Error: 'Source IP' column not found in the data file.")
             return # Stop if column missing
        # ------------------------------------

        # Calculate value counts for the 'Source IP'
        ip_counts = data['Source IP'].value_counts()

        # --- Added Check for Empty Results ---
        # Check if counting resulted in any data (e.g., column exists but all values are null)
        if ip_counts.empty:
             print("No Source IP data available to visualize.")
             return # Stop if no counts
        # -----------------------------------

        # Proceed with plotting if data is valid
        plt.figure(figsize=(10, 6))
        ip_counts.plot(kind='bar')
        plt.title('Packet Source IP Distribution')
        plt.xlabel('Source IP Address')
        plt.ylabel('Number of Packets')
        # Consider adding plt.tight_layout() for better spacing if labels overlap
        plt.show() # Display the plot window
    except pd.errors.EmptyDataError:
         print(f"Error: The file '{file_path}' is empty or improperly formatted.")
    except KeyError:
         # This is another way the 'Source IP' column absence might manifest
         print("Error: 'Source IP' column key not found during processing.")
    except Exception as e:
         # Catch other potential errors (plotting issues, etc.)
         print(f"Error reading or visualizing data: {e}")


# Command Line Interface (Improved Input Handling)
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
                # Get input for packet count
                packet_count_str = input("Enter number of packets to capture: ")
                packet_count = int(packet_count_str) # Convert to integer
                # Add basic validation for the count
                if packet_count <= 0:
                    print("Invalid input: Please enter a positive number of packets.")
                else:
                    capture_packets(packet_count) # Call capture function
            except ValueError:
                # Handle non-numeric input
                print("Invalid input. Please enter a whole number.")
            # Consider adding other exception handling if needed

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
