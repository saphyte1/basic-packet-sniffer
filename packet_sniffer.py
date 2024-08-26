import threading
from scapy.all import sniff, wrpcap

# ASCII Art
ascii_art = """
                    _,    _   _    ,_
               .o888P     Y8o8Y     Y888o.
              d88888      88888      88888b
             d888888b_  _d88888b_  _d888888b
             8888888888888888888888888888888
             8888888888888888888888888888888
             YJGS8P"Y888P"Y888P"Y888P"Y8888P
              Y888   '8'   Y8P   '8'   888Y
               '8o          V          o8'
                 `                     `
"""

# Global variable to control sniffing
sniffing = False
captured_packets = []

# Packet handler function to process each packet
def packet_handler(packet):
    if packet.haslayer('IP'):
        ip_layer = packet['IP']
        print(f"New packet: {ip_layer.src} -> {ip_layer.dst} ({packet.summary()})")
        captured_packets.append(packet)

# Function to start sniffing
def start_sniffing():
    global sniffing
    sniffing = True
    print("Starting packet sniffing...")
    sniff(prn=packet_handler, stop_filter=lambda x: not sniffing)

# Function to stop sniffing
def stop_sniffing():
    global sniffing
    sniffing = False
    print("Stopping packet sniffing...")

# Function to save captured packets to a file
def save_packets():
    if captured_packets:
        filename = input("Enter the filename to save packets (e.g., captured_packets.pcap): ")
        wrpcap(filename, captured_packets)
        print(f"Packets saved to {filename}")
    else:
        print("No packets to save.")

# Function to view captured packets
def view_packets():
    if captured_packets:
        for packet in captured_packets:
            print(packet.summary())
    else:
        print("No packets captured yet.")

# Function to display the menu
def display_menu():
    print(ascii_art)
    print("Welcome to the Python Packet Sniffer!")
    print("1. Start Packet Sniffing")
    print("2. Stop Packet Sniffing")
    print("3. View Captured Packets")
    print("4. Save Captured Packets")
    print("5. Exit")

# Main function to handle user input
def main():
    while True:
        display_menu()
        choice = input("Enter your choice: ")

        if choice == "1":
            if not sniffing:
                sniff_thread = threading.Thread(target=start_sniffing)
                sniff_thread.start()
            else:
                print("Sniffing is already running.")
        elif choice == "2":
            if sniffing:
                stop_sniffing()
            else:
                print("Sniffing is not running.")
        elif choice == "3":
            view_packets()
        elif choice == "4":
            save_packets()
        elif choice == "5":
            if sniffing:
                stop_sniffing()
            print("Exiting the program...")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()