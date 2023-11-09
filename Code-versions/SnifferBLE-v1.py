import subprocess
from datetime import datetime
import re
import sys

# ANSI escape codes for colors
COLOR_RESET = "\033[0m"
COLOR_TIMESTAMP = "\033[94m"  # Blue
COLOR_ADDRESS = "\033[92m"    # Green

def main():
    interface = "nRF Sniffer for Bluetooth LE COM6"
    
    # Build the tshark command to capture packets with detailed information command="tshark -i "nRF Sniffer for Bluetooth LE COM6" -T json"
    command = ["tshark", "-i", interface, "-V"]
    
    # Start the tshark process
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    print(f"Capturing on '{interface}'...")

    try:
        ble_mode = False
        for line in iter(process.stdout.readline, ''):
            if "Bluetooth Low Energy Link Layer" in line:
                ble_mode = True
                
            if ble_mode:
                print(parse_ble_packet(line.strip()))
            else:
                print(line.strip())

            if line.strip() == "":
                ble_mode = False

    except KeyboardInterrupt:
        # Terminate the process gracefully when interrupted
        process.terminate()
        print("Capture terminated by user.")

    # Wait for the process to finish
    process.wait()

def parse_ble_packet(packet):
    # Extract relevant information
    frame_number_match = re.search(r"Frame Number: (\d+)", packet)
    arrival_time_match = re.search(r"Arrival Time: (.+?)\s", packet)
    rssi_match = re.search(r"RSSI: (.*?) dBm", packet)
    address_match = re.search(r"Advertising Address: (.*?) \(", packet)
    company_match = re.search(r"Company ID: (.*?)\)", packet)
    data_match = re.search(r"Data: (.+)$", packet, re.MULTILINE)

    # Check if the packet is a BLE device
    if not frame_number_match or not arrival_time_match:
        return packet

    output = []
    output.append(f"Frame: {frame_number_match.group(1)}")
    output.append(f"Time: {arrival_time_match.group(1)}")

    if rssi_match:
        output.append(f"RSSI: {rssi_match.group(1)} dBm")

    if address_match:
        output.append(f"Address: {address_match.group(1)}")

    if company_match and data_match:
        output.append(f"Company: {company_match.group(1)}")
        output.append(f"Data: {data_match.group(1)}")

    # Color the output if it's a BLE device
    if address_match:
        return f"{COLOR_TIMESTAMP}{' | '.join(output)}{COLOR_RESET}"
    else:
        return ' | '.join(output)


if __name__ == "__main__":
    main()