# BLE Advertising Process

# In BLE, devices can broadcast packets to advertise their presence, service capabilities, or other data. These packets are not directed to a specific device but are intended to be read by any scanning device in the vicinity. This is called advertising.

# BLE advertising packets have different PDU (Protocol Data Unit) types, which define the purpose and structure of the packet. Common types include:

#     ADV_IND: Connectable undirected advertising (PDU type 0x00)
#     ADV_DIRECT_IND: Connectable directed advertising (PDU type 0x01)
#     ADV_NONCONN_IND: Non-connectable undirected advertising (PDU type 0x02)
#     ADV_SCAN_IND: Scannable undirected advertising (PDU type 0x06)

# Tshark Display Filters

# Tshark uses display filters to determine which packets to show or hide. These filters are based on the fields of the packet and can be combined using logical operators. For instance:

#     == is used for comparison (equality).
#     ! negates a condition.
#     || stands for logical OR.

# The Filter Construction

# When creating the filter !(btle.advertising_header.pdu_type == 0x00), we're asking tshark to exclude packets (! negates the condition) where the BLE advertising header's PDU type is equal to 0x00 (ADV_IND packets). However, we also want to exclude other types of advertising packets (e.g., ADV_NONCONN_IND, ADV_SCAN_IND).

# To do this, we extend the filter with additional PDU types using logical OR ||. The filter "!(btle.advertising_header.pdu_type == 0x00 || btle.advertising_header.pdu_type == 0x02 || btle.advertising_header.pdu_type == 0x04 || btle.advertising_header.pdu_type == 0x06)" now excludes all the common advertising PDU types.

#   THIS CODE IS HOW OUR IDEA CAME 👻🐧🌐🍹

import subprocess


def capture_packets(interface):
    # Build the tshark command to capture packets, excluding advertising PDUs
    # Build the tshark command to capture packets filtered to BLE only= tshark -i "nRF Sniffer for Bluetooth LE COM6" -Y "!(btle.advertising_header.pdu_type == 0x00 || btle.advertising_header.pdu_type == 0x02 || btle.advertising_header.pdu_type == 0x04 || btle.advertising_header.pdu_type == 0x06)"
    # command for json format = tshark -i "nRF Sniffer for Bluetooth LE COM6" -T json -Y "!(btle.advertising_header.pdu_type == 0x00 || btle.advertising_header.pdu_type == 0x02 || btle.advertising_header.pdu_type == 0x04 || btle.advertising_header.pdu_type == 0x06)"
    command = [
        "tshark",
        "-i", interface,
        "-T", "json",
        "-Y", "!(btle.advertising_header.pdu_type == 0x00 || btle.advertising_header.pdu_type == 0x02 || btle.advertising_header.pdu_type == 0x04 || btle.advertising_header.pdu_type == 0x06)"
    ]

    # Start a new process with the specified command and capture its output
    process = subprocess.Popen(command, stdout=subprocess.PIPE, text=True)
    
    
    print(f"🦈Capturing BLE on '{interface}'...")
    try:
        # Iterate through the lines of the captured output (captured packets)
        for line in process.stdout:
            # Print each line (captured packet) to the console without adding extra newlines
            print(line, end='')

    except KeyboardInterrupt:
        # Handle a KeyboardInterrupt (Ctrl+C) to terminate the process
        print("\n🐧Capturing stopped.")
        process.terminate()

if __name__ == "__main__":
    # Define the interface from which to capture packets, this willl be different, check in your wireshark interfaces
    interface = "nRF Sniffer for Bluetooth LE COM6"


    capture_packets(interface)
