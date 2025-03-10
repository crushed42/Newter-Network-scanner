import scapy.all as scapy
import argparse
import os

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def ascii_art():
    return """
 ███╗   ██╗███████╗██╗    ██╗████████╗███████╗██████╗ 
 ████╗  ██║██╔════╝██║    ██║╚══██╔══╝██╔════╝██╔══██╗
 ██╔██╗ ██║█████╗  ██║ █╗ ██║   ██║   █████╗  ██████╔╝
 ██║╚██╗██║██╔══╝  ██║███╗██║   ██║   ██╔══╝  ██╔══██╗
 ██║ ╚████║███████╗╚███╔███╔╝   ██║   ███████╗██║  ██║
 ╚═╝  ╚═══╝╚══════╝ ╚══╝╚══╝    ╚═╝   ╚══════╝╚═╝  ╚═╝
    """

def scan_network(ip_range):
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    
    devices = []
    for element in answered_list:
        devices.append({"IP": element[1].psrc, "MAC": element[1].hwsrc})
    
    return devices

def display_results(devices):
    print("IP Address\t\tMAC Address")
    print("--------------------------------------------------")
    for device in devices:
        print(f"{device['IP']}\t{device['MAC']}")

def main():
    clear()
    print(ascii_art())
    parser = argparse.ArgumentParser(description="Network Scanner")
    parser.add_argument("-t", "--target", dest="target", required=True, help="Target IP range (e.g., 192.168.1.1/24)")
    args = parser.parse_args()
    
    print("\n[ SCANNING NETWORK... ]\n")
    devices = scan_network(args.target)
    display_results(devices)
    print("\n[ SCAN COMPLETE! ]\n")

if __name__ == "__main__":
    main()
