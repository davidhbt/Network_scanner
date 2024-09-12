import scapy.all as scapy
import pyfiglet


def scan(ip):
    #banner
    print('*' * 50)
    print(pyfiglet.figlet_format("network scanner")) 
    print('made by https://github.com/davidhbt, www.linkedin.com/in/david-habte-a7043a263')
    print('*' * 50)
    enter = input("press enter to continue the scan: ")
    print("scanning....")
    print('\n')
    
    #destnation
    arp_request = scapy.ARP(pdst=ip)
    #asking on public broadcast mac
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    
    #combining the req and broadcast ans
    arp_request_broadcast = broadcast / arp_request
    
    #sending the arp requests
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    results = []

    for element in answered_list:
        result = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        results.append(result)
    
    return results
# displaying results
def display_results(results):
    print("IP Address\t\tMAC Address")
    print("-----------------------------------------")
    for result in results:
        print(result["ip"] + "\t\t" + result["mac"])
        
#defualt getway
target_ip = "192.168.1.1/24"
#starting the sccan
scan_results = scan(target_ip)


display_results(scan_results)
