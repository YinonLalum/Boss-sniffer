from scapy3k.all import *
import socket
from subprocess import Popen
import json
from urllib.request import urlopen
from ipaddress import ip_address
from threading import Thread
from re import findall

GET_COUNTRY_ADDRESS = "http://ip-api.com/json/"
SERVER_IP = "127.0.0.1"
NUMBER_OF_SNIFFING_ROUNDS = 1
SERVER_PORT = 8814
SELF_IP = socket.gethostbyname(socket.gethostname())
CMD_COMMAND = "netstat -on"
WEB_SERVER_IP = "54.71.128.194"

SOC = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
SERVER_ADDR = (SERVER_IP, SERVER_PORT)

#the "cache" to make sure the same IP isn't checked twice
countrys = {}


def main():
    while True:
        sniff(count=NUMBER_OF_SNIFFING_ROUNDS, lfilter=fltr, prn=for_packet)


def fltr(packet):
    """
    :param packet: the packet object that i'm checking for
    :return: True if the packet contain an IP and TCP or UDP layer AND the packet is not from a private network
    """
    try:
        return IP in packet and (UDP in packet or TCP in packet) and\
           not ip_address(get_ip(packet)).is_private and\
           get_ip(packet) != WEB_SERVER_IP
    except:
        return False  #if for some reason this check crashes, oddities, it means i don't want this packet


def for_packet(packet):
    """
    Function will print out the ip directions of the packet, for convinience, and will start the proccessing thread
    :param packet: the packet object that i'm checking for
    :return: None
    """
    proccessing_thread = Thread(target=process_packet_and_send, args=(packet,))
    proccessing_thread.start()
    try:
        return packet[IP].src + " ---> "+packet[IP].dst
    except:
        return "An error has accoured"


def is_entering(packet):
    """
    :param packet: the packet object that i'm checking for
    :return: weather or not the packet is entering the pc or not
    """
    if packet[IP].src != SELF_IP:
        return True
    else:
        return False


def get_ip(packet):
    """
    :param packet: the packet object that i'm checking for
    :return: The ip in the packet that does not belong to me, IE the ip that i'm talking with
    """
    if is_entering(packet):
        return packet[IP].src
    else:
        return packet[IP].dst


def get_country(packet):
    """
    :param packet: the packet object that i'm checking for
    :return: the country that the hosts the ip i'm talking with
    """
    #while you probobly can do it without it being global, it's far easier this way
    global countrys
    if get_ip(packet) in countrys.keys():
        return countrys[get_ip(packet)]
    else:
        res = json.loads(urlopen(GET_COUNTRY_ADDRESS + get_ip(packet)).read().decode('utf-8'))
        try:
            countrys[get_ip(packet)] = res["country"]
        except:
            countrys[get_ip(packet)] = "Unknown"
        return countrys[get_ip(packet)]


def get_partner_port(packet):
    """
    :param packet: the packet object that i'm checking for
    :return: the DST port of the packet
    """
    if is_entering(packet):
        return packet.sport
    else:
        return packet.dport


def get_port(packet):
    """
    :param packet: the packet object that i'm checking for
    :return: the internal port of the packet
    """
    if is_entering(packet):
        return packet.dport
    else:
        return packet.sport


def get_program(packet):
    """
    :param packet: the packet object that i'm checking for
    :return: the program that the packet belongs to
    """
    port = str(get_port(packet))
    process = Popen(CMD_COMMAND, shell=True, stdin=subprocess.PIPE, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    output, error = process.communicate()
    output= output.decode()
    results = findall(port+" +[\d\.]+:\d+ +[A-Z]+ +(\d+)", output)
    try:
        process = Popen("tasklist | findstr /c:"+results[0], shell=True, stdin=subprocess.PIPE, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        program = process.communicate()[0].decode()
        results = findall(".+\.exe",program)
        return results[0]
    except:
        pass
    return "Unknown"
#there are 2 cases in which it will be unknown,
#one is when the src port of the packet is not found amongst the list of netstat
#two is for oddities


def process_packet_and_send(packet):
    proccessed = {"ip": get_ip(packet),
                  "country": get_country(packet),
                  "entering": is_entering(packet),
                  "port": get_partner_port(packet),
                  "size": packet[IP].len,  #the len of the ip layer is the len of the entire packet
                  "program": get_program(packet)}

    message = json.dumps((SELF_IP, [proccessed]))
    SOC.sendto(message.encode(), SERVER_ADDR)



if __name__ == "__main__":
    main()
