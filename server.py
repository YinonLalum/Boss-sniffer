import socket
import json
from time import strftime

SERVER_PORT = 8814
AMOUNT_OF_MOST_COMMON = 5

WEB_SERVER_PORT = 8808
WEB_SERVER_IP = "54.71.128.194"

AGENTS_IN_KEYS = '%%AGENTS_IN_KEYS%%'
AGENTS_IN_VALUES = '%%AGENTS_IN_VALUES%%'

AGENTS_OUT_KEYS = '%%AGENTS_OUT_KEYS%%'
AGENTS_OUT_VALUES = '%%AGENTS_OUT_VALUES%%'

COUNTRIES_KEYS = '%%COUNTRIES_KEYS%%'
COUNTRIES_VALUES = '%%COUNTRIES_VALUES%%'

IPS_KEYS = '%%IPS_KEYS%%'
IPS_VALUES = '%%IPS_VALUES%%'

APPS_KEYS = '%%APPS_KEYS%%'
APPS_VALUES = '%%APPS_VALUES%%'

PORTS_KEYS = '%%PORTS_KEYS%%'
PORTS_VALUES = '%%PORTS_VALUES%%'

ALERTS = '%%ALERTS%%'

TIMESTAMP = '%%TIMESTAMP%%'

USER_CODE = '400#USER=yinon.lalum'
OK_CODE = '405'
DATA_SEND_START = '700#SIZE=%d,HTML='
SUCCESSFUL_SAVE_CODE = '705'
BYE_CODE = '900#BYE'

with open("template.html", 'r') as f:
    template = f.read()

with open("settings.dat") as f:
    exec(f.read(), globals(), locals())
WORKERS = locals()["WORKERS"]  #to remove the little red underline
BLACKLIST = locals()["BLACKLIST"]
#since i'm passing exec the locals dictionary, the variables
#that it creates there are passed to the local variables, as such they can be used anywhere in the program


def main():
    stats = {'common ips': [], 'common countries': [], 'common programs': [], 'common ports': [], 'incoming traffic': {}, 'outgoing traffic': {}, 'blacklist': []}
    packets = {}
    soc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    soc.bind(('', SERVER_PORT))
    while True:
        print("listening")
        client_msg, client_addr = soc.recvfrom(8192)  #8192 is the first square of 2 that gets all the data in one go
        msg = json.loads(client_msg)
        print("\nrecieved message from " + str(client_addr) + " AKA: "+msg[0]+"\n")
        packets = add_packets(msg, packets)  #adding a packet to the overall list
        #packets format: {user ip: [{ip: "the ip with whom the agent's computer is speaking", country: "the country of that ip",
        #entering: "whether or not it's entering", port: "the external port",size: "total size of the packet", program: "the program that uses the packet"}]
        stats = add_stats(stats, packets)  #rconstructing the stats
        html_report = create_report(stats)  #creating a report with the new stats
        with open("template/html/report.html", 'w') as f: #not really necessary but conevinient
            f.write(html_report)
        send_report(html_report)


def send_report(html_report):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((WEB_SERVER_IP, WEB_SERVER_PORT))
    html_size = len(html_report)

    s.sendall(USER_CODE.encode())
    try:
        print_val = s.recv(1024).decode() #reciving the message from server
        if OK_CODE in print_val:  #making sure the ok code is in the recived message
            s.sendall(((DATA_SEND_START % html_size)+html_report).encode())
        else:
            raise Exception(print_val + "while waiting for ok return code")  #raising the type of error

        print_val = s.recv(1024).decode() #reciving the message from server
        if SUCCESSFUL_SAVE_CODE in print_val:
            s.sendall(BYE_CODE.encode())
        else:
            raise Exception(print_val + "while waiting for save code!")

        print_val = s.recv(1024).decode() #reciving the message from server
       #no point in checking code for this, since at this point it definetly got uploaded succesfully

    except Exception as e:
        s.close()
        print("an error accoured while attempting to send report")
        print("error is: "+str(e))
        return #to stop the function


def create_report(stats):
    #timestamp
    t = template.replace(TIMESTAMP, strftime("%d.%m.%Y, %H:%M"))  #first time also to get the template out of the variable

    #incoming traffic
    l = []
    t = t.replace(AGENTS_IN_KEYS, str(list(stats['incoming traffic'].keys())))
    for key in stats['incoming traffic'].keys():
        l.append(stats['incoming traffic'][key])
    t = t.replace(AGENTS_IN_VALUES, str(l))

    #outgoing traffic
    l = []
    t = t.replace(AGENTS_OUT_KEYS, str(list(stats['outgoing traffic'].keys())))
    for key in stats['outgoing traffic'].keys():
        l.append(stats['outgoing traffic'][key])
    t = t.replace(AGENTS_OUT_VALUES, str(l))

    #countries
    #this lambda expression returns a list of the first value of the tuples
    #so for a list of tuples such as [('a',2),('b',3)] it will return ['a','b']
    t = t.replace(COUNTRIES_KEYS, str([i[0] for i in stats['common countries']]))
    t = t.replace(COUNTRIES_VALUES, str([i[1] for i in stats['common countries']]))

    #ips
    t = t.replace(IPS_KEYS, str([i[0] for i in stats['common ips']]))
    t = t.replace(IPS_VALUES, str([i[1] for i in stats['common ips']]))

    #apps
    t = t.replace(APPS_KEYS, str([i[0] for i in stats['common programs']]))
    t = t.replace(APPS_VALUES, str([i[1] for i in stats['common programs']]))

    #ports
    t = t.replace(PORTS_KEYS, str([i[0] for i in stats['common ports']]))
    t = t.replace(PORTS_VALUES, str([i[1] for i in stats['common ports']]))

    #blacklist
    t = t.replace(ALERTS, str(stats['blacklist']))

    return t


def get_alerts(alerts, packets):
    #a whole lot of checks
    #going through: all of the workers, the keys
    for key in WORKERS.keys():
        if WORKERS[key] in packets.keys():  #making sure i got at least one message from this worker
            for packet in packets[WORKERS[key]]:  #check for each packet from this user
                for ip in BLACKLIST:  #go through all the ips in the blacklist from settings.dat
                    if packet['ip'] == ip[0] and (key, WORKERS[key]) not in alerts:  #if the packet's ip is the same as
                        #one of those in blacklist and it's the first time we're adding it
                        alerts.append((key, WORKERS[key]))  #only then append the the ip and name of the violating worker
    return alerts


def add_stats(stats, packets):
    stats['common ips'] = get_most_common(compile_all('ip', packets))
    stats['common countries'] = get_most_common(compile_all('country', packets))
    stats['common programs'] = get_most_common(compile_all('program', packets))
    stats['common ports'] = get_most_common(compile_all('port', packets))
    stats['incoming traffic'] = get_size_for_all_users(stats['incoming traffic'], True, packets)
    stats['outgoing traffic'] = get_size_for_all_users(stats['outgoing traffic'], False, packets)
    stats['blacklist'] = get_alerts(stats['blacklist'], packets)
    return stats


def get_size_for_all_users(traffic_stats, entering, packets):
    for key in WORKERS.keys():
        traffic_stats[key] = compile_size_for(key, entering, packets)
    return traffic_stats


def compile_size_for(user, entering, packets):
    #will return the total size the user used, entering or leaving depending on the passed variable
    answer = 0
    if WORKERS[user] in packets.keys():  #making sure there is at least one message from the user
        for packet in packets[WORKERS[user]]:
            if packet['entering'] == entering:
                    answer += packet['size']
    return answer


def compile_all(key, packets):
    #Function will return a list of all the values of the given key that appears anywhere in the packets list
    #regardless of the ip using them
    answer = []
    for ip in packets.keys():
        for packet in packets[ip]:
            answer.append((packet[key], packet["size"]))
    return answer


def get_most_common(l):
    orders = []
    answer = []
    answer_with_sizes = []
    labels = [i[0] for i in l]  #making a list of all the first parts of the tuple, which is the labels
    for item in labels:
        orders.append((item, labels.count(item)))
    orders = list(set(orders))  #remove any reaccurances of the same value in the list
    orders = sorted(orders, key=lambda tup: tup[1], reverse=True) #sorting it by the second part of the tuple
    for i in range(0, AMOUNT_OF_MOST_COMMON):
        try:
            answer.append(orders[i][0]) #getting the sorted labels list
        except:
            break  #the list is shorted then the amount_of_most_common

    #recunstructing it with the sizes
    for item in answer:
        size = 0
        for i in l:
            if i[0] == item:
                size += i[1]
        answer_with_sizes.append((item, size))

    return answer_with_sizes


def add_packets(msg, packets):
    #this function will add a packet(msg) to the packets list
    #it will add it to the proper worker's ip
    if msg[0] in packets.keys():
        for packet in msg[1]:
            packets[msg[0]].append(packet)
    else:
        packets[msg[0]] = msg[1]
    return packets

if __name__ == "__main__":
    main()
