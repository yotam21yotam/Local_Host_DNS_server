import json
import socket, glob

DNS_SERVER_IP = '127.0.0.1'
DNS_SERVER_PORT = 53
DEFAULT_BUFFER_SIZE = 1024

def load_zones():
    jsonzone = {}
    zonefiles = glob.glob('zones/*.zone')
    for zone in zonefiles:
        print(zone)
        with open(zone) as zonedata:
            data = json.load(zonedata)
            zonename = data["$origin"]
            jsonzone[zonename] = data
    return jsonzone

def getflags(flags):
    byte1 = bytes(flags[:1])
    byte2 = bytes(flags[1:2])
    rflags = ''
    qr = '1'

    opcode = ''
    for bit in range(1,5):
        opcode += str(ord(byte1)&(1<<bit))

    AA = '1'
    TC = '0'
    RD = '0'
    RA = '0'
    Z = '000'
    RCODE = '0000'

    return int (qr+opcode+AA+TC+RD, 2).to_bytes(1, byteorder='big')+int(RA+Z+RCODE).to_bytes(1, byteorder='big')

def getquestiondomain(data):
    state = 0
    expectedlength = 0
    domainstring = ''
    domainparts = []
    x = 0
    y = 0
    for byte in data:
        if state == 1:
            if byte != 0:

                domainstring += chr(byte)
            x += 1
            if x == expectedlength:
                domainparts.append(domainstring)
                domainstring = ''
                state = 0
                x = 0
            if byte == 0:
                domainparts.append(domainstring)
                break
        else:
            state = 1
            expectedlength = byte
        y+=1

    questiontype = data[y:y+2]
    return (domainparts, questiontype)

def getzone(domain):
    zonedata = load_zones()

    zone_name = '.'.join(domain)

    return zonedata[zone_name]

def getrecs(data):
    domain, questiontype = getquestiondomain(data)
    qt = ''
    if questiontype == b'\x00\x01':
        qt = 'a'

    zone = getzone(domain)
    print(zone+" "+ qt + " " +domain)
    return (zone[qt],qt,domain)

def buildresponse(data):

    """
    build DNS response from the request
    :param data:
    :return:
    """
    # data is strings of bytes
    # Transection ID
    transactionID = data[:2] # take the first 2 bytes


    # Get the Flags
    flags = getflags(data[2:4])

    # Question count
    QDCOUNT = b'\x00\x01'

    # Answer Count
    ANCOUNT = len(getrecs(data[12:])[0]).to_bytes(2, byteorder='big')
    #nameserver count
    NSCOUNT = (0).to_bytes(2, byteorder='big')
    #additional count
    ARCOUNT = (0).to_bytes(2, byteorder='big')

    dnsheaader = transactionID+flags+QDCOUNT+ANCOUNT+NSCOUNT+ARCOUNT

    dnsbody = b''
    records,rectype,domainname = getrecs(data[12:])
    dnsquestion = buildquestion(domainname,rectype)

    for record in records:
        dnsbody += rectobytes(domainname, rectype, record['ttl'],record['value'])
    return dnsheaader + dnsquestion + dnsbody

def rectobytes(domainname, rectype, recttl, recvalue):
    rbytes = b'\xc0\x0c'
    if rectype == 'a':
        rbytes = rbytes + bytes([0]) + bytes([1])

    rbytes = rbytes + bytes([0]) + bytes([1])
    rbytes += int(recttl).to_bytes(4, byteorder='big')
    if rectype == 'a':
        rbytes = rbytes + bytes([0]) + bytes([4])
        for part in recvalue:
            rbytes += bytes([int(part)])
    return rbytes

def buildquestion(domainname,rectype):
    qbytes = b''
    for part in domainname:
        length = len(part)
        qbytes += bytes([length])

        for char in part:
            qbytes += ord(char).to_bytes(1, byteorder='big')
    if rectype == 'a':
        qbytes += (1).to_bytes(2, byteorder='big')
    qbytes += (1).to_bytes(2, byteorder='big')
    return qbytes

def dns_handler(data,addr,server_socket):

    # in python the hex decimal base is represented by "\x00" - meaning that its bytes before converted to ASCII charaters
    data_str = str(data)
    addr_str = str(addr)
    print(data_str, addr_str)

    host_name = 'yahoo.com'
    host_ip = socket.gethostbyname(host_name)
    server_socket.connect(('212.143.70.40', 80))

    # if 'google' in data_str:
    #     #r = buildresponse(data)
    #     host_name = 'yahoo.com'
    #     host_ip = socket.gethostbyname(host_name)
    #     server_socket.send(host_ip, addr)

def dns_udp_server(ip, port):
    # AF_INET - means that we use ipv4 and not ipv6
    # socket.SOCK_DGRAM - means that we use UDP and not TCP

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((ip, port)) # when binding socket we need to provide one tuple containing ip and port
    print("server started succesfully, Waiting for data")
    while True:
        try:
            data, addr = server_socket.recvfrom(DEFAULT_BUFFER_SIZE)
            dns_handler(data, addr, server_socket)
        except IndexError:
            break

def main():
    print("Sarting DNS server: ")
    dns_udp_server(DNS_SERVER_IP,DNS_SERVER_PORT)

if __name__ == '__main__':
    main()