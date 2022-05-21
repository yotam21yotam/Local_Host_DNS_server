import json
import socket, glob,webbrowser,socketserver

DNS_SERVER_IP = '127.0.0.1'
DNS_SERVER_PORT = 53
DEFAULT_BUFFER_SIZE = 1024

# def buildquestion(domainname,rectype):
#     qbytes = b''
#     for part in domainname:
#         length = len(part)
#         qbytes += bytes([length])
#
#         for char in part:
#             qbytes += ord(char).to_bytes(1, byteorder='big')
#     if rectype == 'a':
#         qbytes += (0).to_bytes(2, byteorder='big')
#         qbytes += (1).to_bytes(1, byteorder='big')
#     qbytes += (0).to_bytes(1, byteorder='big')
#     qbytes += (1).to_bytes(1, byteorder='big')
#     return qbytes

def buildquestion(domainname,rectype):
    # rectype = request type, A, AAA, CNAME, A its regular DNS which weare targeting
    """
    take domain name "www.yahoo"
    return DNS response
    transaction id, flags, etc
    """
    qbytes = b''
    # qbytes = b'\x03'+b'\x77'+b'\x77'+b'\x77'+b'\x05'+b'y'+b'a'+b'h'+b'o'+b'o'+b'\x03'+b'c'+b'o'+b'm'+b'\x00'
    # qbytes because there was spaces in whireshark
    for part in domainname:
        length = len(part)
        qbytes += bytes([length])

        for char in part:
            qbytes += ord(char).to_bytes(1, byteorder='big')

    if rectype == 'a': # if its A then its a DNS first request, type A - 0100
        qbytes += (0).to_bytes(1, byteorder='big')
        qbytes += (1).to_bytes(1, byteorder='big')
    qbytes += (0).to_bytes(1, byteorder='big')
    qbytes += (1).to_bytes(1, byteorder='big')
    return qbytes

def to_hex(hostname):

    build_response1 = b'g'
    build_response1 += b'\xb9'
    # build_response = '\x67\xb9'
    build_response2 = b'\x01'+b'\x00'+b'\x00'+b'\x01'+b'\x00'+b'\x00'+b'\x00'+b'\x00'+b'\x00'+b'\x00'
    # build_response += '\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
    build_response3 = b'\x00'+b'\x01'
    #build_response3 = 0x00+0x01+0x00+0x01
    build_response = build_response1 + build_response2 + buildquestion(hostname, 'a')
    # build_response = build_response1.to_bytes(2, byteorder='big') + build_response2.to_bytes(10, byteorder='big') + buildquestion(hostname, 'a')
    # build_response += hostname.encode('utf-8').hex()
    # build_response += 0x00+0x00+0x00+0x01
    # build_response += '\x00\x00\x00\x01'
    print(build_response)

    return build_response


def dns_handler(data,addr,server_socket):
    print(data, addr)
    # in python the hex decimal base is represented by "\x00" - meaning that its bytes before converted to ASCII charaters
    data_str = str(data)
    # a = '212.143.70.40'
    # string = 'Welcome to heaven'
    # addr_str = str(addr)
    # print(addr_str)
    # server_socket.sendall(string.encode())

    # print('!!!!!!!!!!!!!!')
    # print((0).to_bytes(1, byteorder='big'))
    # return

    if 'o' in data_str:
        print("GOOGLE \nGOOGLE")
        # hw = "hello world"
        # a = '212.143.70.40'
        host_name = 'www.yahoo.com'
        host_ip = socket.gethostbyname(host_name)
        print(host_ip)
        # dns_server = bytes(host_ip, encoding='utf8')
        hex_hostname = to_hex(host_name)
        server_socket.sendto(hex_hostname, addr)

def dns_udp_server(ip, port):
    # AF_INET - means that we use ipv4 and not ipv6
    # socket.SOCK_DGRAM - means that we use UDP and not TCP

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((ip, port)) # when binding socket we need to provide one tuple containing ip and port
    print("server started succesfully, \nWaiting for data")
    while True:
        try:
            data, addr = server_socket.recvfrom(DEFAULT_BUFFER_SIZE)
            dns_handler(data, addr, server_socket)
        except IndexError:
            break

def main():

    dns_udp_server(DNS_SERVER_IP,DNS_SERVER_PORT)

if __name__ == '__main__':
    main()