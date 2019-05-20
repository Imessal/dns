import binascii
import ipaddress
import threading
import socket
import sys
import pickle
import time
from collections import defaultdict

from dnslib import *


ANSWER_LENGTH = 0
KNOWN_NS = {}
TYPE_VALUES = {
    'A' : '00 01',
    'NS' : '00 02',
    # 'SOA' : '00 06',
    'AAAA' : '00 1C',
    'PTR' : '000C'
}


def send_udp_message(message, address, port):
    message = message.replace(" ", "").replace("\n", "")
    server_address = (address, port)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(binascii.unhexlify(message), server_address)
        data, _ = sock.recvfrom(4096)

    return binascii.hexlify(data).decode("utf-8")


def format_hex(hex):
    octets = [hex[i:i+2] for i in range(0, len(hex), 2)]
    pairs = [" ".join(octets[i:i+2]) for i in range(0, len(octets), 2)]
    return "\n".join(pairs)


def configure_params(qr, opcode, aa, tc, r, ra, z, rcode):
    params = str(qr) + \
             check_length(opcode, 4) + \
             str(aa) + \
             str(tc) + \
             str(r) + \
             str(ra) + \
             check_length(z, 3) + \
             check_length(rcode, 4)
    if len(params) != 16:
        raise ValueError('Error here!')

    data = [params[i:i+4] for i in range(0, len(params), 4)]
    result = ''
    for el in data:
        hex_one = format(int(el), 'x')
        result += hex_one
    return result[:2:] + ' ' + result[2::]


def check_length(field, length):
    field = str(field)
    while len(field) < length:
        field = '0'+field
    return field


def configure_header(id, params, qdcount, ancount="00 00", nscount="00 00", arcount="00 00"):
    header = id + ' ' + \
             params + ' ' + \
             qdcount + ' ' + \
             ancount + ' ' + \
             nscount + ' ' + \
             arcount
    return header


def make_req_body(qname, qtype, qclass):
    s_name = qname.split('.')
    result = ''
    for section in s_name:
        length = check_length(format(len(section), 'x'), 2) #КОСТЫЛЬ
        encoded = section.encode()
        encoded = binascii.hexlify(encoded)
        encoded = str(encoded, 'ascii')
        result += str(length)
        result += encoded
    body = ' '.join([result[i:i+2] for i in range(0, len(result), 2)])
    body += " 00" + ' ' + qtype +' '+ qclass
    # print(body)
    return body


def get_type(type):
    global TYPE_VALUES
    try:
        return TYPE_VALUES[type]
    except KeyError:
        return '00 01'


def parse_response(response, name):
    global KNOWN_NS
    addresses = []
    parsed = {}
    ttl = 0
    parsed['id'] = response[0:4]
    params = response[4:8]
    params = str(format(int(params, 16), '0>42b'))
    if params[-4::] == '0011':
        raise ValueError('No such name')
    if params[-4::] == '0101':
        raise ValueError('Refused')
    parsed['params'] = params
    parsed['answer_section'] = response[ANSWER_LENGTH:]
    parsed['header'] = response[:ANSWER_LENGTH]
    gen = parse_answer(parsed['answer_section'], response)
    for value in gen:
        addresses.append((value['name'], value['addr'],
                          get_type_by_value(value['type'])))
        ttl = value['ttl']
    result = (addresses, ttl)
    return result


def merge_addresses(addresses):
    result_dict = defaultdict(dict)
    for name, addr, type in addresses:
        result_dict[name][type] = []
    for name, addr, type in addresses:
        if name in result_dict.keys():
            if type in result_dict[name].keys():
                result_dict[name][type].append(addr)
    return result_dict


def get_type_by_value(value):
    types = {'0001' : 'A',
             '0002' : 'NS',
             '0028' : 'AAAA',
             '001c' : 'AAAA',
             '000c' : 'PTR'}
    return types[value]


def parse_answer(answer, response):
    result = {}
    while answer:
        result['name'] = answer[0:4]
        result['type'] = answer[4:8]
        result['class'] = answer[8:12]
        result['ttl'] = int(answer[16:20], 16)
        result['rdlength'] = answer[20:24]

        length = int(result['rdlength'],16)
        type = int(result['type'], 16)
        data_raw = answer[24:24+length*2]

        if type == 1:
            data = [str(int(data_raw[i:i + 2], 16)) for i in range(0, len(data_raw), 2)]
            addr = '.'.join(data)
        elif type == 2:
            data = [str(data_raw[i:i + 2]) for i in range(0, len(data_raw), 2)]
            addr = ''.join(data)
            addr = parse_ns(addr, response)
        elif type == 28:
            data = [str(data_raw[i:i + 4]) for i in range(0, len(data_raw), 4)]
            addr = ':'.join(data)
            addr = str(ipaddress.ip_address(addr))
        else:
            try:
                data = [str(data_raw[i:i + 2]) for i in range(0, len(data_raw), 2)]
                addr = ''.join(data)
                addr = parse_ns(addr, response)
            except Exception:
                raise ValueError('Something bad happened. Probably no ipv6 address')

        result['addr'] = addr
        result['name'] = parse_ns(result['name'], response)
        yield result
        answer = answer[24+length*2::]


def parse_ns(data, package):
    if data[-4:-2] == 'c0':
        name = data[:-4:]
        offset = int(data[-2::], 16)
    else:
        name = data[:-2:]
        offset = 0
    parts = []
    while name:
        length = int(name[:2], 16)
        parts.append(binascii.unhexlify(name[2:2 + length * 2]).decode())
        name = name[2 + length * 2:]
    s_name = package[offset * 2:]
    length = int(s_name[:2], 16)
    while True:
        if offset == 0:
            break
        part = s_name[2:2 + length * 2]
        parts.append(binascii.unhexlify(part).decode())
        if s_name[2 + length * 2:4 + length * 2:] == 'c0':
            offset = int(s_name[4 + length * 2:6 + length*2], 16)
            s_name = package[offset * 2:]
            length = int(s_name[:2], 16)
        else:
            s_name = s_name[2 + length * 2::]
            length = int(s_name[:2], 16)
            if length == 0:
                break
    result = '.'.join(parts)
    return result


def make_header():
    req_id = 'AA AA'
    params = {
        'qr': 0,
        'opcode': check_length(0, 4),
        'aa': 0,
        'tc': 0,
        'r': 1,
        'ra': 0,
        'z': check_length(0, 3),
        'rcode': check_length(0, 4)
    }
    return configure_header(req_id, configure_params(**params), '00 01')


def change_name_to_ptr(name):
    name = name.split('.')
    name.reverse()
    name = '.'.join(name)
    name += '.in-addr.arpa'
    return name


def get_name_from_req(data):
    type = data[-8:-4]
    data = data[24:-10:]
    parts = []
    while data:
        length = int(data[:2], 16)
        parts.append(binascii.unhexlify(data[2:2 + length * 2]).decode())
        data = data[2 + length * 2:]
    name = '.'.join(parts)
    print(name, type)
    return name, type


def ns_request(name, type, main_server='212.193.163.6'): # 212.193.163.6
    global ANSWER_LENGTH
    global KNOWN_NS
    try:
        if type == 'AAAA':
            return ['']
        print(KNOWN_NS[name])
        value, ttl, rec_time = KNOWN_NS[name]
        # ttl = value[1]
        print('TTL given by main server:', ttl)
        print('Current storage time', time.time() - rec_time)
        if time.time() - rec_time > ttl:
            pass
        else:
            print('RETURNED FROM KNOWN NS', value[type])
            return value[type]
    except KeyError:
        pass
    if type == 'PTR':
        name = change_name_to_ptr(name)
    header = make_header()
    body = make_req_body(name,
                            get_type(type),
                            '00 01')
    requesrt = header + ' ' + body
    ANSWER_LENGTH = len(requesrt.replace(' ', ''))
    response = send_udp_message(requesrt, main_server, 53)
    try:
        result = parse_response(response, name)
    except ValueError as error:
        return [str(error)]

    addrs, ttl = result
    merged = merge_addresses(addrs)
    safe_result = {}
    for el in merged.keys():
        safe_result[el] = (merged[el], ttl, time.time())

    for key, value in safe_result.items():
        print(key, value)

    for key, value in safe_result.items():
        if KNOWN_NS.get(key):
            KNOWN_NS[key] = safe_result[key]
        else:
            KNOWN_NS[key] = {}
            KNOWN_NS[key] = safe_result[key]

    print('KNOWN NS', KNOWN_NS)
    return safe_result[name][0][type]


def make_nslib_a_response(id, name, addresses):
    d = DNSRecord(DNSHeader(id=id, qr=1, aa=0, ra=1),
                  q=DNSQuestion(name))
    for addr in addresses:
        d.add_answer(RR(name, ttl=200, rdata=A(addr)))
    return binascii.hexlify(d.pack()).decode()


def make_nslib_ns_response(id, name, addresses):
    d = DNSRecord(DNSHeader(id=id, qr=1, aa=0, ra=1),
                  q=DNSQuestion(name))
    for addr in addresses:
        d.add_answer(RR(name, rtype=2, ttl=200, rdata=NS(addr)))
    return binascii.hexlify(d.pack()).decode()


def make_nslib_ptr_response(id, name, addresses):
    d = DNSRecord(DNSHeader(id=id, qr=1, aa=0, ra=1),
                  q=DNSQuestion(name))
    for addr in addresses:
        d.add_answer(RR(name, rtype=12, ttl=200, rdata=PTR(addr)))
    return binascii.hexlify(d.pack()).decode()


def save():
    with open('saved.pickle', 'wb') as f:
        print('saving... ', KNOWN_NS)
        pickle.dump(KNOWN_NS, f)


HOST = 'localhost'
PORT = 53

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
print('# Socket created')

try:
    s.bind((HOST, PORT))
except socket.error as msg:
    print('# Bind failed. ')
    sys.exit()

print('# Socket bind complete')

try:
    with open('saved.pickle', 'rb') as f:
        load = pickle.load(f)
        KNOWN_NS = load
        print('NS loaded from disk:', KNOWN_NS)
except:
    pass


save()


while True:
    request, addr = s.recvfrom(1024)
    if not request:
        pass
    else:
        print("# From", addr)
        query = binascii.hexlify(request).decode()
        print(query)
        name, type = get_name_from_req(query)
        if type == '001c':
            s.sendto(''.encode(), addr)
        type = get_type_by_value(type)
        id = query[0:4]
        print(name, type)

        time.sleep(1 - time.monotonic() % 1)
        save()

        print('# Got', name, type)
        print('# KNOWN NS:', KNOWN_NS)
        addresses = ns_request(name, type)
        print('\n', addresses, '\n')
        print('# Result to send:\n',
              make_nslib_ns_response(int(id, 16), name, addresses))
        try:
            if type == 'A':
                s.sendto(binascii.unhexlify(make_nslib_a_response(int(id, 16), name, addresses)), addr)
            elif type == 'NS':
                s.sendto(binascii.unhexlify(make_nslib_ns_response(int(id, 16), name, addresses)), addr)
            elif type == 'PTR':
                s.sendto(binascii.unhexlify(make_nslib_ptr_response(int(id, 16), name, addresses)), addr)
            else:
                pass
        except ValueError:
            pass

