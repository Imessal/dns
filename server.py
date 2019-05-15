import binascii
import ipaddress
import socket
import sys
import pickle
import time


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
    #global KNOWN_NS
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
    gen = parse_answer(parsed['answer_section'], response)# parsed['header'])
    for value in gen:
        addresses.append((value['addr'],
                       get_type_by_value(value['type'])))
        ttl = value['ttl']
    result = (addresses, ttl)
    return result


def merge_addresses(addresses):
    new_dict = {}
    for (value, key) in addresses:
        if key in new_dict:
            new_dict[key].append(value)
        else:
            new_dict[key] = [value]
    return new_dict


def get_type_by_value(value):
    types = {'0001' : 'A',
             '0002' : 'NS',
             '0028' : 'AAAA',
             '0012' : 'PTR'}
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


def ns_request(name, type, main_server = '8.8.8.8'): # 212.193.163.6
    global ANSWER_LENGTH
    global KNOWN_NS
    try:
        value, rec_time = KNOWN_NS[name][type]
        ttl = value[1]
        print('TTL given by main server:', ttl)
        print('Current storage time', time.time() - rec_time)
        if time.time() - rec_time > ttl:
            pass
        else:
            return value[0]
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

    print(result)

    addrs = result[0]
    merged = merge_addresses(addrs)
    safe_result = {}
    for keys, values in merged.items():
        safe_result[keys] = (set(values), result[1]) , time.time()

    if KNOWN_NS.get(name):
        for keys, values in safe_result.items():
            KNOWN_NS[name][keys] = values
    else:
        KNOWN_NS[name] = {}
        for keys, values in safe_result.items():
            KNOWN_NS[name][keys] = values
    return safe_result[type][0][0]


HOST = ''
PORT = 7000

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print('# Socket created')

try:
    s.bind((HOST, PORT))
except socket.error as msg:
    print('# Bind failed. ')
    sys.exit()

print('# Socket bind complete')

s.listen(10)
print('# Socket now listening')

try:
    with open('saved.pickle', 'rb') as f:
        load = pickle.load(f)
        KNOWN_NS = load
        print('NS loaded from disk:', KNOWN_NS)
except:
    pass

conn, addr = s.accept()
print('# Connected to ' + addr[0] + ':' + str(addr[1]))

while True:
    data = conn.recv(1024)
    if not data:
        conn.close()
        conn, addr = s.accept()
    else:
        name, type = pickle.loads(data)
        if (name, type) == ('shut', 'down'):
            s.close()
            with open('saved.pickle', 'wb') as f:
                print('saving... ', KNOWN_NS)
                pickle.dump(KNOWN_NS, f)
            break

        # line = line.replace("\n","")
        print('# Got', name, type)
        print('# KNOWN NS:', KNOWN_NS)
        result = ns_request(name, type)
        print('# Result to send:', result)
        conn.send(pickle.dumps(result))
