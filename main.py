import binascii
import socket


ANSWER_LENGTH = 0
KNOWN_NS = {
    'test.ru' : '1.1.1.1'
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


def make_req_header(id, params, qdcount, ancount="00 00", nscount="00 00", arcount="00 00"):
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
    return body


def parse_response(response, name):
    global KNOWN_NS
    parsed = {}
    parsed['id'] = response[0:4]
    params = response[4:8]
    params = str(format(int(params, 16), '0>42b'))
    if params[-4::] == '0011':
        raise ValueError('No such name')
    if params[-4::] == '0101':
        raise ValueError('Refused')
    parsed['params'] = params
    parsed['answer_section'] = response[ANSWER_LENGTH:]
    gen = parse_answer(parsed['answer_section'])
    for value in gen:
        print(value['addr'])
        KNOWN_NS[name] = value['addr']
    return KNOWN_NS


def parse_answer(answer):
    result = {}
    while answer:
        result['name'] = answer[0:4]
        result['type'] = answer[4:8]
        result['class'] = answer[8:12]
        result['ttl'] = answer[16:20]
        result['rdlength'] = answer[20:24]

        length = int(result['rdlength'],16)
        type = int(result['type'], 16)
        data_raw = answer[24:24+length*2]

        if type == 1:
            data = [str(int(data_raw[i:i + 2], 16)) for i in range(0, len(data_raw), 2)]
            addr = '.'.join(data)
        else:
            data = [str(data_raw[i:i + 2]) for i in range(0, len(data_raw), 2)]
            addr = ' '.join(data)
            # addr = binascii.unhexlify(addr)

        result['addr'] = addr
        yield result
        answer = answer[24+length*2::]


def nslookup(name, main_server = '8.8.8.8'):
    global ANSWER_LENGTH
    global KNOWN_NS
    if KNOWN_NS.get(name):
        print(KNOWN_NS.get(name))
        return
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
    header = make_req_header(req_id, configure_params(**params), '00 01')
    body = make_req_body(name, '00 01', '00 01')
    request = header + ' ' + body
    ANSWER_LENGTH = len(request.replace(' ', ''))
    response = send_udp_message(request, main_server, 53)  # 212.193.163.6
    ip = parse_response(response, name)
    KNOWN_NS = ip


if __name__ == "__main__":
    nslookup('yandex.ru')
    print(KNOWN_NS)
