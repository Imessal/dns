import socket
import sys
import pickle


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ip = '127.0.0.1'
port = 7000
addr = (ip, port)


if __name__ == '__main__':
    s.connect(addr)
    s.settimeout(1)
    name, type = sys.argv[1], sys.argv[2]
    request = pickle.dumps((name, type))
    s.send(request)
    while True:
        try:
            reply = s.recv(1024)
            if not reply:
                break
            result = pickle.loads(reply)
            for el in result:
                print(el)
        except socket.timeout:
            break

