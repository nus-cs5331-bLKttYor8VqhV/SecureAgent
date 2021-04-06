import socket
from urllib.parse import urlparse

HOST = "127.0.0.1"
PORT = 4567

class EnclaveRequest:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(2)

    def get(self, url):
        parser = urlparse(url)
        host = parser.netloc
        port = parser.port if parser.port else ("80" if parser.scheme == "http" else "443")
        path = parser.path
        request = f"""GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n"""
        self.sock.connect((HOST, PORT))
        self.send(host)
        self.send(port)
        print(port)
        self.send(request)


    def post(self, url, data):
        pass

    def send(self, data):
        print("sending ...\n")
        try:
            self.sock.send(data.encode("ascii"))
            a = self.sock.recv(3)
            assert(a==b"ACK")
        except (socket.timeout, ConnectionRefusedError):
            print("[-] SGX enclave socket server not found\n")

class Response:
    def __init__(self):
        pass


if __name__ == "__main__":
    a = EnclaveRequest()
    a.get("https://httpbin.org/get")