import socket
import json
from urllib.parse import urlparse


class EnclaveRequest:
    def __init__(self, host="127.0.0.1", port=4567):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(2)
        # Can raise ConnectionRefusedError is enclave is not listening
        self.sock.connect((host, port))

    def get(self, url):
        # Parse url
        parser = urlparse(url)
        host = parser.netloc
        port = parser.port if parser.port else (
            "80" if parser.scheme == "http" else "443")
        path = parser.path
        # Prepare request
        request = f"""GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n"""
        # Send request
        nb_try = 3
        done = False
        while(nb_try > 0 and done == False):
            try:
                self.send(host)
                self.send(port)
                self.send(request)
                done = True
            except socket.timeout:
                nb_try -= 1
        # Receive response from enclave
        self.sock.settimeout(10)
        a = self.sock.recv(1024)
        a = a.decode().split("\r\n")
        return a

    def post(self, url, data):
        # Parse url
        parser = urlparse(url)
        host = parser.netloc
        port = parser.port if parser.port else (
            "80" if parser.scheme == "http" else "443")
        path = parser.path
        # Prepare request
        json_string = json.dumps(data)
        json_len = len(json_string)
        request = f"""POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {json_len}\r\n\r\n{json_string}""" + "\r\n"
        # Send request
        nb_try = 3
        done = False
        while(nb_try > 0 and done == False):
            try:
                self.send(host)
                self.send(port)
                self.send(request)
                done = True
            except socket.timeout:
                nb_try -= 1
        # Receive response from enclave
        self.sock.settimeout(10)
        a = self.sock.recv(1024)
        a = a.decode().split("\r\n")
        return a

    def send(self, data):
        try:
            self.sock.send(data.encode("ascii"))
            a = self.sock.recv(3)
            assert(a == b"ACK")
        except socket.timeout:
            print("[-] Problem when sending data to enclave\n")


class Response:
    def __init__(self):
        pass


if __name__ == "__main__":
    a = EnclaveRequest()
    # Test 1
    """    d = {"test": "oo"}
    a.post("https://httpbin.org/post", d)"""
    # Test 2
    print(a.get("https://httpbin.org/get?param1=2"))
