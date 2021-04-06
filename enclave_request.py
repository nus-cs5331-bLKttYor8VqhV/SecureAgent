import socket, json
from urllib.parse import urlparse


class EnclaveRequest:
    def __init__(self, host="127.0.0.1", port=4567):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(2)
        try:        
            self.sock.connect((host, port))
        except (socket.timeout, ConnectionRefusedError):
            print("[-] SGX enclave socket server not found\n")


    def get(self, url):
        parser = urlparse(url)
        host = parser.netloc
        port = parser.port if parser.port else ("80" if parser.scheme == "http" else "443")
        path = parser.path
        request = f"""GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n"""
        self.send(host)
        self.send(port)
        self.send(request)
        print("[+] Sent")
        self.sock.settimeout(10)
        a = self.sock.recv(1024)
        a = a.decode().split("\r\n")
        print(a)

    def post(self, url, data):
        parser = urlparse(url)
        host = parser.netloc
        port = parser.port if parser.port else ("80" if parser.scheme == "http" else "443")
        path = parser.path
        json_string = json.dumps(data)
        json_len = len(json_string)
        request = f"""POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {json_len}\r\n\r\n{json_string}""" + "\r\n"
        self.send(host)
        self.send(port)
        self.send(request)
        print("[+] Sent")
        self.sock.settimeout(10)
        a = self.sock.recv(1024)
        a = a.decode().split("\r\n")
        # Test with httpbin post
        print(a)
        print(json.loads(a[-1]))

    def send(self, data):
        try:
            self.sock.send(data.encode("ascii"))
            a = self.sock.recv(3)
            assert(a==b"ACK")
        except socket.timeout:
            print("[-] SGX enclave socket server not found\n")

class Response:
    def __init__(self):
        pass


if __name__ == "__main__":
    a = EnclaveRequest()
    # Test 1
    """    d = {"test": "oo"}
    a.post("https://httpbin.org/post", d)"""
    # Test 2
    a.get("https://httpbin.org/get?param1=2")