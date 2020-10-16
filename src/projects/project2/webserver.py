"""Python Web server implementation"""
from socket import socket, AF_INET, SOCK_STREAM


ADDRESS = "127.0.0.2"  # Local client is going to be 127.0.0.1
PORT = 4300  # Open http://127.0.0.2:4300 in a browser
LOGFILE = "webserver.log"


def main():
    """Main loop"""
    with socket(AF_INET, SOCK_STREAM) as server_sock:
        print("Server started")
        server_sock.bind((ADDRESS,PORT))
        server_sock.listen(1)
        print("Binded")
        while True:
            msg, client = server_sock.accept()
            with msg:
                request = msg.recv(2048)
                data = request.decode()
                print(data)


if __name__ == "__main__":
    main()
