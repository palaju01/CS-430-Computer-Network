"""Python Web server implementation"""
from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR
from datetime import datetime


ADDRESS = "127.0.0.2"  # Local client is going to be 127.0.0.1
PORT = 4300  # Open http://127.0.0.2:4300 in a browser
LOGFILE = "webserver.log"


def convertToDict(request):
    """ Decode the message and return it as a dictionary """
    # Convert it to string
    requestString = request.decode()
    print(requestString)

    # Create Dictionary for data
    data = {}

    # Split the request to separate lines
    requestLines = requestString.split("\r\n")

    # Method, file name, and version
    method, fileName, version = requestLines[0].split()
    data["method"] = method.strip()
    data["file"] = fileName.strip()
    data["version"] = version.split("/")[1]

    # User
    data["browser"] = requestLines[2].split(": ")[1]

    # Date
    data["time"] = str(datetime.now())

    return data


def writeLogRequest(time, fileRequested, clientIP, clientBroser, logFile):
    """ Appends the provided information into given log file """
    with open(logFile,"a") as log:
        output = time + " | " + fileRequested + " | " + clientIP + " | " + clientBroser + "\n"
        log.write(output)


def main():
    """Main loop"""
    with socket(AF_INET, SOCK_STREAM) as server_sock:
        server_sock.setsockopt(SOL_SOCKET, SO_REUSEADDR,1)
        server_sock.bind((ADDRESS,PORT))
        server_sock.listen(1)
        while True:
            connection, client = server_sock.accept()
            with connection:
                request = connection.recv(1024)
                data = convertToDict(request)
                writeLogRequest(data["time"], data["file"], client[0], data["browser"], LOGFILE)

                # Not Implemented
                if data["method"] != "GET" and data["method"] != "POST":
                    connection.send("HTTP/1.1 501 Not Implemented\r\n\r\n".encode())
                    connection.send("<html><head></head><body><h1>501 Not Implemented</h1></body></html>".encode())

                # Method Not Allowed
                if data["method"] != "GET":
                    connection.send("HTTP/1.1 405 Method Not Allowed\r\n\r\n".encode())
                    connection.send("<html><head></head><body><h1>405 Method Not Allowed</h1></body></html>".encode())

                # File Not Found
                elif data["file"] != "/alice30.txt":
                    connection.send("HTTP/1.1 404 Not Found\r\n\r\n".encode())
                    connection.send("<html><head></head><body><h1>404 Not Found</h1></body></html>".encode())

                # Valid request
                else:
                    # Calulate content length
                    content_length = 0
                    with open("alice30.txt", "rb") as f:
                        content_length = len(f.read())

                    # Send header
                    header = "HTTP/1.1 200 OK\n" + \
                    "Content-Length: {}\n".format(content_length) + \
                    "Content-Type: text/plain; charset=utf-8\n" + \
                    "Date: " + datetime.now().strftime("%a %b %d %H:%M:%S %Y") + "\n" + \
                    "Last-Modified: Wed Aug 29 11:00:00 2018\n" + \
                    "Server: CS430-GABRIEL\n\n"
                    connection.send(header.encode())

                    # Send file
                    with open("alice30.txt","rb") as content:
                        connection.send(content.read())
            connection.close()


if __name__ == "__main__":
    main()
