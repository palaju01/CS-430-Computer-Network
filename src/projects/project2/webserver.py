"""Python Web server implementation"""
from socket import socket, AF_INET, SOCK_STREAM
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
        print("Server started")
        server_sock.bind((ADDRESS,PORT))
        server_sock.listen(1)
        print("Binded")
        while True:
            connection, client = server_sock.accept()
            with connection:
                request = connection.recv(1024)
                data = convertToDict(request)
                print(client[1])
                writeLogRequest(data["time"], data["file"], client[0], data["browser"], LOGFILE)


if __name__ == "__main__":
    main()
