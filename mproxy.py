import argparse
import logging
import os
import select
import socket
import string
import sys
import threading
import traceback

MAXCONN = 10
BUFSIZE = 4096

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
log = False


def print_and_exit(status, message):
    print("Exit " + str(status) + ": " + message)
    sys.exit(status)


def log_message(message, type):
    if log == True and type == 'info':
        logger.info(message)
    else:
        logger.debug(message)


class Proxy:

    def __init__(self, port, thread_count, timeout):
        self.thread_count = thread_count
        self.timeout = timeout
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind(('', port))
            print("Proxy server successfully binded to port " + str(port))
            self.sock.listen(MAXCONN)
            print("Proxy server listening on port " + str(port))
        except Exception, e:
            print_and_exit(1, "Unable to initialize socket")


    def start(self):
        print("Starting proxy server...")
        while True:
            try:
                conn, addr = self.sock.accept()
                data = conn.recv(BUFSIZE)
                thread = threading.Thread(target=self.proxy_server,
                                          args=(conn, data, addr))
                thread.start()
            except KeyboardInterrupt:
                self.sock.close()
                print_and_exit(0, "Closing connection")
        self.sock.close()


    def proxy_server(self, conn, data, addr):
        host, port = self.parse_request(data)
        print("Host: " + str(host))
        print("Port: " + str(port))
        print("Address: " + str(addr[0]) + "\n")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((host, port))
            s.send(data)
            while True:
                reply = s.recv(BUFSIZE)
                if len(reply) > 0:
                    conn.send(reply)
                    print("Request processed for " + str(host) + " ("
                            + str(addr[0]) + ")")
                else:
                    break
            s.close()
            conn.close()
        except socket.error, (value, message):
            s.close()
            conn.close()


    def parse_request(self, data):
        host = ''
        port = 0
        # Client browser request appears here
        try:
            first_line = data.split('\n')[0]
            url = first_line.split(' ')[1]
            # Find the position of "://"
            http_pos = url.find('://')
            if http_pos < 0:
                temp = url
            else:
                # Get the rest of the url
                temp = url[(http_pos + 3):]
            # Find the position of the port (if any)
            port_pos = temp.find(':')
            # Find the end of the host
            host_pos = temp.find('/')
            if host_pos < 0:
                host_pos = len(temp)
            if port_pos < 0 or host_pos < port_pos:
                # Default port
                port = 80
                host = temp[:host_pos]
            else:
                # Specific port
                port = int((temp[(port_pos + 1):])[:host_pos - port_pos - 1])
                host = temp[:port_pos]
        except Exception, e:
            pass
        return host, port


def main():
    global log
    parser = argparse.ArgumentParser(description='A simple HTTP proxy.',
                                     prog='mproxy')
    parser.add_argument('-v', '--version',
                        action='version', version='%(prog)s 0.1 Brandon Hammel',
                        help='prints version information and exit')
    parser.add_argument('-p', '--port',
                        type=int, required=True,
                        help='port the server will be listening on')
    parser.add_argument('-n', '--numworker',
                        type=int, default=10,
                        help='number of threads [default: 10]')
    parser.add_argument('-t', '--timeout',
                        type=int, default=-1,
                        help='time (seconds) to wait before giving up '
                             '[default: infinite]')
    parser.add_argument('-l', '--log',
                        action='store_true',
                        help='logs all requests and responses')
    args = parser.parse_args()
    if args.port < 1 or args.port > 65535:
        print_and_exit(4, "Error: Invalid port")
    elif args.numworker < 1:
        print_and_exit(4, "Error: Invalid number of workers")
    elif args.timeout < -1:
        print_and_exit(4, "Error: Invalid timeout")
    print("Port: " + str(args.port))
    print("Numworkers: " + str(args.numworker))
    print("Timeout: " + str(args.timeout))
    print("Logfile: " + str(args.log) + "\n")
    if args.log == True:
        log = True
    proxy = Proxy(args.port, args.numworker, args.timeout)
    proxy.start()


if __name__ == '__main__':
    main()
