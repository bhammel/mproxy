import argparse
import errno
import os
import Queue
import socket
import sys
import threading

MAXCONN = 10
BUFSIZE = 4096


def print_and_exit(status, message):
    print("Exit " + str(status) + ": " + message)
    sys.exit(status)


class Proxy:

    def __init__(self, port, thread_count, timeout, logdir):
        self.timeout = timeout
        self.logdir = logdir
        self.log = False
        if not logdir is None:
            self.log = True
        self.index = 0
        self.index_lock = threading.Lock()
        self.queue = Queue.Queue()
        print("Creating workers...")
        for _ in range(thread_count):
            thread = threading.Thread(target=self.get_next_request)
            thread.daemon = True
            thread.start()
        print("All workers created")
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind(('', port))
            self.sock.listen(MAXCONN)
            print("Proxy server listening on port " + str(port))
        except Exception as ex:
            print_and_exit(1, "Unable to initialize socket")


    def get_next_request(self):
        while True:
            conn, data, addr = self.queue.get()
            self.process_request(conn, data, addr)
            self.queue.task_done()


    def start(self):
        print("Starting proxy server...\n")
        while True:
            try:
                conn, addr = self.sock.accept()
                if self.timeout > 0:
                    conn.settimeout(self.timeout)
                try:
                    data = conn.recv(BUFSIZE)
                except socket.timeout as ex:
                    print(ex)
                    conn.close()
                else:
                    self.queue.put((conn, data, addr))
            except KeyboardInterrupt:
                self.sock.close()
                print("\n")
                print_and_exit(0, "Closing connection")
        self.sock.close()


    def process_request(self, conn, data, addr):
        host, port = self.parse_request(data)
        print("Host: " + str(host))
        print("Port: " + str(port))
        print("Address: " + str(addr[0]) + "\n")
        filename = ''
        if self.log:
            self.index_lock.acquire()
            try:
                filename = self.logdir + str(self.index) + "_" + str(addr[0]) + "_" + str(host)
                self.index += 1
            finally:
                self.index_lock.release()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((host, port))
            if self.timeout > 0:
                s.settimeout(self.timeout)
            s.send(data)
            if self.log:
                with open(filename, "a+") as f:
                    f.write(data + "\n")
            while True:
                try:
                    response = s.recv(BUFSIZE)
                    if len(response) > 0:
                        conn.send(response)
                        if self.log:
                            with open(filename, "a+") as f:
                                f.write(response)
                        print("Request processed for " + str(host) + " ("
                                + str(addr[0]) + ")")
                    else:
                        break
                except socket.timeout as ex:
                    print(ex)
                    break
            s.close()
            conn.close()
        except socket.error as ex:
            print(ex)
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
        except Exception as ex:
            pass
        return host, port


def main():
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
                        nargs='?', default=None, const=os.getcwd(),
                        help='logs all requests and responses')
    args = parser.parse_args()
    if args.port < 1 or args.port > 65535:
        print_and_exit(4, "Error: Invalid port")
    elif args.numworker < 1:
        print_and_exit(4, "Error: Invalid number of workers")
    elif args.timeout < -1:
        print_and_exit(4, "Error: Invalid timeout")
    logdir = args.log
    if not logdir is None:
        if not os.path.exists(logdir):
            try:
                os.makedirs(logdir)
            except OSError as ex:
                if ex.errno != errno.EEXIST:
                    raise
        if not logdir.endswith("/"):
            logdir = logdir + "/"
    print("Port: " + str(args.port))
    print("Numworkers: " + str(args.numworker))
    print("Timeout: " + str(args.timeout))
    if not logdir is None:
        print("Logdir: " + logdir + "\n")
    else:
        print("Logdir: None\n")
    proxy = Proxy(args.port, args.numworker, args.timeout, logdir)
    proxy.start()


if __name__ == '__main__':
    main()
