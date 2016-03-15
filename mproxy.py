import argparse
import errno
import logging
import os
import Queue
import select
import socket
import ssl
import sys
import threading


MAXCONN = 200
BUFSIZE = 4096

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("mproxy")


def print_and_exit(status, message, level):
    if level == logging.ERROR:
        logger.error("Exit %d: %s", status, message)
    else:
        logger.info("Exit %d: %s", status, message)
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
        logger.info("Creating workers...")
        for _ in range(thread_count):
            thread = threading.Thread(target=self.get_next_request)
            thread.daemon = True
            thread.start()
        logger.info("All workers created")
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind(('', port))
            self.sock.listen(MAXCONN)
            logger.info("Proxy server listening on port %s", str(port))
        except Exception as ex:
            print_and_exit(1, "Unable to initialize socket", logging.ERROR)


    def get_next_request(self):
        while True:
            conn, data, addr = self.queue.get()
            self.process_request(conn, data, addr)
            self.queue.task_done()


    def start(self):
        logger.info("Starting proxy server...\n")
        while True:
            try:
                conn, addr = self.sock.accept()
                if self.timeout > 0:
                    conn.settimeout(self.timeout)
                try:
                    ready_socks = select.select([conn], [], [], 1)
                    if ready_socks[0]:
                        data = conn.recv(BUFSIZE)
                    else:
                        conn.close()
                        continue
                except socket.timeout as ex:
                    logger.error("%s", ex)
                    conn.close()
                else:
                    self.queue.put((conn, data, addr))
            except KeyboardInterrupt:
                self.sock.close()
                print_and_exit(0, "Closing connection", logging.INFO)
        self.sock.close()


    def process_request(self, conn, data, addr):
        host, port = self.parse_request(data)
        logger.info("Host: %s", host)
        logger.info("Port: %d", port)
        logger.info("Address: %s\n", addr[0])
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
                    ready_socks = select.select([s], [], [], 1)
                    if ready_socks[0]:
                        response = s.recv(BUFSIZE)
                    else:
                        break
                    if len(response) > 0:
                        conn.send(response)
                        if self.log:
                            with open(filename, "a+") as f:
                                f.write(response)
                        logger.info("Request processed for %s (%s)", host, addr[0])
                    else:
                        break
                except socket.timeout as ex:
                    logger.error("%s", ex)
                    break
            s.close()
            conn.close()
        except socket.error as ex:
            logger.error("%s", ex)
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
                        action='version',
                        version='%(prog)s 0.1 Copyright (C) Brandon Hammel',
                        help='show version information and exit')
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
        print_and_exit(4, "Invalid port", logging.ERROR)
    elif args.numworker < 1:
        print_and_exit(4, "Invalid number of workers", logging.ERROR)
    elif args.timeout < -1:
        print_and_exit(4, "Invalid timeout", logging.ERROR)
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
    logger.debug("Port: %d", args.port)
    logger.debug("Numworkers: %d", args.numworker)
    logger.debug("Timeout: %d", args.timeout)
    if not logdir is None:
        logger.debug("Logdir: %s\n", logdir)
    else:
        logger.debug("Logdir: None\n")
    proxy = Proxy(args.port, args.numworker, args.timeout, logdir)
    proxy.start()


if __name__ == '__main__':
    main()
