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

from M2Crypto import RSA, X509
from OpenSSL import crypto, SSL
from pprint import pprint
from time import gmtime, mktime


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


def create_self_signed_cert(cert_file, key_file):
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 1024)

    cert = crypto.X509()
    cert.get_subject().C = "US"
    cert.get_subject().ST = "California"
    cert.get_subject().L = "Isla Vista"
    cert.get_subject().O = "HackItUp, Inc."
    cert.get_subject().OU = "HackItUp, Inc."
    cert.get_subject().CN = socket.gethostname()
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha1')

    open(cert_file, "wt").write(
        crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    open(key_file, "wt").write(
        crypto.dump_privatekey(crypto.FILETYPE_PEM, k))


def use_cert(cert_file, key_file, message):
    f = open(cert_file)
    cert_buffer = f.read()
    f.close()

    cert = X509.load_cert_string(cert_buffer, X509.FORMAT_PEM)
    pub_key = cert.get_pubkey()
    rsa_key = pub_key.get_rsa()
    cipher = rsa_key.public_encrypt(message, RSA.pkcs1_padding)

    logger.debug("Message encrypted")

    read_rsa = RSA.load_key(key_file)
    try:
        plaintext = read_rsa.private_decrypt(cipher, RSA.pkcs1_padding)
    except:
        print("Error: wrong key?")
        plaintext = ""

    logger.debug("Message decrypted:")
    logger.debug("%s", plaintext)


class Proxy:

    def __init__(self, port, thread_count, timeout, logdir):
        self.timeout = timeout
        self.logdir = logdir
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
            logger.info("Proxy server listening on port %d", port)
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
                    r, w, e = select.select([conn], [], [], 1)
                    if conn in r:
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
        if self.logdir:
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
            r, w, e = select.select([], [s], [], 1)
            if s in w:
                s.send(data)
            else:
                s.close()
                conn.close()
                return
            if self.logdir:
                with open(filename, "a+") as f:
                    f.write(data + "\n")
            while True:
                try:
                    r, w, e = select.select([s], [], [], 1)
                    if s in r:
                        response = s.recv(BUFSIZE)
                    else:
                        break
                    if len(response) > 0:
                        r, w, e = select.select([], [conn], [], 1)
                        if conn in w:
                            conn.send(response)
                        else:
                            break
                        if self.logdir:
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
    if logdir:
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
    if logdir:
        logger.debug("Logdir: %s\n", logdir)
    else:
        logger.debug("Logdir: None\n")
    cert_file = "selfsigned.crt"
    key_file = "private.key"
    create_self_signed_cert(cert_file, key_file)
    use_cert(cert_file, key_file, "Fuck you!")
    proxy = Proxy(args.port, args.numworker, args.timeout, logdir)
    proxy.start()


if __name__ == '__main__':
    main()
