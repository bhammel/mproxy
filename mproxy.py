import argparse
import errno
import hashlib
import io
import logging
import OpenSSL
import os
import pprint
import Queue
import select
import socket
import ssl
import struct
import sys
import threading
import time


SSLCERT_DIR = "ssl"
CA_FILE = os.path.join(SSLCERT_DIR, "rootca.crt")
CERTS_DIR = os.path.join(SSLCERT_DIR, "certs")

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("mproxy")


def print_and_exit(status, message, level):
    if level == logging.ERROR:
        logger.error("Exit %d: %s", status, message)
    else:
        logger.info("Exit %d: %s", status, message)
    sys.exit(status)


def create_ca():
    ca_digest = 'sha1' if sys.platform == 'win32' and sys.getwindowsversion() < (6,) else 'sha256'
    key = OpenSSL.crypto.PKey()
    key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
    req = OpenSSL.crypto.X509Req()
    subj = req.get_subject()
    subj.countryName = 'US'
    subj.stateOrProvinceName = 'CA'
    subj.localityName = 'Santa Barbara'
    subj.organizationName = 'Root CA'
    subj.organizationalUnitName = 'CS 176B'
    subj.commonName = 'Brandon Hammel'
    req.add_extensions([OpenSSL.crypto.X509Extension(b'basicConstraints', False, b'CA:FALSE'),
        OpenSSL.crypto.X509Extension(b'keyUsage', False, b'nonRepudiation, digitalSignature, keyEncipherment')])
    req.set_pubkey(key)
    req.sign(key, ca_digest)
    ca = OpenSSL.crypto.X509()
    ca.set_serial_number(0)
    ca.gmtime_adj_notBefore(0)
    ca.gmtime_adj_notAfter(24 * 60 * 60 * 3652)
    ca.add_extensions([OpenSSL.crypto.X509Extension(b'basicConstraints', False, b'CA:TRUE')])
    ca.set_issuer(req.get_subject())
    ca.set_subject(req.get_subject())
    ca.set_pubkey(req.get_pubkey())
    ca.sign(key, ca_digest)
    return key, ca


def generate_ca_file():
    key, ca = create_ca()
    with open(CA_FILE, 'wb') as f:
        f.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key))
        f.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, ca))


class Proxy:
    maxconn = 200
    bufsize = 4096

    def __init__(self, port, thread_count, timeout, logdir):
        self.timeout = timeout
        self.logdir = logdir
        self.index = 0
        self.index_lock = threading.Lock()
        self.cert_lock = threading.Lock()
        self.queue = Queue.Queue()
        for _ in range(thread_count):
            thread = threading.Thread(target=self.get_next_request)
            thread.daemon = True
            thread.start()
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind(('', port))
            self.sock.listen(Proxy.maxconn)
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
                data = conn.recv(Proxy.bufsize)
                self.queue.put((conn, data, addr))
            except KeyboardInterrupt:
                self.sock.close()
                print_and_exit(0, "Closing connection", logging.INFO)
        self.sock.close()


    def process_request(self, conn, data, addr):
        host, port = self.parse_request(data)
        filename = ''
        if self.logdir:
            self.index_lock.acquire()
            try:
                filename = self.logdir + str(self.index) + "_" + str(addr[0]) + "_" + str(host)
                self.index += 1
            finally:
                self.index_lock.release()
        if port == 443 or port == 8443:
            self.handle_https_request(conn, data, addr, host, port, filename)
        else:
            self.handle_http_request(conn, data, addr, host, port, filename)


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


    def handle_http_request(self, conn, data, addr, host, port, filename):
        logger.info("Server: %s", host)
        logger.info("Port: %d", port)
        logger.info("Client: %s\n", addr[0])
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if self.timeout > 0:
                s.settimeout(self.timeout)
            s.connect((host, port))
            try:
                s.send(data)
                if not filename is '':
                    with open(filename, 'a+') as f:
                        f.write(data + '\n')
                while True:
                    r, w, e = select.select([s], [], [], 5)
                    if s in r:
                        response = s.recv(Proxy.bufsize)
                        if len(response) > 0:
                            conn.send(response)
                            if not filename is '':
                                with open(filename, 'a+') as f:
                                    f.write(response)
                            logger.info("HTTP request processed for %s (%s)", host, addr[0])
                        else:
                            break
                    else:
                        break
                s.close()
                conn.close()
            except socket.timeout as ex:
                logger.error("%s", ex)
                s.close()
                conn.close()
        except socket.error as ex:
            logger.error("%s", ex)
            conn.close()


    def handle_https_request(self, conn, data, addr, host, port, filename):
        try:
            conn.send(b"HTTP/1.1 200 OK\r\n\r\n")
            server_name = ''
            leadbyte = conn.recv(1, socket.MSG_PEEK)
            if leadbyte in ('\x80', '\x16'):
                if leadbyte == '\x16':
                    for _ in xrange(2):
                        leaddata = conn.recv(1024, socket.MSG_PEEK)
                        if self.is_clienthello(leaddata):
                            try:
                                server_name = self.extract_sni_name(leaddata)
                            finally:
                                break
            server_hostname = ''
            if not server_name is '':
                server_hostname = server_name
            else:
                server_hostname = host
            client_context = ssl.create_default_context()
            s = client_context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname=server_hostname)
            if self.timeout > 0:
                s.settimeout(self.timeout)
            s.connect((server_hostname, port))
            cert = s.getpeercert()
            subjectdict = cert.get("subject", None)
            sansdict = cert.get("subjectAltName", None)
            cn = ''
            for sub in subjectdict:
                for field, val in sub:
                    if field == 'commonName':
                        cn = val
            sans = []
            for sub, san in sansdict:
                sans.append(san)
            commonname = ''
            if not cn is '':
                commonname = cn
            else:
                commonname = host
            try:
                certfile = self.get_cert(commonname, sans)
                server_context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
                server_context.load_cert_chain(certfile=certfile)
                ssl_conn = server_context.wrap_socket(conn, server_side=True)
            except Exception as ex:
                logger.error("%s", ex)
                s.close()
                conn.close()
                return
            ssl_conn.do_handshake()
            logger.info("Server: %s", server_hostname)
            logger.info("Port: %d", port)
            logger.info("Client: %s\n", addr[0])
            try:
                request = ssl_conn.recv(Proxy.bufsize)
                s.send(request)
                if not filename is '':
                    with open(filename, 'a+') as f:
                        f.write(request + '\n')
                while True:
                    r, w, e = select.select([s], [], [], 5)
                    if s in r:
                        response = s.recv(Proxy.bufsize)
                        if len(response) > 0:
                            ssl_conn.send(response)
                            if not filename is '':
                                with open(filename, 'a+') as f:
                                    f.write(response)
                            logger.info("HTTPS request processed for %s (%s)", server_hostname, addr[0])
                        else:
                            break
                    else:
                        break
                s.close()
                ssl_conn.close()
            except socket.timeout as ex:
                logger.error("%s", ex)
                s.close()
                ssl_conn.close()
        except socket.error as ex:
            logger.error("%s", ex)
            conn.close()


    def is_clienthello(self, data):
        if len(data) < 20:
            return False
        if data.startswith('\x16\x03'):
            length, = struct.unpack('>h', data[3:5])
            return len(data) == 5 + length
        elif data[0] == '\x80' and data[2:4] == '\x01\x03':
            return len(data) == 2 + ord(data[1])
        else:
            return False


    def extract_sni_name(self, packet):
        if packet.startswith('\x16\x03'):
            stream = io.BytesIO(packet)
            stream.read(0x2b)
            session_id_length = ord(stream.read(1))
            stream.read(session_id_length)
            cipher_suites_length, = struct.unpack('>h', stream.read(2))
            stream.read(cipher_suites_length + 2)
            extensions_length, = struct.unpack('>h', stream.read(2))
            while True:
                data = stream.read(2)
                if not data:
                    break
                etype, = struct.unpack('>h', data)
                elen, = struct.unpack('>h', stream.read(2))
                edata = stream.read(elen)
                if etype == 0:
                    server_name = edata[5:]
                    return server_name


    def get_cert(self, commonname, sans):
        certfile = os.path.join(CERTS_DIR, commonname + '.crt')
        if os.path.exists(certfile):
            return certfile
        elif OpenSSL is None:
            return CA_FILE
        else:
            with self.cert_lock:
                if os.path.exists(certfile):
                    return certfile
                return self._get_cert(commonname, sans)


    def _get_cert(self, commonname, sans):
        ca_thumbprint = ''
        ca_digest = 'sha1' if sys.platform == 'win32' and sys.getwindowsversion() < (6,) else 'sha256'
        with open(CA_FILE, 'rb') as f:
            content = f.read()
            key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, content)
            ca = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, content)
            ca_thumbprint = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, content).digest('sha256')
        pkey = OpenSSL.crypto.PKey()
        pkey.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
        req = OpenSSL.crypto.X509Req()
        subj = req.get_subject()
        subj.countryName = 'US'
        subj.stateOrProvinceName = 'CA'
        subj.localityName = 'Santa Barbara'
        subj.organizationName = commonname
        subj.organizationalUnitName = 'CS 176B'
        subj.commonName = commonname
        req.add_extensions([OpenSSL.crypto.X509Extension(b'subjectAltName', True, b', '.join('DNS: %s' % x for x in sans))])
        req.set_pubkey(pkey)
        req.sign(pkey, ca_digest)
        cert = OpenSSL.crypto.X509()
        cert.set_version(2)
        try:
            cert.set_serial_number(self.get_cert_serial_number(commonname, ca_thumbprint))
        except OpenSSL.SSL.Error:
            cert.set_serial_number(int(time.time() * 1000))
        cert.gmtime_adj_notBefore(-600)
        cert.gmtime_adj_notAfter(60 * 60 * 24 * 3652)
        cert.set_issuer(ca.get_subject())
        cert.set_subject(req.get_subject())
        cert.set_pubkey(req.get_pubkey())
        cert.add_extensions([OpenSSL.crypto.X509Extension(b'subjectAltName', True, b', '.join('DNS: %s' % x for x in sans))])
        cert.sign(key, ca_digest)
        certfile = os.path.join(CERTS_DIR, commonname + '.crt')
        with open(certfile, 'wb') as f:
            f.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, pkey))
            f.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert))
            f.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, ca))
        return certfile


    def get_cert_serial_number(self, commonname, ca_thumbprint):
        assert ca_thumbprint
        saltname = '%s|%s' % (ca_thumbprint, commonname)
        return int(hashlib.md5(saltname.encode('utf-8')).hexdigest(), 16)


def main():
    assert sys.version_info >= (2, 7, 5)
    parser = argparse.ArgumentParser(description='Man-in-the-Middle HTTPS proxy server.',
                                     prog='mproxy')
    parser.add_argument('-v', '--version',
                        action='version',
                        version='%(prog)s 0.1 Copyright (C) 2016 Brandon Hammel',
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
    if not os.path.exists(CERTS_DIR):
        try:
            os.makedirs(CERTS_DIR)
        except OSError as ex:
            if ex.errno != errno.EEXIST:
                raise
    proxy = Proxy(args.port, args.numworker, args.timeout, logdir)
    proxy.start()


if __name__ == '__main__':
    main()
