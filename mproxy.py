import argparse
import logging
import os
import select
import socket
import string
import sys
import threading

def print_and_exit(status, message):
    print(str(message))
    sys.exit(status)

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
    print("Logfile: " + str(args.log))

if __name__ == "__main__":
    try:
        main()
    except:
        print(traceback.format_exc())
