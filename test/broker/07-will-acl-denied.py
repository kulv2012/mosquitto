#!/usr/bin/env python

import subprocess
import socket
import time

import inspect, os, sys
# From http://stackoverflow.com/questions/279237/python-import-a-module-from-a-folder
cmd_subfolder = os.path.realpath(os.path.abspath(os.path.join(os.path.split(inspect.getfile( inspect.currentframe() ))[0],"..")))
if cmd_subfolder not in sys.path:
    sys.path.insert(0, cmd_subfolder)

import mosq_test

rc = 1
mid = 53
keepalive = 60
connect_packet_ok = mosq_test.gen_connect("will-acl-test", keepalive=keepalive, will_topic="ok", will_payload="should be ok")
connack_packet_ok = mosq_test.gen_connack(rc=0)

connect_packet = mosq_test.gen_connect("will-acl-test", keepalive=keepalive, will_topic="will/acl/test", will_payload="should be denied")
connack_packet = mosq_test.gen_connack(rc=5)

broker = subprocess.Popen(['../../src/mosquitto', '-c', '07-will-acl-denied.conf'], stderr=subprocess.PIPE)

try:
    time.sleep(0.5)

    sock_ok = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_ok.settimeout(5)
    sock_ok.connect(("localhost", 1888))
    sock_ok.send(connect_packet_ok)
    sock = None

    if mosq_test.expect_packet(sock_ok, "connack_ok", connack_packet_ok):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(("localhost", 1888))
        sock.send(connect_packet)

        if mosq_test.expect_packet(sock, "connack", connack_packet):
            rc = 0

    sock_ok.close()
    if sock:
        sock.close()

finally:
    broker.terminate()
    broker.wait()
    if rc:
        (stdo, stde) = broker.communicate()
        print(stde)

exit(rc)

