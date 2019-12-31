#!/usr/bin/python
#
# Copyright (C) 2019 Wonjun Jung
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#

import traceback
import json
import os
import requests
import wget
import pexpect
import sys
import socks
import base64
import hashlib

class psi_server:
    def __init__(self, hexdata):
        # parse datas from hex-encoded string.
        data = json.loads(bytearray.fromhex(hexdata).split()[-1])
        
        self.region = data['region']

        self.ipaddr = data['ipAddress']

        # These will be used when connecting to SSH server.
        # pretty basic things
        self.sshport = data['sshPort']
        self.sshuser = data['sshUsername']
        self.sshpwd = data['sshPassword']
        self.sshkey = data['sshHostKey']

        # These will be used when user is connecting to the VPN server
        # using obfuscated SSH, which is not supported by basic openssh
        # binary. which means we have to build modified ssh binary,
        # which is quite hard because it uses older version of libssl
        # so I guess I'll just leave it here.
        self.sshobfuscatedport = data['sshObfuscatedPort']
        self.sshobfuscatedkey = data['sshObfuscatedKey']

        # Frankly, We have to access its webserver to use SSH server.
        # Without it, we won't be able to open a tunnel as they won't
        # allow us to do anything. These datas are used while handshake.
        self.webport = data['webServerPort']
        self.websecret = data['webServerSecret']
        self.webcert = data['webServerCertificate']

        # tbh I Really have no idea about what this is
        # but it seems like they don't check if it's legit,
        # They're just checking if it's hex string lmao
        self.propchanid = "FFFFFFFFFFFFFFFF"
        self.sponsorid = "FFFFFFFFFFFFFFFF"

        # session is just 16 byte random string, encoded with hex.
        self.sessionid = bytearray(os.urandom(16)).hex()

        self.handshake_done = False
    def handshake(self, relay = "SSH", cli_ver = "1", cli_platform = "Python", servers = []):
        # server_secret, propagation_channel_id, sponsor_id, client_version, client_platform, relay_protocol
        # MAN THIS ADDRESS IS FUCKING HUGE
        address = '''\
        https://{}:{}/handshake?server_secret={}&propagation_channel_id={}&sponsor_id={}&client_version={}&client_platform={}&relay_protocol={}&client_session_id={}'''\
        .format(self.ipaddr, self.webport, self.websecret, self.propchanid, self.sponsorid, cli_ver, cli_platform, relay, self.sessionid)\
        + "known_server=" + "&known_server=".join(servers)
        print("Attempting Handshake to {}:{}, Relay Protocol:{}".format(self.ipaddr, self.webport, relay))
        try:
            self.handshake_result = requests.get(address, verify = False, proxies={"http": "socks5://127.0.0.1:1080", "https": "socks5://127.0.0.1:1080"})
            if self.handshake_result.status_code != 200:
                print("Error: Handshake Failed, Status Code: " + str(self.handshake_result.status_code))
                self.handshake_done = False
            else:
                print("Handshake Successful")
                self.handshake_done = True
        except Exception as e:
            print("Error: Handshake Failed.")
            print(type(e).__name__ + ": " + str(e))
            self.handshake_done = False

    def SSHconnect(self, socksport = 1080):
        cmd = "ssh -C -D 127.0.0.1:{} -N -p {} {}@{}".format(
            socksport, self.sshport, self.sshuser, self.ipaddr)
        pwd = self.sessionid + self.sshpwd

        # calculate SHA256 base64-encoded fingerprint from SSH host key
        # https://stackoverflow.com/questions/56769749/calculate-ssh-public-key-fingerprint-into-base64-why-do-i-have-an-extra
        fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(base64.b64decode(self.sshkey)).digest()).decode()[:-1]
        fingerprint = "fingerprint"

        print(fingerprint)

        self.ssh = pexpect.spawn(cmd)
        self.ssh.logfile = sys.stdout.buffer
        expectrtn = self.ssh.expect(["[pP]assword", fingerprint])
        print(expectrtn)
        if expectrtn:
            self.ssh.sendline("yes")
            self.ssh.expect("[pP]assword")
            self.ssh.sendline(pwd)
            print("password sent")
        else:
            self.ssh.sendline(pwd)
            print("password sent")

        print("Connection Established.")
        print("Server Region:", self.region)

def update_server_list(url = "https://psiphon3.com/server_list"):
    os.rename("server_list", ".server_list")
    try:
        wget.download(url)
        os.remove(".server_list")
    except Exception as e:
        print("Error: Failed to download " + url + ".")
        print(type(e).__name__ + ": " + str(e))
        os.rename(".server_list", "server_list")

def load_server_list():
    file = open("server_list").read()
    svlist = json.loads(file)['data'].split("\n")
    return list(map(lambda x:  psi_server(x), svlist))

update_server_list()
test = load_server_list()
for x in range(len(test)):
    print(str(x) + " ", end = "")
    x = test[x]
    print(x.ipaddr, x.webport, x.region)

x = int(input())

print("ssh -C -D 127.0.0.1:1080 -N -p {} {}@{}\nPassword: {}{}".format(
    test[x].sshport, test[x].sshuser, test[x].ipaddr, test[x].sessionid, test[x].sshpwd))

test[x].SSHconnect()
try:
    test[x].handshake(servers = list(map(lambda x:  x.ipaddr, test)))
except Exception as e:
    print(type(e).__name__ + ": " + str(e))

print(test[x].ssh)

input()