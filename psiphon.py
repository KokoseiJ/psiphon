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
import socket
import base64
import hashlib
import time

requests.packages.urllib3.disable_warnings() 

class psi_server:
    def __init__(self, rawdata):
        # parse datas from hex-encoded string.
        data = json.loads(rawdata)
        
        # List of the protocol that server supports.
        self.capabilities = data['capabilities']

        # This contains the region of the server.
        self.region = data['region']

        # quite obvious tho. it's just IP address
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

        self.rawdata = rawdata
        
    def handshake(self, relay = "SSH", cli_ver = "1", cli_platform = "Python", servers = []):
        # MAN THIS ADDRESS IS FUCKING HUGE
        # format the address in the right way, and add bunch of
        # known_server parameters.
        address = "https://{}:{}/handshake?server_secret={}&propagation_channel_id={}&sponsor_id={}&client_version={}&client_platform={}&relay_protocol={}&client_session_id={}"\
        .format(self.ipaddr, self.webport, self.websecret, self.propchanid, self.sponsorid, cli_ver, cli_platform, relay, self.sessionid)\
        + "&known_server=" + self.ipaddr#"&known_server=".join(servers)
        print("Attempting Handshake to {}:{}, Relay Protocol:{}".format(self.ipaddr, self.webport, relay))
        # Let's connect to the web server!
        try:
            # We have to send a request through the SOCKS proxy.
            # also, You should set verify argument to False as all of
            # those web servers are self signed.
            # I should find another method to verify the server's
            # certificate tho
            self.handshake_result = requests.get(address, verify = False, proxies={"http": "socks5://127.0.0.1:1080", "https": "socks5://127.0.0.1:1080"})
            if self.handshake_result.status_code == 200:
                print("Handshake Successful")
                self.handshake_done = True
                return 0
            else:
                print("Error: Handshake Failed, Status Code: " + str(self.handshake_result.status_code))
                self.handshake_done = False
                return 1
        except Exception as e:
            print("Error: Handshake Failed.")
            self.handshake_done = False
            return 1

    def SSHconnect(self, socksport = 1080):
        # Generate a ssh command that opens a SOCKS proxy Through SSH.
        cmd = "ssh -C -D 127.0.0.1:{} -N -p {} {}@{}".format(
            socksport, self.sshport, self.sshuser, self.ipaddr)
        # Basically password is session id + password
        pwd = self.sessionid + self.sshpwd

        # calculate SHA256 base64-encoded fingerprint from SSH host key
        # https://stackoverflow.com/questions/56769749/calculate-ssh-public-key-fingerprint-into-base64-why-do-i-have-an-extra
        fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(base64.b64decode(self.sshkey)).digest()).decode()[:-1]
        # It doesn't work for some reason, I have to find another way
        # to verify it.
        fingerprint = "fingerprint"

        # Spawn a process with the command.
        print("Connecting to " + self.ipaddr + "...")
        try:
            self.ssh = pexpect.spawn(cmd)
            # Prints log
            # self.ssh.logfile = sys.stdout.buffer
    
            # Check if we need to check fingerprint or input Password
            expectrtn = self.ssh.expect(["[pP]assword", fingerprint])
            if expectrtn:
                self.ssh.sendline("yes")
                self.ssh.expect("[pP]assword")
                self.ssh.sendline(pwd)
            else:
                self.ssh.sendline(pwd)
        except Exception as e:
            print("Error: Failed to connect to the SSH server.")
            print(type(e).__name__ + ": " + str(e))
            return 1
        # Check if the SOCKS server are opened.
        print("Checking Connection...")
        for x in range(3):
            try:
                socket.socket().connect(("127.0.0.1", socksport))
                # If it's able to connect to the SOCKS server,
                # it will return and escape the function
                print("Connection Established.\nSOCKS5 opened at 127.0.0.1:" + str(socksport))
                print("Server Region:", self.region)
                return 0
            except Exception as e:
                time.sleep(1)
        # If it wasn't able to connect to the SOCKS server,
        # It will raise Exception
        print("Error: SOCKS5 server time out")
        self.ssh.terminate(force=True)
        return 1

    def wait_disconnect(self, interact = True):
        print("Press CTRL + C to terminate.")
        try:
            if interact:
                input()
                return 1
            else:
                self.ssh.wait()
                print("Error: SSH disconnected unexpectedly.")
        except KeyboardInterrupt:
            print("Terminating SSH session...")
            self.ssh.terminate(force=True)
        return 0

class server_list:
    @classmethod
    def load(cls):
        try:
            file = open("servers.dat").read()
            svlist = file.split("\n")
            cls.list = list(map(lambda x:  psi_server(x), svlist))
            cls.cursv = None
        except Exception as e:
            print("Error: Failed to load the servers.dat file.")
            print(type(e).__name__ + ": " + str(e))
            exit(1)
        return

    @classmethod
    def get(cls, region = False, relay = "SSH"):
        for numb, sv in zip(range(len(cls.list)), cls.list):
            if relay in sv.capabilities and ((not region) or sv.region == region):
                cls.cursv = numb
                return sv
        print("Error: Can't find " + region + " server that supports " + relay)
        exit(1)

    @classmethod
    def get_ip_list(cls):
        return tuple(map(lambda x:  x.ipaddr, cls.list))

    @classmethod
    def pop_server(cls):
        cls.list.append(cls.list.pop(cls.cursv))
        generate_servers_dat(data = list(map(lambda x:  x.rawdata, cls.list)))
        return

    @classmethod
    def get_region_list(cls):
        rtnlist = []
        for x in cls.list:
            if not x.region in rtnlist:
                rtnlist.append(x.region)
        return rtnlist

def update_server_list(url = "https://psiphon3.com/server_list"):
    try:
        # Back up the previous server_list file
        os.rename("server_list", ".server_list")
        # Download the file
        wget.download(url)
        # if it was successful, delete backed up file
        os.remove(".server_list")
    except Exception as e:
        print("Error: Failed to download " + url + ".")
        print(type(e).__name__ + ": " + str(e))
        # Restore the backed up file
        os.rename(".server_list", "server_list")

def generate_servers_dat(data = None):
    try:
        os.rename("servers.dat", ".servers.dat")
        if data:
            rtnlist = data
        else:
            svlist = open("server_list").read()
            rtnlist = map(lambda x:  bytearray.fromhex(x).decode().split()[-1], json.loads(svlist)['data'].split("\n"))
        open("servers.dat", "w").write("\n".join(rtnlist))
        print("Succesfully generated servers.dat file.")
        return
    except Exception as e:
        print("Error: Failed to generate servers.dat.")
        print(type(e).__name__ + ": " + str(e))
        os.rename(".servers.dat", "servers.dat")
        return

if __name__ == "__main__":
    if input("Update server_list file?(y/n): ") == "y":
        update_server_list()
        generate_servers_dat()

    server_list.load()

    print("List of the region is:")
    rglist = requests.get("http://country.io/names.json").json()
    for x in server_list.get_region_list():
        print(x, ":", rglist[x])

    region = input("Enter your region code or leave it blank to set it to ANY: ")
    if not region:
        region = False

    while True:
        server = server_list.get(region = region)
        if server.SSHconnect():
            server_list.pop_server()
            continue
        elif server.handshake(servers = server_list.get_ip_list()):
            server_list.pop_server()
            continue
        elif server.wait_disconnect():
            server_list.pop_server()
            continue
        exit(1)


# All the codes below were for testing
"""
def load_server_list():
    file = open("server_list").read()
    svlist = json.loads(file)['data'].split("\n")
    return list(map(lambda x:  psi_server(bytearray.fromhex(x).decode().split()[-1]), svlist))

if __name__ == "__main__":
    update_server_list()
    test = load_server_list()
    for x in range(len(test)):
        print(str(x), end = " ")
        x = test[x]
        print(x.ipaddr, x.webport, x.region)

    x = test[int(input())]
    x.SSHconnect() 
    try:
        x.handshake(servers = list(map(lambda x:  x.ipaddr, test)))
    except Exception as e:
        print(type(e).__name__ + ": " + str(e))
    input()
else:
    update_server_list
    svlist = load_server_list()
"""