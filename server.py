# -*- coding: utf-8 -*-

# Copyright (c) 2012 clowwindy
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import socket
import select
import SocketServer
import struct
import string
import hashlib

PORT = 8499
KEY = "foobar!"


#: 具体分析见file:`~.local.py`
#: 采用对称加密，故加密、解密算法与local端保持一致
def get_table(key):
    m = hashlib.md5()
    m.update(key)
    s = m.digest()
    (a, b) = struct.unpack('<QQ', s)
    table = [c for c in string.maketrans('', '')]
    for i in xrange(1, 1024):
        table.sort(lambda x, y: int(a % (ord(x) + i) - a % (ord(y) + i)))
    return table


class ThreadingTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass


class Socks5Server(SocketServer.StreamRequestHandler):

    def handle_tcp(self, sock, remote):
        fdset = [sock, remote]
        while True:
            r, w, e = select.select(fdset, [], [])
            #: 来自local的请求流
            if sock in r:
                if remote.send(self.decrypt(sock.recv(4096))) <= 0:
                    break
            #: 远端响应流
            if remote in r:
                if sock.send(self.encrypt(remote.recv(4096))) <= 0:
                    break

    def encrypt(self, data):
        return data.translate(encrypt_table)

    def decrypt(self, data):
        return data.translate(decrypt_table)

    def send_encrpyt(self, sock, data):
        sock.send(self.encrypt(data))

    def handle(self):
        try:
            print 'socks connection from ', self.client_address
            sock = self.connection

            #: 用户端本地进程在连接上local进程时，会先发一个握手数据包
            #: local将握手包转发给SOCKS server
            #: SOCKS server应答一个`0x0500`数据包
            #: 05: 协议版本号；00: 无需认证
            #:
            #: +----+--------+
            #: |VER | METHOD |
            #: +----+--------+
            #: | 1  |   1    |
            #: +----+--------+
            #:
            sock.recv(262)
            self.send_encrpyt(sock, "\x05\x00")

            #: 来自用户进程（由local代理）的第二个数据包
            data = self.decrypt(self.rfile.read(4))
            #: `CMD` field
            #: - CONNECT       0x01
            #: - BIND          0x02
            #: - UDP ASSOCIATE 0x03
            mode = ord(data[1])
            #: `ATYP` field, 地址类别
            #: - IP V4 address: 0x01
            #: - DOMAINNAME:    0x03
            #: - IP V6 address: 0x04
            addrtype = ord(data[3])

            #: IP V4地址
            if addrtype == 1:
                addr = socket.inet_ntoa(self.decrypt(self.rfile.read(4)))
            #: 域名
            elif addrtype == 3:
                #: 地址域的第一个字节为域名的长度
                domain_len = ord(self.decrypt(sock.recv(1)))
                addr = self.decrypt(self.rfile.read(domain_len))
            else:
                # not support IP V6
                return
            #: 端口号
            port = struct.unpack('>H', self.decrypt(self.rfile.read(2)))

            #: Replies
            #:
            #: +----+-----+-------+------+----------+----------+
            #: |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
            #: +----+-----+-------+------+----------+----------+
            #: | 1  |  1  | X'00' |  1   | Variable |    2     |
            #: +----+-----+-------+------+----------+----------+
            #:
            #: `REP` Reply field:
            #: - 0x00 succeeded
            #: - 0x01 general SOCKS server failure
            #: - 0x02 connection not allowed by ruleset
            #: - 0x03 Network unreachable
            #: - 0x04 Host unreachable
            #: - 0x05 Connection refused
            #: - 0x06 TTL expired
            #: - 0x07 Command not supported
            #: - 0x08 Address type not supported
            #: - 0x09 to 0xFF unassigned
            reply = "\x05\x00\x00\x01"
            try:
                if mode == 1:
                    #: 连接至目标服务器
                    remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    remote.connect((addr, port[0]))
                    local = remote.getsockname()
                    reply += socket.inet_aton(
                        local[0]) + struct.pack(">H", local[1])
                    print 'Tcp connect to', addr, port[0]
                else:
                    reply = "\x05\x07\x00\x01"  # Command not supported
                    print 'command not supported'
            except socket.error:
                # Connection refused
                reply = '\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00'
            #: 响应local
            self.send_encrpyt(sock, reply)

            #: 后续真实请求处理
            if reply[1] == '\x00':
                if mode == 1:
                    self.handle_tcp(sock, remote)
        except socket.error:
            print 'socket error'


def main():
    server = ThreadingTCPServer(('', PORT), Socks5Server)
    server.allow_reuse_address = True
    print "starting server at port %d ..." % PORT
    server.serve_forever()


if __name__ == '__main__':
    encrypt_table = ''.join(get_table(KEY))
    decrypt_table = string.maketrans(encrypt_table, string.maketrans('', ''))
    main()
