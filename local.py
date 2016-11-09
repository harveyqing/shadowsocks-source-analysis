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
import string
import struct
import hashlib
import threading
import time
import SocketServer

SERVER = 'localhost'
REMOTE_PORT = 8499
PORT = 1081
KEY = "foobar!"


def get_table(key):
    #: 给加密串计算MD5签名
    m = hashlib.md5()
    m.update(key)
    s = m.digest()
    (a, b) = struct.unpack('<QQ', s)

    #: 生成所有字节字符列表
    #: 等价于`map(chr, range(256))`
    table = [c for c in string.maketrans('', '')]

    #: 生成一个字符翻译表，用以`加密`tcp/udp字节流
    #: 一旦加密算法泄露，就能通过解密还原来监测原始数据包
    for i in xrange(1, 1024):
        table.sort(lambda x, y: int(a % (ord(x) + i) - a % (ord(y) + i)))
    return table


#: 加密表
encrypt_table = ''.join(get_table(KEY))
#: 解密表
decrypt_table = string.maketrans(encrypt_table, string.maketrans('', ''))

my_lock = threading.Lock()


#: server采用了多线程模型
def lock_print(msg):
    my_lock.acquire()
    try:
        print "[%s]%s" % (time.ctime(), msg)
    finally:
        my_lock.release()


#: SOCKS代理对于其客户端来说也是一个server
#: 对于SOCKS server来说其为client
class ThreadingTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass


class Socks5Server(SocketServer.StreamRequestHandler):
    """
    local在这里作为代理的主要职责在于：
        - 对本地通信进程的tcp数据流进行加密并发送至server端
        - 对server端的响应数据流进行解密并转发给本地通信进程
    """

    def encrypt(self, data):
        """加密数据流"""
        return data.translate(encrypt_table)

    def decrypt(self, data):
        """解密数据流"""
        return data.translate(decrypt_table)

    def handle_tcp(self, sock, remote):
        #: 对于sock而言，可读意味着有来自客户端的request
        #: 对于remote而言，可读意味着有来自SOCKS server的response
        fdset = [sock, remote]
        counter = 0
        while True:
            r, w, e = select.select(fdset, [], [])
            #: 来自客户端的请求
            if sock in r:
                #: 根据SOCKS5协议，第一个数据包由client端发送
                #:
                #: +----+----------+----------+
                #: |VER | NMETHODS | METHODS  |
                #: +----+----------+----------+
                #: | 1  |    1     | 1 to 255 |
                #: +----+----------+----------+
                #:
                #: 如`0x050100`
                #: 注意，本地进程与local进程数据不加密
                #: 由于server端不需要加密（握手包响应`0x0500`），
                #: 故加密方法协商阶段被省去
                r_data = sock.recv(4096)

                #: 来自本地进程的第二个数据包，SOCKS request
                #:
                #: +----+-----+-------+------+----------+----------+
                #: |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
                #: +----+-----+-------+------+----------+----------+
                #: | 1  |  1  | X'00' |  1   | Variable |    2     |
                #: +----+-----+-------+------+----------+----------+
                #:
                if counter == 1:
                    try:
                        lock_print(
                            "Connecting " + r_data[5: 5 + ord(r_data[4])])
                    except Exception:
                        pass

                if counter < 2:
                    counter += 1

                #: 本地进程的真正请求数据包
                if remote.send(self.encrypt(r_data)) <= 0:
                    break

            #: 来自SOCKS server的响应
            if remote in r:
                #: SOCKS server的响应流
                remote_data = self.decrypt(remote.recv(4096))
                #: 将来自server端的响应解密后原封不动的返还给本地sock
                if sock.send(remote_data) <= 0:
                    break

    def handle(self):
        try:
            #: 来自客户端的连接
            sock = self.connection
            #: 连接至SOCKS server
            remote = socket.socket()
            remote.connect((SERVER, REMOTE_PORT))

            self.handle_tcp(sock, remote)
        except (socket.error, KeyboardInterrupt) as e:
            lock_print(e.message)
            remote.close()


def main():
    print 'Starting proxy at port %d' % PORT
    server = ThreadingTCPServer(('', PORT), Socks5Server)
    server.serve_forever()


if __name__ == '__main__':
    main()
