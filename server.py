#!/usr/bin/env python

import sys
import os
import logging
import subprocess
from Crypto.Cipher import AES
import base64
import string
import random
import socket
import select

logfile = "/tmp/aesnetserver.log"
host = '0.0.0.0'
port = 4555
secret = None
data = None

class AesNetServer:

   def __init__(self, host = None, port = None, secret = None, cmdname = None):
       self.host = host
       self.port = int(port)
       self.secret = secret
       self.data = cmdname

   def server(self):
      '''
########################################################################################
#       recv aes encypted data
#
      '''
#     gen random enc password 'pwd'
      pwd = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase + string.digits) for _ in range(16))

      CONNECTION_LIST = []    # list of socket clients
      self.RECV_BUFFER = 4096 # Advisable to keep it as an exponent of 2
      isbin = 0

      try:
         s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
         s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
         s.bind((self.host, self.port))
         s.listen(10)
         self.log(0, "server was bind to '%s:%s' with pass: %s" % (self.host, self.port, pwd), 1)
      except:
         self.log(2, "cant bind '%s:%s' address" % (self.host, self.port), 1)
         return False

# Add server socket to the list of readable connections
      CONNECTION_LIST.append(s)

      while 1:
# Get the list sockets which are ready to be read through select
         read_sockets,write_sockets,error_sockets = select.select(CONNECTION_LIST,[],[])
         for sock in read_sockets:
#New connection
            if sock == s:
                # Handle the case in which there is a new connection recieved through server_socket
                sockfd, addr = s.accept()
                CONNECTION_LIST.append(sockfd)
                self.log(0, "server is connected by: '%s:%s'" % (addr[0], addr[1]), 1)
#Some incoming message from a client
            else:
# Data recieved from client, process it
      #          try:
                    if isbin == 1:
                          while True:
                             recvdata = sock.recv(self.RECV_BUFFER)
                             if not recvdata:
                                 break
                             self.decData = self.aes(pwd, 'dec', recvdata)
                             buf.write(self.decData)
                          isbin = 0
                          buf.close()
                    else:
#In Windows, sometimes when a TCP program closes abruptly,
# a "Connection reset by peer" exception will be thrown
                       recvdata = sock.recv(self.RECV_BUFFER)
                       self.decData = self.aes(pwd, 'dec', recvdata)
# echo back the client message
                       if recvdata:
                           data = self.decData.split(' ')

# shutdown server if receive 'closecon'
                           if data[-1] == 'closecon':
                              self.log(1, "server was stopped by '%s:%s'!" % (addr[0], addr[1]), 1)
                              s.close()
                              return False

                           elif data[0] == 'binfile':
                              isbin = 1
                              buf = open('/tmp/%s' % data[1], 'wb')
                           else:
                              for i in data:
                                 print "recv data: %s" % i

                    sock.send(recvdata)
# client disconnected, so remove from socket list
     #           except:
     #               self.log(2, "'%s:%s' client is offline!" % (addr[0], addr[1]), 1)
     #               sock.close()
     #               CONNECTION_LIST.remove(sock)
     #               continue

# close socket server
      s.close()

   def client(self):
      '''
########################################################################################
#       send aes encrypted data
#
      '''
# ENC
      if len(self.secret) != 16:
         return self.log(2, "server password should be 16 symbols, current is: %s" % len(self.secret))

      try:
         self.cs = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
         self.cs.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
         self.cs.connect((self.host, self.port))
      except socket.error:
         self.log(2, "no connection to %s:%s" % (self.host, self.port))
         return '1'
# ENC and SEND

      encData = self.aes(self.secret, 'enc', ' '.join(self.data))
# send bin file
      self.cs.send(encData)
      rcvData = self.cs.recv(1024)

      if self.data[0] == "binfile":
         self.log(0, "transfer '%s' to '%s'" % (self.data[2], self.host))
         send_file = open(self.data[2], "rb")
         while True:
            chunk = send_file.read(4096)
            if not chunk:
               break  # EOF
            encData = self.aes(self.secret, 'enc', chunk)
            self.cs.sendall(encData)

      self.cs.shutdown(socket.SHUT_RDWR)
      self.cs.close()
      self.log(0, "transfer to '%s' was finished!" % self.host, 1)

   def aes(self, secret, encdec, data):
      '''
########################################################################################
#   Original src: http://www.codekoala.com/posts/aes-encryption-python-using-pycrypto/
#
      '''
# the block size for the cipher object; must be 16, 24, or 32 for AES
      BLOCK_SIZE = 32

# the character used for padding--with a block cipher such as AES, the value
# you encrypt must be a multiple of BLOCK_SIZE in length.  This character is
# used to ensure that your value is always a multiple of BLOCK_SIZE
      PADDING = '{'

# one-liner to sufficiently pad the text to be encrypted
      pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING

# one-liners to encrypt/encode and decrypt/decode a string
# encrypt with AES, encode with base64
      EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
      DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)

# create a cipher object using the random secret
      cipher = AES.new(secret)

      if encdec == 'enc':
 # encode a string
         encoded = EncodeAES(cipher, data)
         return encoded

      if encdec == 'dec':
# decode the encoded string
         decoded = DecodeAES(cipher, data)
         return decoded

   def log(self, ltype, msg, logit = None):
      """
########################################################################################
# print msg and log it if is needed
# log([0 - INFO, 1 = WARRNING and 2 - ERROR], 'log message'
#
      """
      logtype = ['INFO', 'WARNING', 'ERROR']
      print "	%s: %s" % (logtype[ltype], msg)

      if logit != None:
         logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', level=logging.DEBUG, filename=logfile)
         if ltype == 0:
            logging.info('   %s' % msg)
         if ltype == 1:
            logging.warning(msg)
         if ltype == 2:
            logging.error('  %s' % msg)

if '__main__' == __name__:

    if len(sys.argv) < 2:
        sys.exit(2)

    if len(sys.argv) >= 3:
        host = sys.argv[2]
    if len(sys.argv) >= 4:
        port = int(sys.argv[3])
    if len(sys.argv) >= 5:
        secret = sys.argv[4]
    if len(sys.argv) >= 6:
        data = sys.argv[5:]

    if sys.argv[1] == 'server':
        ans = AesNetServer(host, port)
        ans.server()

    elif sys.argv[1] == 'client':
        ans = AesNetServer(host, port, secret, data)
        ans.client()

    else:
        sys.exit(2)
