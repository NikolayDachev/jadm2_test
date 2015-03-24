__author__ = 'dako'

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

logfile = "aesnetserver.log"

class AesNetServer:

   def __init__(self, host = None, port = None, secret = None, cmdname = None):
       self.host = host
       self.port = int(port)
       self.secret = secret
       if cmdname:
          self.data = cmdname[0]
          self.binfile = cmdname[1]

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
         log(0, "server was bind to '%s:%s' with pass: %s" % (self.host, self.port, pwd), 1)
      except:
         log(2, "cant bind '%s:%s' address" % (self.host, self.port), 1)
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
                try:
#In Windows, sometimes when a TCP program closes abruptly,
# a "Connection reset by peer" exception will be thrown
                    self.data = sock.recv(self.RECV_BUFFER)
                    self.decData = self.aes(pwd, 'dec', self.data)
                    # echo back the client message
                    if self.data:
# shutdown server if receive 'closecon'
                        if self.decData == 'closecon':
                           self.log(1, "server was stopped by '%s:%s'!" % (addr[0], addr[1]), 1)
                           s.close()
                           return False

                        if isbin == 1:
                           buf = open('%s' % self.name, 'w')
                           buf.write(self.decData)
                           buf.close()

                        else:
                           data = self.decData.split(' ')

                        if self.decData == 'isbin':
                            isbin = 1

                        if self.decData == 'no_isbin':
                            isbin = 0

                        sock.send(self.data)
# client disconnected, so remove from socket list
                except:
                    self.log(2, "'%s:%s' client is offline!" % (addr[0], addr[1]), 1)
                    sock.close()
                    CONNECTION_LIST.remove(sock)
                    continue

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
# send jadm cmd

      encData = self.aes(self.secret, 'enc', self.data)
# send bin file
      if self.data == "binfile":
         self.log(0, "transfer '%s' to '%s:%s'" % (self.binfile, self.host, self.remote_path))
         send_file = open(self.binfile, "rb")
         while True:
            chunk = send_file.read(65536)
            encData = self.aes(self.secret, 'enc', chunk)
            if not chunk:
               break  # EOF
            self.cs.sendall(encData)

      self.cs.send(encData)
      rcvData = self.cs.recv(1024)

      self.cs.shutdown(socket.SHUT_RDWR)
      self.cs.close()
      self.log(0, "transfer to '%s' was finished!" % self.host, 1)
      return '0'

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