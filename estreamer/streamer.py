#local lib
import config

#standard libs
from six import raise_from
import socket
import traceback
import sys
import struct

#pypi libs
import OpenSSL.crypto as crypto
from OpenSSL import SSL

class Error(Exception): pass
class eStreamerKeyError(Error): pass
class eStreamerCertError(Error): pass
class eStreamerVerifyError(Error): pass


'''
    :host = eStreamer host
    :port = eStreamer port (default: 8302)
    :cert_path = cert file (string/path to, not file handle)
    :pkey_path = private key file (string / path to, not file handle)
    :pkey_passphase = passphrase for private key file
    :verify - PEM file to verify host
'''
class eStreamerConnection(object):


    def __init__(self, host, port, verify, cert_path, pkey_path, pkey_passphrase=''):
        self.host = host
        self.port = port
        try:
            self.pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, open(pkey_path, 'rb').read(), pkey_passphrase)
        except IOError:
            raise eStreamerKeyError("Unable to locate key file {}".format(pkey_path))
        except crypto.Error:
            raise eStreamerKeyError("Invalid key file or bad passphrase {}".format(cert_path))
        try:
            self.cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(cert_path, 'rb').read())
        except IOError:
            raise eStreamerCertError("Unable to locate cert file {}".format(cert_path))
        except crypto.Error:
            raise eStreamerCertError("Invalid certificate {}".format(cert_path))
        self.verify = verify
        self.ctx = None
        self.sock = None
        self._bytes = None

    def __enter__(self):
        self.ctx = SSL.Context(SSL.TLSv1_METHOD)
        self.ctx.set_verify(SSL.VERIFY_PEER, self.validate_cert)
        self.ctx.use_privatekey(self.pkey)
        self.ctx.use_certificate(self.cert)
        self.ctx.load_verify_locations(self.verify)
        self.trusted_cert = crypto.load_certificate(crypto.FILETYPE_PEM, file(self.verify).read())
        self.sock = SSL.Connection(self.ctx, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        self.sock.connect((self.host, self.port))
        return self

    def __exit__(self, exc_type, exc_al, exc_tb):
        self.close()

    def validate_cert(self, conn, cert, errnum, depth, ok):
        # just handle the self-signed use case
        if not ok and errnum == 19:
            if cert.get_pubkey() == self.trusted_cert.get_pubkey() and cert.get_issuer() == self.trusted_cert.get_issuer():
                if not cert.has_expired():
                    return 1
        return ok

    def close(self):
        self.sock.shutdown()
        self.sock.close()

    @property
    def bytes(self):
        return self._bytes

    @bytes.setter
    def bytes(self, buf):
        self._bytes = value

    def request(self, buf):
        try:
            self.sock.send(buf)
        except SSL.Error as exc:
            raise_from(Error("SSL Error"), exc)
        else:
            try:
                #peek_bytes = self.sock.recv(8, socket.MSG_PEEK) # peeky no worky?!
                peek_bytes = self.sock.recv(8)
            except SSL.Error as exc:
                raise
                #raise_from(Error("SSL Error"), exc)
            else:
                (ver, type_, length) = struct.unpack('>HHL', peek_bytes)
                return bytearray(peek_bytes + self.sock.recv(length))

    def response(self):
        try:
            peek_bytes = self.sock.recv(8, socket.MSG_PEEK)
        except SSL.Error as exc:
            raise_from(Error("SSL Error"), exc)
        else:
            (ver, type_, length) = struct.unpack('>HHL', peek_bytes)
            return bytearray(peek_bytes + self.sock.recv(length))
