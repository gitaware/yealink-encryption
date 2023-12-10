import re
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class Yealink:
  def __init__(self):
    self.privateKey = None
    self.loadRSAPrivateKey(privateKey='-----BEGIN PRIVATE KEY-----\nMIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBALnpXEuyRrAi07KG\n18WqrmSbgu/SEMVj4Z3mJv9iIeuCVdnGR3PGLsT96qAXeZhTgr1cyp5BB87wPgrc\ntTt4sctPFqzbJXG4aYwRarg3Gh98a0EO3b3swCR9pvoCL0q+2ZS1Pq9vvvnlfiCv\nxGYpOC31Nhq2208VkzvRaYJRCAPNAgMBAAECgYBcdfUTKJ0DaK7EsU+K3XJSUw1x\n3JW+tgg1kYt/o/yetnmgD37l04DbNDWGXWZ6Hb5+EzIqNsl9X/pbSJ1R8JrrWzqT\nxljQnAU96JrddTIZvJZqIFSeypC6QM+DhUQjhBo8E6F7XEOygpENDTeBiJEvp3Qv\nXVCrizzCQZdPwTYbOQJBAOPyGPy0dNF87wkg2Zg3bJViqkvIkajICltrvstplCLg\nw2rzNMW4d0ml7JWPWk1MQcw4Lb+Xfk65AthRoxiB1kcCQQDQyuPxcaPgO9DXBVlZ\nmWVkSo8DDqUl7DhYORek3AtmwPkEkZP476oA3mlN/lP5zxyNft6cwLTVDOrmQyNY\nFVtLAkBIki5UXhuHCpCLxnKgXJzsXpI7OGrvYmixvHbtCfsIs6hjp3SYsmcAApx0\n7UPhsjKMkyI1ikTDSXHXbv5O8h9HAkAA0MoTJ158gb9PF7ZBo1fCDIiCeowqmcGe\nlpqBClsBC7/tRKRPVKBVYIkIxPWPBEAYTWaRNi9+pY5FV/3LWkoBAkAElr4aulEb\nPvzGXNU2q2yShXmh+4qS8ff7JZJg3gubu2hqR+P6N26zA6pxlztYmD2kEsYgH7XZ\nIsYUywG02bBg\n-----END PRIVATE KEY-----')
    self.legacyAESkey = 'EKs35XacP6eybA25'

  def generateRSAPrivateKey(self, public_exponent=65537, key_size=1024):
    self.privateKey = rsa.generate_private_key(
        public_exponent=public_exponent,
        key_size=key_size,
    )

  def loadRSAPrivateKey(self, privateKey=None, privateKeyFile=None):
    if privateKey is not None:
      if isinstance(privateKey, str):
        privateKey = privateKey.encode()
      self.privateKey = serialization.load_pem_private_key(privateKey, None, default_backend())
    elif privateKeyFile is not None:
      with open(privateKeyFile, mode='rb') as private_file:
        key_data = private_file.read()
        self.privateKey = serialization.load_pem_private_key(key_data, None, default_backend())

  def extractRSAPublicKey(self):
    return (self.privateKey).public_key()

  def serializePrivateKey(self):
    return self.privateKey.private_bytes(
               encoding=serialization.Encoding.PEM,
               format=serialization.PrivateFormat.PKCS8,
               encryption_algorithm=serialization.NoEncryption()
    )

  def serializePublicKey(self):
    return self.extractRSAPublicKey().public_bytes(
             encoding=serialization.Encoding.PEM,
             format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

  def RSAEncrypt(self, message):
    if isinstance(message, str):
      message = message.encode()

    return base64.b64encode( (self.extractRSAPublicKey()).encrypt(
      message,
      padding.PKCS1v15()
    ))

  def RSADecrypt(self, message):
    return self.privateKey.decrypt(
      message,
      padding.PKCS1v15()
      )
    #return rsa.decrypt(message, self.privateKey).decode()





  #AES
  def pkcs7_padding(self, message, block_size):
    padding_length = block_size - ( len(message) % block_size )
    if padding_length == 0:
      padding_length = block_size
    padding = bytes([padding_length]) * padding_length
    return message + padding

  def pkcs7_strip(self, data):
    padding_length = data[-1]
    return data[:- padding_length]

  def encryptAesEcb(self, msg, key, padding=False):
    if isinstance(msg, str):
      msg = msg.encode()
    if isinstance(key, str):
      key = key.encode()
    padded_msg = msg
    if padding:
      padded_msg = self.pkcs7_padding(msg, block_size=16)
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(padded_msg) + encryptor.finalize()

  def decryptAesEcb(self, ctxt, key, padding=False):
    if isinstance(ctxt, str):
      ctxt = ctxt.encode()
    if isinstance(key, str):
      key = key.encode()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data =  decryptor.update(ctxt) + decryptor.finalize()
    message = decrypted_data
    if padding:
      message = self.pkcs7_strip(decrypted_data)
    return message






  #provisioning
  def regularExtract(self, regex, string, group=0, options=re.MULTILINE):
    matches = re.search( regex, string, options)
    return matches.group(group)

  def extractAesKey(self, document, keepBase64=False):
    regex = r"#\!key_ciphertext\:([\w\+\-\/\=]+)[\r\n]+#\!\-\-\-BEGIN CONFIG DATA\-\-\-[\r\n]+([\w\+\-\/\=]+)"
    key = self.regularExtract(regex, document, 1)
    if keepBase64:
      return key
    else:
      return base64.b64decode(key)

  def extractConfig(self, document, keepBase64=False, mode='RSA'):
    if mode == 'RSA':
      regex = r"#\!key_ciphertext\:([\w\+\-\/\=]+)[\r\n]+#\!\-\-\-BEGIN CONFIG DATA\-\-\-[\r\n]+([\w\+\-\/\=]+)"
      key = self.regularExtract(regex, document, 2)
      if keepBase64:
        return key
      else:
        return base64.b64decode(key)
    if mode == 'legacy':
      regex = r"#!key_ciphertext:([\w\+\-\/\=]+)"
      key = self.regularExtract(regex, document, 1)
      if keepBase64:
        return key
      else:
        return base64.b64decode(key)



