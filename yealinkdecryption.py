#!/usr/bin/python3

from Yealink import Yealink
import getopt
import sys
import base64
from os.path import exists, join, basename
from os import makedirs
import string
import random

def help():
  print("Usage: ")
  print("%s -p[--private] privatekeyfile -a aeskey -i[--infile=] inputfilename -m mode [auto,aes,legacy]"%(sys.argv[0]))

privateKeyFile = None
inputFile      = None
outputFile     = None
aesKey         = None
mode           = 'auto'

options, arguments = getopt.getopt(
                sys.argv[1:],
                'i:a:p:m:h',
                ["infile=", "aes=", "private=", "mode=", "help"])
for o, a in options:
  if o in ("-i", "--infile"):
    inputFile = a
  if o in ("-p", "--private"):
    privateKeyFile = a
  if o in ("-a", "--aes"):
    aesKey = a
  if o in ("-m", "--mode"):
    mode = a
  if o in ("-h", "--help"):
      help()
      sys.exit()

if inputFile is None or mode not in ['rsa', 'legacy', 'auto']:
  help()
  sys.exit(0)

if not exists(inputFile):
  print("Unable to locate inputfile: %s"%(inputFile))
  sys.exit(0)

yealink = Yealink()

provisioningFile = None
with open(inputFile, mode='rb') as input_file:
  provisioningFile = input_file.read()

guessedMode = None
try:
  if 'key_signatue' in provisioningFile.decode() and '---BEGIN CONFIG DATA---' in provisioningFile.decode():
    guessedMode = 'rsa'
  else:
    guessedMode = 'legacy'
except:
  guessedMode = 'legacy'

if guessedMode != mode and mode != 'auto':
  print("Requested mode %s, but detected mode is: %s!"%(mode, guessedMode))

if mode == 'auto' and guessedMode is None:
  print( "Unable to detect encryption mode! Exiting..." )
  sys.exit(0)
else:
  mode = guessedMode

if mode == 'rsa':
  print("INFO: using RSA mode")

  if privateKeyFile is None:
    print("No private keyfile specified. Using default Yealink private key!")

  #print( "Encrypted AES key in base64 format: %s"%( yealink.extractAesKey(provisioningFile.decode(), keepBase64=True) ) )
  #print( "Encrypted provisioning file in base64 format: %s"%( yealink.extractConfig(provisioningFile.decode(), mode='RSA', keepBase64=True) ) )
  aesKey = yealink.RSADecrypt(yealink.extractAesKey(provisioningFile.decode()))
  print( "AES key found: %s"%(aesKey.decode()) )
  print("Decrypting provisiong file...")

  config = yealink.decryptAesEcb( yealink.extractConfig(provisioningFile.decode()), aesKey, padding=False )
  print( "%s"%(config.decode()) )
if mode == 'legacy':
  print("INFO: using legacy mode")

  if aesKey is None:
    print("No AES key specifed. Using default Yealink AES key!")

  aesKey = None
  basefilename = '.'.join(basename(inputFile).split('.')[:-1] )
  with open(basefilename+"_Security.enc", 'rb') as f:
    aesKey = yealink.decryptAesEcb( f.read(), yealink.legacyAESkey, padding=False )
  print("Found AES key: %s"%(aesKey.decode()) )

  config = yealink.decryptAesEcb( provisioningFile, aesKey, padding=False )
  print("Decrypted provisioning file:\n%s"%(config.decode()) )

