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
  print("%s -p[--private] privatekeyfile -i[--infile=] inputfilename -d[--dir=] outputdir -m mode [rsa,legacy]"%(sys.argv[0]))
  print("Not specifying an AES key will generate a new one.")
  print("When the privatekeyfile is 'auto', it will generate a new keypair. If the privatekeyfile is not specified yealink's default keypair will be used!")

publicKeyFile  = None
privateKeyFile = None
inputFile      = None
outputFile     = None
aesKey         = None
mode           = 'rsa'

options, arguments = getopt.getopt(
                sys.argv[1:],
                'i:d:a:p:m:h',
                ["infile=", "dir=", "aeskey=", "private=", "mode=", "help"])
for o, a in options:
  if o in ("-i", "--infile"):
    inputFile = a
  if o in ("-d", "--dir"):
    outDir = a
  if o in ("-a", "--aeskey"):
    aesKey = a
  if o in ("-p", "--private"):
    privateKeyFile = a
  #if o in ("-P", "--public"):
  #  publicKeyFile = a
  if o in ("-m", "--mode"):
    mode = a
  if o in ("-h", "--help"):
      help()
      sys.exit()

if inputFile is None or outDir is None or mode not in ['rsa', 'legacy']:
  help()
  sys.exit(0)

if aesKey is None:
  print("No AES key specified. Generating new one...")
  length=32
  if mode == 'legacy':
    length=16
  aesKey = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(length))

if exists(join(outDir, inputFile)):
  print("ERROR: output file %s already exists..."%(join(outDir, inputFile)))
  sys.exit(0)

if not exists(outDir):
  makedirs(outDir)

yealink = Yealink()
if privateKeyFile == 'auto' and mode == 'rsa':
  print("WARNING: No keyfile specified, generating new key pair")
  yealink.generateRSAPrivateKey()

if mode == 'rsa':
  #class get initialised with default Yealink keys pair, if you want, you can load keys:
  #yealink.loadRSAPrivateKey(privateKeyFile=privateKeyFile)
  #yealink.loadRSAPrivateKey(privateKey=priv)

  with open(join(outDir, inputFile), 'w') as f:
    f.write("#!encrypt:1.0.0.0\n")
    f.write("#!key_signatue:RSA_256\n")
    f.write("#!conf_encryption:AES_256\n")
    with open(inputFile, mode='rb') as input_file:
      f.write("#!key_ciphertext:"+yealink.RSAEncrypt(aesKey).decode()+"\n")
    #print("#!key_ciphertext:"+yealink.RSAEncrypt('0123456789012345').decode())
    f.write("#!---BEGIN CONFIG DATA---\n")
    with open(inputFile, mode='rb') as input_file:
      f.write( base64.b64encode(yealink.encryptAesEcb(input_file.read(), aesKey, padding=True) ).decode() + "\n" )
    f.write("#!---END CONFIG DATA---\n")

  with open(join(outDir, "Aeskey.txt"), 'a') as f:
    f.write("%s:%s\n\n"%(inputFile, aesKey))
  with open(join(outDir, "private.key"), 'w') as f:
    f.write(yealink.serializePrivateKey().decode())
  with open(join(outDir, "public.key"), 'w') as f:
    f.write(yealink.serializePublicKey().decode())
elif mode == 'legacy': # old aes-128-ecb encryption with leaked secret key
  with open(join(outDir, "Aeskey.txt"), 'a') as f:
    f.write("%s:%s\n\n"%(basename(inputFile), aesKey) )

  with open(join(outDir, basename(inputFile)), 'wb') as f:
    with open(inputFile, mode='rb') as input_file:
      f.write( yealink.encryptAesEcb(input_file.read(), aesKey, padding=True) )

  basefilename = '.'.join(basename(inputFile).split('.')[:-1] )
  with open(join(outDir, basefilename+"_Security.enc"), 'wb') as f:
    f.write( yealink.encryptAesEcb(aesKey, yealink.legacyAESkey, padding=False) )
