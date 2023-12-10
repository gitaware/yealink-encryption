#!/usr/bin/python3

import string
import random
from Yealink import Yealink
from os.path import exists, join, basename
from os import makedirs
import base64

try:
  import PySimpleGUI as sg
except:
  print("python module pySimpleGui missing.")
  
def randomString(length):
  return ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(length))
  
form_rows = [
             [sg.Text('Select File(s)', size=(15, 1)),
                sg.InputText(key='configFile'), sg.FileBrowse(size=(10, 1))],
             [sg.Text('Target Directory', size=(15, 1)),
                sg.InputText(key='targetDir'), sg.FolderBrowse(size=(10, 1))],
             [sg.Text('Encryption Mode', size=(15, 1)), 
                sg.Radio('RSA Mode', "MODE", key='MODE-RSA', default=True, enable_events=True),sg.Radio('Compatibility Mode', "MODE", key='MODE-COMPAT', default=False, enable_events=True)],
             [sg.Text('AES Type', size=(15, 1)), 
                sg.Combo(['128 bit','256 bit'],default_value='256 bit',key='AESKEYLENGTH', enable_events=True)],
             [sg.Text('RSA Model', size=(15, 1)), 
                sg.Radio('Default', "RSAMODEL", key='RSAMODEL-DEFAULT', default=True, enable_events=True),sg.Radio('Self-Define', "RSAMODEL", key='RSAMODEL-SD', default=False, enable_events=True), sg.Text('', key='rsakeyfile'), sg.FileBrowse(disabled=True, key='RSAKEYFILE', size=(10, 1))],
             [sg.Text('AES Model', size=(15, 1)), 
                sg.Radio('Manual', "AESMODEL", key='AESMODEL-MANUAL', default=False, enable_events=True),sg.Radio('Auto Generate', "AESMODEL", key='AESMODEL-AUTO', default=True, enable_events=True)],
             [sg.Text('AES KEY', size=(15, 1)),
                sg.InputText(key='aeskey', enable_events=True), sg.Button('Re-Generate')],

             [sg.Button('Encrypt', enable_events=True), sg.Button('Exit')]]



sg.theme('DefaultNoMoreNagging')
window = sg.Window('Yealink Configuration Encrypt Tool v1.0 by Jeroen Hermans', form_rows, finalize=True)
#window['aeskey'].bind("<FocusOut>", "FocusOut")
length = 32
if window['AESKEYLENGTH'] == '128 bit':
  length = 16
window['aeskey'].Update(randomString(length))
window['aeskey'].update(disabled=True)
while True:
  event, values = window.read()
  #print(event)
  #print(values)
  if event in (sg.WIN_CLOSED, 'Exit'):
    break
  elif event == 'Re-Generate':
    length = 32
    if values['AESKEYLENGTH'] == '128 bit':
      length = 16
    window['aeskey'].Update(randomString(length))
  elif event == 'AESMODEL-AUTO': #AES MODEL AUTO selected
    length = 32
    if values['AESKEYLENGTH'] == '128 bit':
      length = 16
    window['aeskey'].Update(randomString(length))
    window['aeskey'].update(disabled=True)
  elif event == 'AESMODEL-MANUAL': #AES MODEL MANUAL selected
    window['aeskey'].update(disabled=False)
  elif event == 'MODE-RSA':
    window['RSAMODEL-DEFAULT'].update(disabled=False)
    window['RSAMODEL-SD'].update(disabled=False)
    window['AESKEYLENGTH'].update('256 bit')
    window['AESKEYLENGTH'].update(disabled=False)
    if window['AESMODEL-AUTO']:
      length = 32
      if values['AESKEYLENGTH'] == '128 bit':
        length = 16
      window['aeskey'].Update(randomString(length))
  elif event == 'MODE-COMPAT':
    window['RSAMODEL-DEFAULT'].update(disabled=True)
    window['RSAMODEL-SD'].update(disabled=True)
    window['AESKEYLENGTH'].update('128 bit')
    window['AESKEYLENGTH'].update(disabled=True)
    window['aeskey'].Update(randomString(16))
  elif event == 'RSAMODEL-DEFAULT':
    window['RSAKEYFILE'].update(disabled=True)
  elif event == 'RSAMODEL-SD':
    window['RSAKEYFILE'].update(disabled=False)
  elif event.endswith("FocusOut"):
    if event == 'aeskeyFocusOut':
      print(values['aeskey'])
  elif event == 'AESKEYLENGTH':
    if window['AESMODEL-AUTO']:
      length = 32
      if values['AESKEYLENGTH'] == '128 bit':
        length = 16
      window['aeskey'].Update(randomString(length))
  elif event == 'Encrypt':
    yealink = Yealink()
    if not exists(values['targetDir']):
      makedirs(values['targetDir'])

    if values['MODE-RSA']:
      with open(join(values['targetDir'], basename(values['configFile'])), 'w') as f:
        f.write("#!encrypt:1.0.0.0\n")
        f.write("#!key_signatue:RSA_256\n")
        if values['AESKEYLENGTH'] == '128 bit':
          f.write("#!conf_encryption:AES_128\n")
        else:
          f.write("#!conf_encryption:AES_256\n")
        f.write("#!key_ciphertext:"+yealink.RSAEncrypt(values['aeskey']).decode()+"\n")
        f.write("#!---BEGIN CONFIG DATA---\n")
        with open(values['configFile'], mode='rb') as input_file:
          f.write( base64.b64encode(yealink.encryptAesEcb(input_file.read(), values['aeskey'], padding=True) ).decode() + "\n" )
        f.write("#!---END CONFIG DATA---\n")

      with open(join(values['targetDir'], "Aeskey.txt"), 'a') as f:
        f.write("%s:%s\n\n"%(basename(values['configFile']), values['aeskey']))
      with open(join(values['targetDir'], "private.key"), 'w') as f:
        f.write(yealink.serializePrivateKey().decode())
      with open(join(values['targetDir'], "public.key"), 'w') as f:
        f.write(yealink.serializePublicKey().decode())
    elif values['MODE-COMPAT']: # old aes-128-ecb encryption with leaked secret key
      with open(join(values['targetDir'], "Aeskey.txt"), 'a') as f:
        f.write("%s:%s\n\n"%(basename(values['configFile']), values['aeskey']))

      with open(join(values['targetDir'], basename(values['configFile'])), 'wb') as f:
        with open(values['configFile'], mode='rb') as input_file:
          f.write( yealink.encryptAesEcb(input_file.read(), values['aeskey'], padding=True) )

      basefilename = '.'.join(basename(values['configFile']).split('.')[:-1] )
      with open(join(values['targetDir'], basefilename+"_Security.enc"), 'wb') as f:
        f.write( yealink.encryptAesEcb(values['aeskey'], yealink.legacyAESkey, padding=False) )



window.close()
