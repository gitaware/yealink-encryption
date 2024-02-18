# yealinkencryption.py

Yealink created a new encryption tool for provisioning documents. Unfortunately this tool is a closed-source tool. In this repository you can find an open source tool incl. a library that can be used in other projects.

Usage:
```
./yealinkencryption.py -p[--private=] privatekeyfile -a[--aeskey=] -i[--infile=] inputfilename -d[--dir=] outputdir -m[mode=] [aes,legacy]
```

Both RSA and legacy mode is implemented.
If you specify 'auto' for the privatekeyfile, the tool wil generate a new keypair and put this pair in the outputdir.
If you do not specify a privatekeyfile, the tool will use the default keypair of Yealink. You can find this private key in Yealink.py
If you do not specify an AES key a new AES key will be generated.

# gui.py

For those who like to click a python pysimplegui gui has been added. I have tried to keep the gui as close as possible to the gui used by the original Yealink Encryption Tool.
This also means some of the naming may not be entirely clear, but if you have any questions, please do contact me.  
![Screenshot gui.py (MAC address is random)](https://raw.githubusercontent.com/gitaware/yealink-encryption/main/screenshots/gui.png)

# yealinkdecryption.py

While making the encryption tool i discovered it is also very easy to decrypt Yealink provisioning files even if you do not have the secret AES key or private RSA key.
This is because the encryption tool encrypts the provisioning document using the AES key and the AES key with the public RSA key. So if you have the private RSA key you can decrypt
the AES key and consequently the provisioning document.
yealinkdecryption.py does exactly that. It tries to guess all parameters. You CAN provide privatekey file, aeskey, etc, but easiest is to just:
```
./yealinkdecryption -i y000000000065.cfg
```

# Yealink.py

For those who want to script the encryption and decryption of Yealink provisioning files, i have provided a python class to do all the crypto stuff.
Both the commandline tools and the gui use this library, so i know it works well. If you do have any remarks on the code, please let me know or make a Pull Request.
