#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
- Derive WPA keys from Passphrase and 4-way handshake info

- Calculate an authentication MIC (the mic for data transmission uses the
Michael algorithm. In the case of authentication, we use SHA-1 or MD5)
"""

__author__      = "Abraham Rubinstein"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
from pbkdf2_math import pbkdf2_hex #contains function to calculate 4096 rounds on passphrase and SSID
from numpy import array_split
from numpy import array
import hmac, hashlib

def customPRF512(key,A,B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i    = 0
    R    = ''
    while i<=((blen*8+159)/160):
        hmacsha1 = hmac.new(key,A+chr(0x00)+B+chr(i),hashlib.sha1)
        i+=1
        R = R+hmacsha1.digest()
    return R[:blen]

# Read capture file -- it contains beacon, open authentication, associacion, 4-way handshake and data
wpa=rdpcap("wpa_handshake.cap"autj


#for packet in wpa:
    #print packet[5].load-encode("hex")
    #print packet.addr3.replace(":", "")

# Important parameters for key derivation - some of them can be obtained from the pcap file
passPhrase  = "actuelle" #this is the passphrase of the WPA network
A           = "Pairwise key expansion" #this string is used in the pseudo-random function and should never be modified
ssid        =  wpa[0].info #"SWI"
APmac       = a2b_hex(wpa[0].addr3.replace(":", "")) #a2b_hex("cebcc8fdcab7") #MAC address of the AP
Clientmac   = a2b_hex(wpa[1].addr1.replace(":", "")) # a2b_hex("0013efd015bd") #MAC address of the client

# Authenticator and Supplicant Nonces
ANonce      = a2b_hex(wpa[5].load[13:45].encode("hex"))
SNonce      = a2b_hex(wpa[6].load[13:45].encode("hex"))

# This is the MIC contained in the 4th frame of the 4-way handshake. I copied it by hand.
# When trying to crack the WPA passphrase, we will compare it to our own MIC calculated using passphrases from a dictionary
mic_to_test = wpa[8].load[77:93].encode("hex")

B           = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function

# Take a good look at the contents of this variable. Compare it to the Wireshark last message of the 4-way handshake.
# In particular, look at the last 16 bytes. Read "Important info" in the lab assignment for explanation

# Get an object describing EAPoL auth
eapol = wpa[8][EAPOL]

# Combine eapol values and load to create data
data = "{0:02x}{1:02x}{2:04x}".format(eapol.version, eapol.type, eapol.len) + wpa[8].load.encode("hex")
data = a2b_hex(data[:-36] + "0" * 36)

print "\n\nValues used to derivate keys"
print "============================"
print "Passphrase: ",passPhrase,"\n"
print "SSID: ",ssid,"\n"
print "AP Mac: ",b2a_hex(APmac),"\n"
print "CLient Mac: ",b2a_hex(Clientmac),"\n"
print "AP Nonce: ",b2a_hex(ANonce),"\n"
print "Client Nonce: ",b2a_hex(SNonce),"\n"

#calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
pmk = pbkdf2_hex(passPhrase, ssid, 4096, 32)

#expand pmk to obtain PTK
ptk = customPRF512(a2b_hex(pmk),A,B)

#calculate our own MIC over EAPOL payload - The ptk is, in fact, KCK|KEK|TK|MICK
mic = hmac.new(ptk[0:16],data,hashlib.sha1)

#separate ptk into different keys - represent in hex
KCK = b2a_hex(ptk[0:16])
KEK = b2a_hex(ptk[16:32])
TK  = b2a_hex(ptk[32:48])
MICK = b2a_hex(ptk[48:64])

#the MIC for the authentication is actually truncated to 16 bytes (32 chars). SHA-1 is 20 bytes long.
MIC_hex_truncated = mic.hexdigest()[0:32]

print "\nResults of the key expansion"
print "============================="
print "PMK:\t\t",pmk,"\n"
print "PTK:\t\t",b2a_hex(ptk),"\n"
print "KCK:\t\t",KCK,"\n"
print "KEK:\t\t",KEK,"\n"
print "TK:\t\t",TK,"\n"
print "MICK:\t\t",MICK,"\n"
print "MIC:\t\t",MIC_hex_truncated,"\n"
