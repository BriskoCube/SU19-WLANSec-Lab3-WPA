#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
- Derive WPA keys from Passphrase and 4-way handshake info

- Calculate an authentication MIC (the mic for data transmission uses the
Michael algorithm. In the case of authentication, we use SHA-1 or MD5)
"""

__author__      = "Antoine Hunkeler & Julien Quartier & Yoon Seokchan"
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
    
wpa = rdpcap('wpa_handshake.cap')    

#open and read the dictionary and put lines in an array
#source : 
dictionary = open('dictionary.txt', 'r')

words = dictionary.read().splitlines()

nbRounds = 4096
sizePMK = 32

ssid = wpa[0].info
ssidLen = len(ssid)

print ssid
print ssidLen

for passphrase in words:
	pmk = pbkdf2_hex(passphrase, ssid, nbRounds, sizePMK)
	print pmk
	
