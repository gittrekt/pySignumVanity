#!/usr/bin/env python3
import base64
import binascii
import codecs
import multiprocessing as mp
import os
import random
from hashlib import sha256
from threading import Thread
from zlib import adler32 as ad

from libcpp cimport bool as bool_C

import apprise
import cython
import fastthreadpool
import nacl.public as curve25519  # pynacl
from cython.parallel import parallel, prange
from tqdm import tqdm

import shared

cdef str alphabet = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ'
cdef list cwmap = [3, 2, 1, 0, 7, 6, 5, 4, 13, 14, 15, 16, 12, 8, 9, 10, 11]
cdef list gexp = [1, 2, 4, 8, 16, 5, 10, 20, 13, 26, 17, 7, 14, 28, 29, 31, 27, 19, 3, 6, 12, 24, 21, 15, 30, 25, 23, 11, 22, 9, 18, 1]
cdef list glog = [0, 0, 1, 18, 2, 5, 19, 11, 3, 29, 6, 27, 20, 8, 12, 23, 4, 10, 30, 17, 7, 22, 28, 26, 21, 25, 9, 16, 13, 14, 24, 15]

def write_pw(FILE, addr, passphrase):
    w = f'{addr}:{passphrase}\n'
    with open(FILE, 'a') as f:
        f.write(w)

cdef bytes get_pubkey(str secret_pass):
    return curve25519.PrivateKey(sha256(codecs.decode(secret_pass.encode('utf-8').hex(), 'hex_codec')).digest()).public_key._public_key

cdef str get_accountid(bytes pub_key):
    cdef str account_id = str(int.from_bytes(bytearray.fromhex(sha256(codecs.decode(pub_key.hex(), 'hex_codec')).digest().hex())[:8], byteorder='little', signed=False))
    cdef int length = len(account_id)
    if 5 < length < 21 and account_id.isdigit():
        if (length == 20 and account_id[0] != '1'):
            raise ValueError()
        return account_id
    raise ValueError()

cdef str get_address(str account_id):
    cdef int i
    cdef list codeword = [1] * 17
    cdef list p = [0] * 4
    cdef str addr = 'S-'

    for i in range(13): # Create the codeword
        codeword[i] = (int(account_id) >> (5 * i)) & 31

    for i in range(12, -1, -1): # Encode the codeword
        fb = codeword[i] ^ p[3]
        p[3] = p[2] ^ gmult(30, fb)
        p[2] = p[1] ^ gmult(6, fb)
        p[1] = p[0] ^ gmult(9, fb)
        p[0] = gmult(17, fb)
    codeword[13] = p[0]
    codeword[14] = p[1]
    codeword[15] = p[2]
    codeword[16] = p[3]

    for i in range(17):
        addr += alphabet[codeword[cwmap[i]]] # Lookup the address
        if i & 3 == 3 and i < 13: # Add dashes
            addr += '-'

    return addr

cdef int gmult(int a, int b):
    if (a == 0 or b == 0):
        return 0

    cdef int idx = (glog[a] + glog[b]) % 31

    return gexp[idx]

cdef str get_checksum(list wordlist, int NBIT):
    cdef list words = list(random.choices(wordlist, k=NBIT))
    cdef str trimmed_words = ""
    cdef str word
    cdef int i
    for i, word in enumerate(words):
        trimmed_words += word[0:3]
    cdef int checksum = ad(trimmed_words.encode('ascii'))
    cdef int index = checksum % len(words)
    words.append(words[index])
    return ' '.join(words)

class runme():
    def __init__(self):
        self.found = 0
        if shared.NOTIFY:
            self.apobj = apprise.Apprise()
            self.apobj.add(shared.NOTIFYTO)
        self.pbar = tqdm(
            bar_format="Tested: {n:,d} | Found: {postfix} | Avg: {rate_fmt} | Elapsed: {elapsed}",
            postfix=self.found,
            smoothing=0,
            miniters=1,
        )

    def worker(self, foundit, log):
        cdef int NBIT = shared.NBIT
        cdef bint CSUM = shared.CSUM
        cdef bint ALL = shared.ALL
        cdef str FILE = shared.FILE
        cdef bint ANYWHERE = shared.ANYWHERE
        cdef bint NOTIFY = shared.NOTIFY
        cdef list WORDS = shared.words
        cdef set MATCH = shared.MATCH
        cdef str acct, addr, mnemonic
        cdef bytes pkey
        if NOTIFY:
            self.apobj.notify(
                body=f'Starting vanity search for {" | ".join(set(MATCH))}',
                title='Starting',
            )
        while True:
            if foundit.is_set(): break
            if CSUM:
                mnemonic = get_checksum(WORDS, NBIT)
            else:
                mnemonic = ' '.join(set(random.choices(WORDS, k=NBIT)))
            try:
                pkey = get_pubkey(mnemonic)
                acct = get_accountid(pkey)
                addr = get_address(acct)
            except:
                continue
            for match in MATCH:
                if ANYWHERE:
                    if match in addr:
                        if ALL:
                            write_pw(FILE, addr, mnemonic)
                            if NOTIFY:
                                self.apobj.notify(
                                    body=f'Address found for {match}, check your output file for the privkey',
                                    title=f'{addr} Found!',
                                )
                        else:
                            foundit.set()
                            self.pbar.close()
                            log.info(f'MATCH FOUND for {match}')
                            log.info(f'Address - {addr}')
                            write_pw(FILE, addr, mnemonic)
                            log.info(f'Passphrase written to - {FILE}')
                            if NOTIFY:
                                self.apobj.notify(
                                    body=f'Address found for {match}, check your output file for the privkey',
                                    title=f'{addr} Found!',
                                )
                            break
                        self.found+=1
                        self.pbar.postfix=self.found
                else:
                    if addr[2:len(match)+2] == match:
                        if ALL:
                            write_pw(FILE, addr, mnemonic)
                        else:
                            foundit.set()
                            self.pbar.close()
                            log.info(f'MATCH FOUND for {match}')
                            log.info(f'Address - {addr}')
                            write_pw(FILE, addr, mnemonic)
                            log.info(f'Passphrase written to - {FILE}')
                            if NOTIFY:
                                self.apobj.notify(
                                    body=f'Address found for {match}, check your output file for the privkey',
                                    title=f'{addr} Found!',
                                )
                            break
                        self.found+=1
                        self.pbar.postfix=self.found
            self.pbar.update()
            continue
        if NOTIFY:
            self.apobj.notify(
                body=f'Vanity search for {MATCH} ended',
                title='Stopping',
            )

