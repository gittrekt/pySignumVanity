#!/usr/bin/env python3
import argparse
import multiprocessing as mp
import os
import re
import signal
from threading import Thread

#import cython
import fastthreadpool

import shared
import tasks_vanity

#import pyximport; pyximport.install(pyimport=True)

def Arguments():
    parser = argparse.ArgumentParser(prog='Signa Vanity Generator', description='Signa Vanity Address Generator')
    parser.add_argument('-s', '--search',  help='Address Prefix to search for', required=True, action="append", type=str)
    parser.add_argument('-o', '--out', help='Where to save the results', required=False, nargs='?', default='signa-vanity-password.txt')
    parser.add_argument('--all',  help='Run constantly saving all results to file', required=False, action='store_true', default=False)
    parser.add_argument('-a', '--anywhere',  help='Search anywhere in the address for the match. This can be faster as you might end up finding it futher in the address than just the beginning. Default: False', required=False, action='store_true')
    parser.add_argument('-t', '--threading',  help='Use threading instead of multiprocessing', required=False, action='store_true')
    parser.add_argument('-th', '--threads',  help='Number of threads to use when multithreading. Default: CPU_COUNT', required=False, default=mp.cpu_count(), type=int)
    parser.add_argument('-m', '--message',  help='Python "Appraise" type notifications', required=False, action='store_true', default=False)
    parser.add_argument('-n', '--nbit',  help='Mnemonic length. Larger numbers will generate longer privkeys Default: 12', required=False, default=12, type=int)
    parser.add_argument('-c', '--checksum',  help="Use a checksum word. This feature isn't implemented in Signum, but was a requested feature", required=False, action='store_true', default=False)
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 2.0')
    gl_args = parser.parse_args()
    return gl_args

if __name__ == '__main__':
    args = Arguments()
    log = shared.log
    signal.signal(signal.SIGINT, shared.killall)
    searches = args.search
    shared.FILE = args.out
    shared.ALL = args.all
    shared.NBIT = args.nbit
    shared.CSUM = args.checksum
    shared.ANYWHERE = args.anywhere
    shared.NOTIFY = args.message
    shared.THREADS = args.threads
    shared.THREADING = args.threading
    for match in searches:
        match = match.upper()
        if not bool(re.match('^[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]+$', match)):
            log.error('Search must only contain 23456789ABCDEFGHJKLMNPQRSTUVWXYZ')
            exit(1)
        if len(match) > 17:
            log.error('Signa addresses cannot be longer than 17 chars')
            exit(1)
        if len(match) > 8:
            log.info('Good luck searching more than 8 characters...')
        match = [match[i:i+4] for i in range(0, len(match), 4)]
        match[3:] = [''.join(match[3:])]
        match = [x for x in match if x]
        match = str('-'.join(match))
        shared.MATCH.add(match)
    log.info(f'Searching for {" | ".join(set(shared.MATCH))}')
    foundit = mp.Event()
    start = tasks_vanity.runme()
    if args.threading:
        for _ in range(args.threads):
            Thread(target=tasks_vanity.runme.worker, args=(start, foundit, log,)).start()
    else:
        with fastthreadpool.Pool(args.threads) as pool:
            try:
                pool.submit(tasks_vanity.runme.worker, start, foundit, log)
                pool.join()
            finally:
                pool.shutdown()
    foundit.wait()
    exit(1)

