"""
Scan file system extracting entitlements from Mach-O binaries (and the raw code signature segment).

This code was primarily written by GitHub Copilot.

There are a number of decisions - like the globals - that I would not have made, but I've left them in place.
The purpose was to use Copilot as much as possible.  Through better prodding on my part I could have gotten
Copilot to write cleaner code.
"""
import os
import sqlite3
import plistlib

import lief

verbose = False
database_name = 'entitlements.sqlite3'
save_entitlements = False
save_code_signature = False

#
#  Helper funcs
#

def find_code_directory_magic(plist):
    """ finds 0xfade0c02 (code directory magic) in memoryview object - returns None if not found """
    """ CSMAGIC_CODEDIRECTORY 0xfade0c02 - bsd/sys/codesign.h """
    for i in range(len(plist)):
        if plist[i] == 0xFA and plist[i+1] == 0xDE and plist[i+2] == 0x0C and plist[i+3] == 0x02:
            return i
    return None

def find_embedded_entitlements_magic(plist):
    """ finds 0xFADE7171 (entitlement magic) in memoryview object - returns None if not found """
    """ CSMAGIC_EMBEDDED_ENTITLEMENTS 0xFADE7171 - bsd/sys/codesign.h """
    for i in range(len(plist)):
        if plist[i] == 0xFA and plist[i+1] == 0xDE and plist[i+2] == 0x71 and plist[i+3] == 0x71:
            return i
    return None

def find_embedded_der_entitlements_magic(plist):
    """ finds 0xFADE7172 (der entitlement magic) in memoryview object - returns None if not found """
    """ CSMAGIC_EMBEDDED_DER_ENTITLEMENTS 0xFADE7172 - bsd/sys/codesign.h """
    for i in range(len(plist)):
        if plist[i] == 0xFA and plist[i+1] == 0xDE and plist[i+2] == 0x71 and plist[i+3] == 0x72:
            return i
    return None

def get_int(plist, offset):
    """ returns next 4 bytes as int """
    return int.from_bytes(plist[offset:offset+4], byteorder='big')

def verify_xml(plist, offset):
    """ verify that start of buffer is <?xml """
    return plist[offset:offset+6] == b'<?xml ' #  or plist[offset:offset+5] == b'<!-- '

def find_xml(plist):
    """ Finds XML string in memoryview object - returns None if not found """
    for i in range(len(plist)):
        if verify_xml(plist, i):
            return i
    return None

def bytes_to_plist(plistbytes):
    """ Converts bytes to plist object """
    try:
        plist = plistlib.loads(plistbytes, fmt=plistlib.FMT_XML)
    except Exception as e:
        verbose and print('Error parsing plist: {}'.format(e))
        plist = None
    return plist

kSecCodeSignatureLibraryValidation = 0x2000 # require library validation
kSecCodeSignatureRestrict = 0x0800 # restrict dyld loading
kSecCodeSignatureRuntime = 0x10000
def is_hardened(flags):
    """ Returns True if binary is hardened """
    return False if flags is None else (flags & kSecCodeSignatureRuntime) == kSecCodeSignatureRuntime



#
# Parsing the binary for entitlements
#

class CodeDirectoryException(Exception):
    pass

class EntitlementException(Exception):
    pass

def parse_binary(executable_path):
    binary = lief.parse(executable_path)
    if binary is None:
        raise EntitlementException('LIEF error parsing binary')
    
    if binary.format != lief.EXE_FORMATS.MACHO:
        raise EntitlementException('LIEF says not a Mach-O binary')

    if not binary.has_entrypoint:
        raise EntitlementException('LIEF says its a dylib')

    if (not binary.has_code_signature) or binary.code_signature is None:
        raise EntitlementException('No code signature segment found')

    return binary

def extract_code_directory_flags(binary):
    """ Extracts CodeDirectory flags from the binary
        raises CodeDirectoryException on error

        binary: lief binary object

        returns flags as an int
    """
    signature = binary.code_signature

    code_directory_offset = find_code_directory_magic(signature.content)
    if code_directory_offset is None:
        raise CodeDirectoryException('No code directory magic found')
    verbose and print('CodeDirectory offset: {}'.format(code_directory_offset))

    # sanity check
    code_directory_buffer_length = get_int(signature.content, code_directory_offset+4)
    if code_directory_offset + code_directory_buffer_length > len(signature.content):
        raise CodeDirectoryException('CodeDirectory declared length exceeds overall segment length')

    # MAGIC[4] - LENGTH[4] - VERSION[4] - FLAGS[4] ...other stuff...
    if code_directory_buffer_length < 16:
        raise CodeDirectoryException('CodeDirectory declared length is too short')

    return get_int(signature.content, code_directory_offset+12)

def extract_entitlement_bytes(binary):
    """ Extracts entitlements plist from executable as bytes
        raises EntitlementException if not found

        binary: lief binary object

        returns both the (full_bytes, xml_bytes)
            returns "full_bytes" cause plistlib struggles when <?xml is not the start of what it receives
    """
    signature = binary.code_signature

    entitlements_offset = find_embedded_entitlements_magic(signature.content)
    if entitlements_offset is None:
        entitlements_offset = find_embedded_der_entitlements_magic(signature.content)
        if entitlements_offset is not None:
            raise EntitlementException('DER entitlements not supported')
        raise EntitlementException('No entitlements magic found')
    verbose and print('Entitlements offset: {}'.format(entitlements_offset))

    entitlements_buffer_length = get_int(signature.content, entitlements_offset+4)
    verbose and print('Entitlements buffer length: {}'.format(entitlements_buffer_length))

    if entitlements_offset + entitlements_buffer_length > len(signature.content):
        raise EntitlementException('Entitlements declared length exceeds overall segment length')

    full_buffer = signature.content[entitlements_offset+8:entitlements_offset+entitlements_buffer_length]
    verbose and print('Entitlements: {}'.format(full_buffer.tobytes()))

    xml_start_tag_offset = find_xml(full_buffer)
    if xml_start_tag_offset is None:
        raise EntitlementException('Entitlements are not XML')
    xml_plist = full_buffer[xml_start_tag_offset:]

    # this feels like a hack.  found several cases where plist was \x00 padded which causes plistlib to fail
    xml_plist = xml_plist.tobytes().rstrip(b'\x00')
    verbose and print('Entitlements (post strip): {}'.format(xml_plist))

    # full_buffer returned cause plistlib struggles when <?xml is not the start of what it receives
    return xml_plist, full_buffer.tobytes()




#
#   plist actions (callbacks)
#
def print_plist(executable, plistbytes, entitlement_buffer, sig_buffer, cd_flags, error=None):
    """ Prints entitlements plist to stdout """
    if save_entitlements and entitlement_buffer is not None:
        save_bytes_to_file(executable, entitlement_buffer, ".entitlements.plist")

    if save_code_signature and sig_buffer is not None:
        save_bytes_to_file(executable, sig_buffer, ".signature")

    if error is not None:
        # print via verbose - print('{}: {}'.format(error, executable))
        return

    plist = bytes_to_plist(plistbytes)
    if plist is None:
        return

    print('{}:'.format(executable))
    print('Flags: 0x{:08X} Hardened: {}'.format(cd_flags, is_hardened(cd_flags)))
    for key in plist.keys():
        print('{}: {}'.format(key, plist[key]))

def save_bytes_to_file(executable_path, bytes, extension):
    filename = executable_path.replace('/', '_') + extension
    filename = filename[-254:]

    verbose and print('Saving bytes [{}] to file: {}'.format(extension, filename))
    try:
        with open(filename, 'wb') as f:
            f.write(bytes)
    except (OSError, IOError) as e:
        print('Error saving file: {} - {}'.format(e, filename))

def save_sqlite_plist(executable, plistbytes, entitlement_buffer, sig_buffer, cd_flags, error=None):
    """ Saves entitlements plist to sqlite database """
    plist = bytes_to_plist(plistbytes) if plistbytes is not None else None
    if plist is None and plistbytes is not None:
        return

    try:
        with sqlite3.connect(database_name) as conn:
            c = conn.cursor()
            if plist is not None:
                for key in plist.keys():
                    c.execute('INSERT INTO entitlements VALUES (?, ?, ?)', (executable, key, str(plist[key])))
            if error is not None:
                c.execute('INSERT INTO errors VALUES (?, ?)', (executable, error))
            if cd_flags is not None:
                c.execute('INSERT INTO cd_flags VALUES (?, ?, ?)', (executable, cd_flags, is_hardened(cd_flags)))
            if (save_entitlements and entitlement_buffer is not None) or (save_code_signature and sig_buffer is not None):
                a = sqlite3.Binary(entitlement_buffer) if entitlement_buffer is not None else sqlite3.Binary(b'')
                b = sqlite3.Binary(sig_buffer) if sig_buffer is not None else sqlite3.Binary(b'')
                c.execute('INSERT INTO raw VALUES (?, ?, ?)', (executable, a, b))
            conn.commit()
    except sqlite3.Error as e:
        verbose and print('Error saving to sqlite: {}'.format(e))

def create_sqlite_tables_and_indexes():
    """ Creates indexes on sqlite database """
    try:
        with sqlite3.connect(database_name) as conn:
            c = conn.cursor()
            c.execute('CREATE TABLE IF NOT EXISTS entitlements (executable text, entitlement text, value text)')
            c.execute('CREATE TABLE IF NOT EXISTS errors (executable text, error text)')
            c.execute('CREATE TABLE IF NOT EXISTS cd_flags (executable text, flags int, hardened boolean)')
            c.execute('CREATE TABLE IF NOT EXISTS raw (executable text, entitlements blob, signature blob)')

            c.execute('CREATE INDEX IF NOT EXISTS entitlements_executable_idx ON entitlements (executable)')
            c.execute('CREATE INDEX IF NOT EXISTS entitlements_entitlement_idx ON entitlements (entitlement)')
            c.execute('CREATE INDEX IF NOT EXISTS cd_flags_executable_idx ON cd_flags (executable)')
            c.execute('CREATE INDEX IF NOT EXISTS cd_flags_hardened_idx ON cd_flags (hardened)')
            conn.commit()
    except sqlite3.Error as e:
        verbose and print('Error creating tables and indexes: {}'.format(e))


def print_sqlite_stats():
    """ Prints stats from sqlite database """
    try:
        with sqlite3.connect(database_name) as conn:
            c = conn.cursor()
            c.execute('SELECT count(distinct entitlement) FROM entitlements')
            print('Entitlements: {}'.format(c.fetchone()[0]))
            c.execute('SELECT count(distinct executable) FROM entitlements')
            print('Executables: {}'.format(c.fetchone()[0]))
            c.execute('SELECT error, count(*) FROM errors GROUP BY error ORDER BY 1 DESC')

            # rowcount doesn't work
            row = c.fetchone()
            if row is not None:
                print('Errors:')
                print('{} - {}'.format(row[1], row[0]))
            for row in c.fetchall():
                print('{} - {}'.format(row[1], row[0]))
    except sqlite3.Error as e:
        verbose and print('Error printing sqlite stats: {}'.format(e))



#
#  Find executables
#

def is_executable(filepath):
    """ Returns True if filepath is executable """
    return os.path.isfile(filepath) and os.access(filepath, os.X_OK)

def find_executables(path):
    """ Finds executables in path """
    if is_executable(path):
        verbose and print('Short-circuit path is executable: {}'.format(path))
        return [path]

    verbose and print('Searching for executables in {}'.format(path))
    executables = []
    for root, dirs, files in os.walk(path):
        for file in files:
            if file.endswith('.app'):
                executable = os.path.join(root, file, 'Contents', 'MacOS', file[:-4])
                if is_executable(executable):
                    executables.append(executable)
            elif is_executable(os.path.join(root, file)):
                executables.append(os.path.join(root, file))
    return executables

def find_entitlements(paths, callback):
    for path in paths:
        for executable in find_executables(path):
            # verbose and print('Processing executable: {}'.format(executable))
            try:
                binary = parse_binary(executable)
            except EntitlementException as e:
                if not str(e).startswith('LIEF '):
                    # could be LIEF parsing error, but most likely is simply not a Mach-O binary (like .js or .py or .sh or ...)
                    # could also be a dylib which don't appear to have entitlements
                    callback(executable, None, None, None, None, error=str(e))
                continue

            try:
                cd_flags = extract_code_directory_flags(binary)
            except CodeDirectoryException as e:
                cd_flags = None

            try:
                xml_plist, entitlement_buffer = extract_entitlement_bytes(binary)
            except EntitlementException as e:
                callback(executable, None, None, binary.code_signature.content, cd_flags, error=str(e))
                verbose and print('Error extracting entitlements: {} - from {}'.format(e, executable))
                continue
            except Exception as e:
                callback(executable, None, None, binary.code_signature.content, cd_flags, error=str(e))
                print('UNEXPECTED ERROR extracting entitlements: {} - from {}'.format(e, executable))
                continue

            callback(executable, xml_plist, entitlement_buffer, binary.code_signature.content, cd_flags)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Extracts entitlements from Mach-O binaries (and code signature segment)')
    parser.add_argument('executables', nargs='*', default=['/Applications',], help='path to executable or directories')
    parser.add_argument('-v', '--verbose', action='store_true', help='verbose output')
    parser.add_argument('--savecert', action='store_true', help='save code signature to file or database')
    parser.add_argument('--saveent', action='store_true', help='save entitlements to file or database')
    parser.add_argument('-d', '--database', help='save entitlements to sqlite database')
    args = parser.parse_args()

    verbose = args.verbose
    save_entitlements = args.saveent
    save_code_signature = args.savecert

    cb = print_plist
    if args.database:
        database_name = args.database
        cb = save_sqlite_plist
        create_sqlite_tables_and_indexes()

    find_entitlements(args.executables, callback=cb)

    if args.database:
        print_sqlite_stats()
