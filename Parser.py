#!/usr/bin/env python3

import argparse

import pwnlib.util.packing
import pandas
from pwn import *
from pathlib import Path

FILE_PATH = ''

#method for creating the parser in main
def create_parser():

    #create var for parser
    parser = argparse.ArgumentParser()

    #type and file arguments
    parser.add_argument('-t', '--type', help='Type', required=True)
    parser.add_argument('-f', '--file', help='Files', required=True)

    #return parser
    return parser


# calc hashs section and export to file
def get_md5(args):
    _file = args.file
    _path = Path(_file)
    file_path = _path

    md5 = hashlib.md5(open(_path, 'rb').read()).hexdigest()

    # write to md5 file
    md5file = open("MD5-" + _path.name + ".txt", "w")
    md5file.write(md5)
    md5file.close()
    return

#calc the sha value and write to file
def get_sha(args):
    _file = args.file
    _path = Path(_file)
    file_path = _path
    _exists = _path.is_file()

    sha256 = hashlib.sha256(open(_path, 'rb').read()).hexdigest()

    # write to md5 file
    sha256file = open("SHA-256-" + _path.name + ".txt", "w")
    sha256file.write(sha256)
    sha256file.close()
    return


# calc MBR record
def get_mbr(args):
    _file = args.file
    _path = Path(_file)

    partitions = []
    part_size = []
    part_type = []
    part_start_lba = []

    _snap = open(_path, 'rb')
    _snap.read(446)

    check = True
    while check:
        part_record = _snap.read(16)
        if part_record[0:2] != b"\x55\xaa":

            # Add data to the List
            partitions.append(part_record)

            # Starting LBA
            part_start_lba.append(pwnlib.util.packing.unpack(data=part_record[8:12], endian='little'))

            # Size of Partition * 512
            part_size.append(int(pwnlib.util.packing.unpack(data=part_record[12:16], endian='little'))*512)

            # Partition Type
            temp_hex = str(hex(part_record[4])[2:])
            if temp_hex.isdigit() and 0 <= int(temp_hex) <= 9:
                temp_hex = str(0) + str(temp_hex)
            part_type.append(temp_hex)

        else:
            check = False

    _snap.close()

    # set dataframe
    list_of_types = pandas.read_csv('PartitionTypes.csv', header=None, index_col=0, squeeze = True)
    data_dict = list_of_types.to_dict()

    # Partition Type , LBA, and Size output
    for i in range(0, len(partitions)):
        print("(" + str(part_type[i]) + ") "
              + str(data_dict.get(part_type[i]))
              + ", " + str(part_start_lba[i])
              + ", " + str(part_size[i]))

    _snap = open(_path, 'rb')

    if len(partitions) == 0:
        return

    for i in range(0, len(partitions)):
        print("Partition number: " + str(i + 1))

        _snap.seek(part_start_lba[i] + 496)
        part_bytes = _snap.read(16).hex()
        if len(part_bytes) == 0:
            return

        finalbyte = ""
        count = 1

        for y in range(0, len(part_bytes)):
            finalbyte += part_bytes[y]
            if count == 2:
                finalbyte += " "
                count = 1
            else:
                count += 1
        print("Last 16 bytes of boot record: " + str(finalbyte))


# calc GPT record
def get_gpt(args):
    # Create Lists for each type
    part_type = []
    start_lba = []
    gpt_part = []
    end_lba = []

    _file = args.file
    _path = Path(_file)
    _snap = open(_path, 'rb')
    _snap.read(1024)

    # Get the Start LBA, End LBA, and Type
    for i in range(0, 128):
        part_rec = _snap.read(128)

        # Get Start LBA
        _startLBA = int.from_bytes(part_rec[32:40], 'little')
        start_lba.append(_startLBA)

        # Get End LBA
        _endLBA = int.from_bytes(part_rec[40:48], 'little')
        end_lba.append(_endLBA)

        # Get Type
        _guidType = str(hex(int.from_bytes(part_rec[0:16], 'big')))[2:]
        part_type.append(_guidType)

        # Append the record
        gpt_part.append(part_rec)

    for i in range(0, len(gpt_part)):
        # Check for Empty
        if len(start_lba) == 0 | len(end_lba) == 0 | len(part_type) == 0:
            continue

        if start_lba[i] == 0 | end_lba[i] == 0 | part_type[i] == 0:
            continue
        else:
            print("Partition number: " + str(1 + i))
            print("Partition Type GUID : " + part_type[i])
            print("Starting LBA address in hex: " + str(hex(start_lba[i])))
            print("ending LBA address in hex: " + str(hex(end_lba[i])))
            print("starting LBA address in Decimal: " + str(start_lba[i]))
            print("ending LBA address in Decimal: " + str(end_lba[i]))

            # add new line in between each check
            print()
            continue

    _snap.close()
