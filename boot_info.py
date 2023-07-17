#!/usr/bin/env python3

from Parser import *


def main():
    # get args passed in through command
    args = create_parser().parse_args()

    # check valid or not type
    if not (check_type(args)):
        return

    # write md5 and sha256
    get_md5(args)
    get_sha(args)

    _type = str(args.type).lower()
    check_type(args)


def check_type(args):
    _type = str(args.type).lower()
    print()

    if _type == 'gpt':
        get_gpt(args)
    elif _type == 'mbr':
        get_mbr(args)
    else:
        return


if __name__ == '__main__':
    main()
