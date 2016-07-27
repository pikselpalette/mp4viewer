#!/usr/bin/python

import argparse
from isobmff.movie import WidevinePsshBox

def main():
    parser = argparse.ArgumentParser(
        description='Process widevine PPSH')
    parser.add_argument('base64_PSSH', metavar='PSSH', help='PSSH')
    args = parser.parse_args()


    pssh = WidevinePsshBox(args.base64_PSSH)
    print(pssh)

if __name__ == "__main__":
    main()
