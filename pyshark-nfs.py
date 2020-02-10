#!/usr/bin/env python

# https://github.com/KimiNewt/pyshark

# tshark -i any port 2049 -o nfs.file_name_snooping:true -o nfs.file_full_name_snooping:true -Y "rpc.msgtyp == 0" -T fields -e rpc.auth.machinename -e rpc.auth.uid -e nfs.procedure_v3 -e nfs.name


from __future__ import print_function

import argparse
import pwd
import pyshark


def main ():
    parser = argparse.ArgumentParser()
    parser.add_argument('--packet-count', type=int)
    args = parser.parse_args()

    capture = pyshark.LiveCapture(
        interface='any',
        bpf_filter='port 2049',
        override_prefs = {
            'nfs.file_name_snooping:true': True,
            'nfs.file_full_name_snooping': True,
        },
        display_filter = 'rpc.msgtyp == 0',
    )
    for packet in capture.sniff_continuously(
            packet_count=args.packet_count,
    ):
        print(packet.rpc.auth_uid)


if __name__ == '__main__':
    main()
