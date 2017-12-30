#!/usr/bin/env python
#
# Copyright (C) 2017 Andrew Chow

import fileinput
import util

def print_pr(pr):
    if pr.error:
        print(pr.error)
    else:
        pr.verify()
        print()
        print("Payment request data")
        print("Network: " + pr.details.network)
        print("Requestor: " + pr.get_requestor())
        print("Memo: " + pr.get_memo())
        print("Expiration: " + util.format_time(pr.get_expiration_date()))
        print("Creation Time: " + util.format_time(pr.details.time))
        print("Verification Status: " + pr.get_verify_status())
        print("Merchant Data: " + str(pr.details.merchant_data))
        print("Outputs:")
        for out in pr.get_outputs():
            if out[0] == util.TYPE_ADDRESS:
                print("  Type: Address")
                print("  Address: " + out[1])
            elif out[0] == util.TYPE_PUBKEY:
                print("  Type: Public Key")
                print("  Public Key: " + out[1])
            elif out[0] == util.TYPE_SCRIPT:
                print("  Type: Script")
                print("  Script: " + out[1])
            else:
                print("  Type: Unknown")
                print("  Data: " + out[1])
            print("  Amount: " + util.format_satoshis(out[2]) + " BTC")

if __name__ == '__main__':
    # Command line interface, print welcome message
    print("Bitcoin Payment Protocol Data Viewer")
    print()
    print("Enter a Bitcoin URI:")
    
    for line in fileinput.input():
        print()
        line = line.strip()
        util.parse_URI(line, print_pr)
        break