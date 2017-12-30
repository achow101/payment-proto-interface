#!/usr/bin/env python
#
# Copyright (C) 2017 Andrew Chow

import util

def print_pr(pr):
    if pr.error:
        print(pr.error)
        exit()
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

        # Prompt to send transaction
        print("To continue, send the necessary amounts of Bitcoin to the addresses specified in the 'Outputs' field above. Once broadcast, press ENTER.")
        input()

        # Only do this if there is a Payment URL
        if pr.details.payment_url:
            # Get raw tx and refund address for Payment message
            raw_tx = input("Enter the hex of the transaction that was just made: ").strip()
            ref_addr = input("Enter a refund address: ").strip()
            print(raw_tx)
            print(ref_addr)

            # Send payment message and wait for ACK
            result = pr.send_ack(raw_tx, ref_addr)
            if result[0]:
                print(result[1])
            else:
                print(result[1])
                exit()

if __name__ == '__main__':
    # Command line interface, print welcome message
    print("Bitcoin Payment Protocol Interface")
    print()

    # Get the payment request
    uri = input("Enter a Bitcoin URI: ").strip()
    print()
    util.parse_URI(uri, print_pr)
    print()
    print("Payment complete!")
