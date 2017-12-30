#!/usr/bin/env python
#
# Copyright (C) 2017 Andrew Chow

import fileinput
import util

def print_pr(pr):
    if pr.error:
        print(pr.error)
    else:
        print(pr.data)
        print(pr.details)

if __name__ == '__main__':
    # Command line interface, print welcome message
    print("Bitcoin Payment Protocol Data Viewer")
    print()
    print("Enter a Bitcoin URI:")
    
    for line in fileinput.input():
        line = line.strip()
        try:
            util.parse_URI(line, print_pr)
            break
        except Exception as e:
            print(e)
            print("Something failed")
            break