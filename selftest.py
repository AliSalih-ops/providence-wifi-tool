#!/usr/bin/env python3
"""Convenience wrapper:  python3 selftest.py  (same as python3 -m wifiaudit --selftest)"""
import sys

from wifiaudit.selftest import run

if __name__ == "__main__":
    sys.exit(run())
