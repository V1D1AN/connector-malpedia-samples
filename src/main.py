#!/usr/bin/env python3
"""
Malpedia Samples — OpenCTI external-import connector.

Downloads malware samples from Malpedia (trust-group account required)
and uploads them as Artifacts in OpenCTI, linked to their Malware family,
Intrusion Sets and YARA rules.
"""

from malpedia_samples.connector import MalpediaSamplesConnector

if __name__ == "__main__":
    connector = MalpediaSamplesConnector()
    connector.run()
