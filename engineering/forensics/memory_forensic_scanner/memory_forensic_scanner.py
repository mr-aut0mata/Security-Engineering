#!/usr/bin/env python3
"""
Memory Artifact Scanner - v2.0
Configured for large File Support (mmap)
"""

import math
import re
import os
import sys
import mmap
import struct
import collections
from datetime import datetime
from typing import Dict, List, Union

# --- CONFIGURATION ---
# Path to your .raw, .mem, or .dmp file.
# If None, the script runs the simulation.
TARGET_FILE = None 

# Tuned Thresholds
# Real encryption/compression is often > 7.5. 7.2 captures too much code.
ENTROPY_THRESHOLD = 7.5       
# Increased NOP sled size to avoid coincidental 0x90 matches in binary data
NOP_SLED_MIN_SIZE = 32        
# Process in 4KB pages (matches standard memory page size)
BLOCK_SIZE = 4096             

class MemoryScanner:
    def __init__(self):
        self.findings = {
            "pe_headers": [],
            "high_entropy_blocks": [],
            "suspicious_strings": [],
            "nop_sleds": []
        }
        
        # Pre-compile regex for performance
        # Global string targets
        self.str_patterns = {
            b"powershell": re.compile(b"powershell", re.IGNORECASE),
            b"cmd.exe": re.compile(b"cmd\.exe", re.IGNORECASE),
            b"kernel32.dll": re.compile(b"kernel32\.dll", re.IGNORECASE),
            b"WScript.Shell": re.compile(b"WScript\.Shell", re.IGNORECASE),
            b"http_proto": re.compile(b"https?://"),
            b"mimikatz": re.compile(b"mimikatz", re.IGNORECASE)
        }
        
        # NOP Sled: Sequence of 0x90
        self.nop_regex = re.compile(b'\x90{' + str(NOP_SLED_MIN_SIZE).encode() + b',}')

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """
        Calculates Shannon entropy using collections.Counter for O(N) performance.
        Previous version was O(256 * N), which is too slow for GB-sized files.
        """
        if not data: return 0.0
        
        length = len(data)
        counts = collections.Counter(data)
        entropy = 0.0
        
        # Math Optimization:
        # H(x) = -sum(p * log2(p))
        # log2(count/len) = log2(count) - log2(len)
        log_len = math.log2(length)
        
        for count in counts.values():
            p = count / length
            entropy -= p * (math.log2(count) - log_len)
            
        return entropy

    @staticmethod
    def is_valid_pe(data: bytes, offset: int, limit: int) -> bool:
        """
        Validates a PE header by checking the e_lfanew pointer.
        Prevents false positives from random 'MZ' bytes.
        """
        try:
            # We need at least 64 bytes to find e_lfanew
            if limit - offset < 0x40: return False
            
            # Read e_lfanew (pointer to PE signature) at offset 0x3C
            # unpack_from requires a buffer, so we slice relative to the view
            # Note: In mmap, slicing returns bytes, which is safe for unpack
            e_lfanew = struct.unpack('<I', data[offset + 0x3C : offset + 0x40])[0]
            
            # Sanity check: PE header shouldn't be miles away (usually < 1KB)
            if e_lfanew > 1024: return False
            
            # Check for 'PE\0\0' signature
            sig_offset = offset + e_lfanew
            if limit - sig_offset < 4: return False
            
            if data[sig_offset : sig_offset + 4] == b'PE\x00\x00':
                return True
                
        except Exception:
            pass
        return False

    def scan_stream(self, data, data_len: int):
        print(f"[*] Scanning {data_len / (1024*1024):.2f} MB of data...")
        start_time = datetime.now()

        # 1. Regex Scanning (Strings & NOPs)
        # Using regex on mmap is efficient (internal C implementation)
        print("[*] Phase 1: Artifact Scanning...")
        for name, pattern in self.str_patterns.items():
            for match in pattern.finditer(data):
                self.findings["suspicious_strings"].append(
                    f"{name.decode()} at {hex(match.start())}"
                )
        
        for match in self.nop_regex.finditer(data):
            self.findings["nop_sleds"].append(
                f"Size {len(match.group())} at {hex(match.start())}"
            )

        # 2. Block Scanning (Entropy & PE Headers)
        # We iterate by blocks to handle entropy. PE headers are checked heuristically.
        print("[*] Phase 2: Block Analysis (Entropy & PE Structures)...")
        
        for i in range(0, data_len, BLOCK_SIZE):
            chunk = data[i : i + BLOCK_SIZE]
            
            # A. Entropy
            entropy = self.calculate_entropy(chunk)
            if entropy > ENTROPY_THRESHOLD:
                self.findings["high_entropy_blocks"].append({
                    "offset": hex(i),
                    "entropy": round(entropy, 2)
                })

            # B. PE Headers
            # We search for 'MZ' in the chunk, then validate
            mz_loc = chunk.find(b'MZ')
            while mz_loc != -1:
                abs_offset = i + mz_loc
                # Only check if it's a valid PE to avoid noise
                if self.is_valid_pe(data, abs_offset, data_len):
                    self.findings["pe_headers"].append(hex(abs_offset))
                
                # Find next MZ in this chunk
                mz_loc = chunk.find(b'MZ', mz_loc + 1)

        duration = datetime.now() - start_time
        print(f"[*] Scan complete in {duration}")
        return self.findings

def run_simulation_mock():
    print("[*] Generating Simulation Data (2MB)...")
    mock = bytearray(b'\x00' * (1024 * 1024 * 2))
    
    # Inject Valid PE (Not just 'MZ')
    base = 0x200
    mock[base:base+2] = b'MZ'
    struct.pack_into('<I', mock, base + 0x3C, 64) # e_lfanew = 64
    mock[base+64:base+68] = b'PE\x00\x00'       # Valid Signature
    
    # Inject NOP Sled
    mock[0x600:0x640] = b'\x90' * 64
    
    # Inject Strings
    mock[0x1000:0x100b] = b'powershell'
    mock[0x1020:0x1027] = b'cmd.exe'
    
    # Inject High Entropy (Encryption)
    mock[0x2000:0x3000] = os.urandom(4096)
    
    return mock

def main():
    scanner = MemoryScanner()
    
    if TARGET_FILE and os.path.exists(TARGET_FILE):
        try:
            with open(TARGET_FILE, "rb") as f:
                # MMAP: Map file into memory without loading it all at once
                # access=mmap.ACCESS_READ is readonly
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    results = scanner.scan_stream(mm, len(mm))
                    print_results(results)
        except Exception as e:
            print(f"[!] Critical Error: {e}")
            sys.exit(1)
    else:
        # Run a mock execution
        mock_data = run_simulation_mock()
        results = scanner.scan_stream(mock_data, len(mock_data))
        print_results(results)

def print_results(results):
    print("\n" + "="*40)
    print("       FORENSIC SCAN REPORT")
    print("="*40)
    
    for category, items in results.items():
        print(f"\n[+] {category.replace('_', ' ').upper()} ({len(items)})")
        if not items:
            print("    No artifacts detected.")
            continue
            
        # Truncated output
        for item in items[:15]:
            if isinstance(item, dict):
                print(f"    Offset: {item['offset']} | Entropy: {item['entropy']}")
            else:
                print(f"    {item}")
        
        if len(items) > 15:
            print(f"    ... {len(items) - 15} more items ...")

if __name__ == "__main__":
    main()
