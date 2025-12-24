import math
import re
import os
import sys

# --- CONFIGURATION ---
# Change this to the path of your .raw or .mem dump file.
# If left as None, the script will run a simulation with mock data.
TARGET_FILE = None 

# Thresholds
ENTROPY_THRESHOLD = 7.2  # Values near 8.0 usually indicate encryption/packing
NOP_SLED_MIN_SIZE = 16   # Minimum number of 0x90 bytes to trigger an alert
BLOCK_SIZE = 1024        # Size of memory chunks for entropy calculation

def calculate_entropy(data):
    """
    Calculates Shannon entropy. 
    Returns a value between 0 (predictable) and 8 (completely random).
    Used to detect encrypted payloads or packed malware.
    """
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def scan_memory(dump_bytes):
    """
    Scans a byte array for forensic artifacts.
    """
    findings = {
        "pe_headers": [],
        "high_entropy_blocks": [],
        "suspicious_strings": [],
        "nop_sleds": []
    }

    # 1. PE Header Search (MZ signatures)
    # Identifies executables or DLLs mapped in the dump.
    for match in re.finditer(b'MZ', dump_bytes):
        findings["pe_headers"].append(hex(match.start()))

    # 2. Suspicious String Search
    # Targets common tools used in fileless attacks or post-exploitation.
    targets = [
        b"powershell", b"cmd.exe", b"kernel32.dll", 
        b"WScript.Shell", b"http://", b"https://"
    ]
    for target in targets:
        for match in re.finditer(target, dump_bytes, re.IGNORECASE):
            findings["suspicious_strings"].append(
                f"'{target.decode()}' at {hex(match.start())}"
            )

    # 3. NOP Sled Search
    # Identifies potential shellcode or exploit padding.
    pattern = b'\x90{' + str(NOP_SLED_MIN_SIZE).encode() + b',}'
    for match in re.finditer(pattern, dump_bytes):
        findings["nop_sleds"].append(
            f"Size {len(match.group())} at {hex(match.start())}"
        )

    # 4. Entropy Analysis
    # Scans for blocks that are likely encrypted or compressed.
    for i in range(0, len(dump_bytes), BLOCK_SIZE):
        block = dump_bytes[i:i+BLOCK_SIZE]
        entropy = calculate_entropy(block)
        if entropy > ENTROPY_THRESHOLD:
            findings["high_entropy_blocks"].append({
                "offset": hex(i),
                "entropy": round(entropy, 2)
            })

    return findings

def run_simulation():
    """
    Generates a fake memory dump to demonstrate detection capabilities.
    """
    print("Running simulation with mock data...\n")
    mock_mem = bytearray(b'\x00' * 10240)
    
    # Inject artifacts
    mock_mem[0x200:0x202] = b'MZ'              # Executable header
    mock_mem[0x600:0x620] = b'\x90' * 32        # NOP sled
    mock_mem[0x1000:0x100b] = b'powershell'    # Malicious string
    mock_mem[0x2000:0x2400] = os.urandom(1024) # High entropy block
    
    return mock_mem

def main():
    if TARGET_FILE and os.path.exists(TARGET_FILE):
        print(f"Opening {TARGET_FILE}...")
        try:
            with open(TARGET_FILE, "rb") as f:
                data = f.read()
        except Exception as e:
            print(f"Error reading file: {e}")
            sys.exit(1)
    else:
        data = run_simulation()

    results = scan_memory(data)

    # Output Results
    for category, items in results.items():
        header = category.replace('_', ' ').upper()
        print(f"[{header}]")
        if not items:
            print("  - No artifacts detected.")
        else:
            for item in items:
                if isinstance(item, dict):
                    print(f"  - Offset {item['offset']} | Entropy: {item['entropy']}")
                else:
                    print(f"  - {item}")
        print("-" * 40)

if __name__ == "__main__":
    main()
