#!/usr/bin/env python3
"""
PHANTOM TRACE - Cross-Layer Consistency Validator
Module: MFT vs. $Bitmap Paradox Detector

Detects anti-forensic manipulation where MFT records are marked 'In Use'
but the corresponding clusters are marked 'Free' in the $Bitmap, or vice versa.
"""

import struct
import sys
import argparse
from dataclasses import dataclass

# NTFS Constants
SECTOR_SIZE = 512
MFT_RECORD_6_BITMAP = 6  # $Bitmap is usually record 6

@dataclass
class NtfsSuperblock:
    bytes_per_sector: int
    sectors_per_cluster: int
    cluster_size: int
    mft_lcn: int  # Logical Cluster Number of $MFT
    mftmirr_lcn: int
    total_clusters: int

@dataclass
class MftRecordHeader:
    magic: bytes
    usa_offset: int
    usa_count: int
    lsn: int
    sequence_number: int
    link_count: int
    first_attr_offset: int
    flags: int  # 0x01 = In Use, 0x02 = Directory
    used_size: int
    allocated_size: int
    base_record: int
    next_attr_id: int

def read_raw_data(handle, offset, length):
    """Safe raw read with error handling."""
    handle.seek(offset)
    data = handle.read(length)
    if len(data) != length:
        raise EOFError(f"Unexpected EOF at offset {offset}")
    return data

def parse_boot_sector(handle):
    """Parse the NTFS Boot Sector (Volume Boot Record)."""
    print("[*] Parsing Boot Sector...")
    bs_data = read_raw_data(handle, 0, SECTOR_SIZE)
    
    if bs_data[0:3] != b'\xEB\x52\x90' and bs_data[0:3] != b'\xEB\x52\x00': # Common JMP signatures
        # Some images might not have standard jump, check OEM ID instead
        if bs_data[3:11] != b'NTFS    ':
            print("[!] Warning: Does not look like a standard NTFS volume, proceeding anyway...")

    bytes_per_sector = struct.unpack('<H', bs_data[11:13])[0]
    sectors_per_cluster = bs_data[13]
    cluster_size = bytes_per_sector * sectors_per_cluster
    
    # Reserved sectors (usually 0 for NTFS data area start relative to partition)
    # We assume handle is seeked to start of Volume (Partition Boot Sector)
    
    mft_lcn = struct.unpack('<Q', bs_data[48:56])[0]
    mftmirr_lcn = struct.unpack('<Q', bs_data[56:64])[0]
    
    # Total clusters (approximate from serial number offset if needed, but usually at 0x28 for older, 
    # for modern NTFS we often derive from partition size or rely on $Bitmap size later)
    # For this prototype, we will dynamically determine range based on $Bitmap size.
    
    sb = NtfsSuperblock(
        bytes_per_sector=bytes_per_sector,
        sectors_per_cluster=sectors_per_cluster,
        cluster_size=cluster_size,
        mft_lcn=mft_lcn,
        mftmirr_lcn=mftmirr_lcn,
        total_clusters=0 # To be determined
    )
    print(f"    Cluster Size: {sb.cluster_size} bytes")
    print(f"    MFT Start LCN: {sb.mft_lcn}")
    return sb

def parse_mft_record_header(data):
    """Parse the standard MFT Record Header (First 48 bytes)."""
    if len(data) < 48:
        return None
    
    magic = data[0:4]
    if magic != b'FILE':
        return None

    usa_offset = struct.unpack('<H', data[4:6])[0]
    usa_count = struct.unpack('<H', data[6:8])[0]
    lsn = struct.unpack('<Q', data[8:16])[0]
    sequence_number = struct.unpack('<H', data[16:18])[0]
    link_count = struct.unpack('<H', data[18:20])[0]
    first_attr_offset = struct.unpack('<H', data[20:22])[0]
    flags = struct.unpack('<H', data[22:24])[0]
    used_size = struct.unpack('<I', data[24:28])[0]
    allocated_size = struct.unpack('<I', data[28:32])[0]
    base_record = struct.unpack('<Q', data[32:40])[0] # Lower 4 bytes + Upper 4 (seq) usually
    next_attr_id = struct.unpack('<H', data[40:42])[0]
    
    return MftRecordHeader(
        magic=magic,
        usa_offset=usa_offset,
        usa_count=usa_count,
        lsn=lsn,
        sequence_number=sequence_number,
        link_count=link_count,
        first_attr_offset=first_attr_offset,
        flags=flags,
        used_size=used_size,
        allocated_size=allocated_size,
        base_record=base_record,
        next_attr_id=next_attr_id
    )

def get_bitmap_data(handle, sb, mft_records):
    """
    Locate $Bitmap (Record 6), extract its data attribute, and return the raw bitmap.
    Simplified: Assumes non-resident $Bitmap stored in standard runs.
    """
    print("[*] Locating $Bitmap (MFT Record 6)...")
    
    # Read Record 6
    record_offset = sb.mft_lcn * sb.cluster_size
    record_size = 1024 # Standard MFT record size usually 1024, can be dynamic
    record_data = read_raw_data(handle, record_offset + (MFT_RECORD_6_BITMAP * record_size), record_size)
    
    header = parse_mft_record_header(record_data)
    if not header:
        raise ValueError("Failed to parse MFT Record 6 ($Bitmap)")
    
    # Parse Attributes to find $DATA (Type 0x80)
    # This is a simplified attribute parser for the prototype
    offset = header.first_attr_offset
    bitmap_buffer = b''
    bitmap_lcn_start = 0
    bitmap_size = 0
    
    while offset < len(record_data) - 4:
        attr_type = struct.unpack('<I', record_data[offset:offset+4])[0]
        if attr_type == 0xFFFFFFFF:
            break
            
        attr_len = struct.unpack('<I', record_data[offset+4:offset+8])[0]
        if attr_len == 0: break
        
        # Check for $DATA (0x80)
        if attr_type == 0x80:
            non_resident_flag = record_data[offset+8]
            if non_resident_flag == 1:
                # Non-resident data (standard for $Bitmap on large volumes)
                starting_vcn = struct.unpack('<Q', record_data[offset+16:offset+24])[0]
                ending_vcn = struct.unpack('<Q', record_data[offset+24:offset+32])[0]
                runlist_offset = struct.unpack('<H', record_data[offset+32:offset+34])[0]
                
                # Calculate total size
                bitmap_size = (ending_vcn - starting_vcn + 1) * sb.cluster_size
                
                # Parse Runlist
                run_offset = offset + runlist_offset
                current_lcn = 0
                decoded_runs = []
                
                while True:
                    if run_offset >= len(record_data): break
                    header_byte = record_data[run_offset]
                    if header_byte == 0: break
                    
                    len_size = header_byte & 0x0F
                    val_size = (header_byte >> 4) & 0x0F
                    
                    if len_size == 0 or val_size == 0: break
                    
                    run_len_bytes = record_data[run_offset+1 : run_offset+1+len_size]
                    run_len = int.from_bytes(run_len_bytes, byteorder='little', signed=False)
                    
                    run_offset_bytes = record_data[run_offset+1+len_size : run_offset+1+len_size+val_size]
                    run_offset_val = int.from_bytes(run_offset_bytes, byteorder='little', signed=True)
                    
                    if starting_vcn == 0 and not decoded_runs:
                        current_lcn = run_offset_val
                    else:
                        current_lcn += run_offset_val
                        
                    decoded_runs.append((current_lcn, run_len))
                    current_lcn += run_len # Prepare for next relative offset
                    
                    run_offset += 1 + len_size + val_size
                
                # Read the bitmap data from disk based on runs
                # Note: This assumes contiguous or simple runs for the prototype
                # In a full tool, we'd map VCN to LCN perfectly.
                # Here we just grab the first run assuming $Bitmap is usually contiguous at start
                if decoded_runs:
                    first_lcn, first_len = decoded_runs[0]
                    read_size = first_len * sb.cluster_size
                    # Cap read size to reasonable limit for prototype safety if needed
                    bitmap_buffer = read_raw_data(handle, first_lcn * sb.cluster_size, read_size)
                    bitmap_lcn_start = first_lcn
                break
        offset += attr_len

    return bitmap_buffer, bitmap_size

def check_consistency(handle, sb, bitmap_data, bitmap_size_bits):
    """
    Iterate MFT and compare against Bitmap.
    """
    print("[*] Starting Cross-Layer Consistency Validation...")
    print(f"    Scanning MFT records against {bitmap_size_bits} bits of bitmap data.")
    
    paradoxes = []
    record_size = 1024 # Assumption for prototype; real tool detects this from BPB or $MFT itself
    mft_end = (sb.mft_lcn * sb.cluster_size) + (len(bitmap_data) // 8 * 8) # Rough estimate
    
    # We scan a reasonable chunk of MFT. 
    # In reality, $MFT size is in its own header. We'll scan up to the bitmap size equivalent as a safe guard
    max_records = min(10000, bitmap_size_bits) 
    
    for i in range(max_records):
        if i == MFT_RECORD_6_BITMAP: continue # Skip bitmap itself
        
        offset = (sb.mft_lcn * sb.cluster_size) + (i * record_size)
        try:
            rec_data = read_raw_data(handle, offset, 48) # Just read header first
            if rec_data[0:4] != b'FILE':
                continue
                
            # Read full record
            full_rec = read_raw_data(handle, offset, record_size)
            header = parse_mft_record_header(full_rec)
            if not header: continue
            
            mft_in_use = (header.flags & 0x01) == 0x01
            
            # Check Bitmap
            # Bitwise check: byte_index = i // 8, bit_index = i % 8
            byte_idx = i // 8
            bit_idx = i % 8
            
            if byte_idx >= len(bitmap_data):
                bitmap_in_use = False # Beyond known bitmap
            else:
                byte_val = bitmap_data[byte_idx]
                bitmap_in_use = ((byte_val >> bit_idx) & 1) == 1
            
            # DETECT PARADOX
            if mft_in_use and not bitmap_in_use:
                paradoxes.append({
                    'record': i,
                    'type': 'MFT_SAYS_USED_BITMAP_SAYS_FREE',
                    'desc': 'Potential MFT Patching / Rootkit Activity'
                })
            elif not mft_in_use and bitmap_in_use:
                # Less common, could be slack space or lost clusters
                paradoxes.append({
                    'record': i,
                    'type': 'MFT_SAYS_FREE_BITMAP_SAYS_USED',
                    'desc': 'Lost Cluster or Delayed Deletion'
                })
                
        except EOFError:
            break
        except Exception as e:
            continue

    return paradoxes

def main():
    parser = argparse.ArgumentParser(description="PhantomTrace: MFT vs $Bitmap Paradox Detector")
    parser.add_argument("target", help="Path to raw device (e.g., \\\\.\\C:) or raw image file (.img)")
    args = parser.parse_args()

    print(r"""
    ____  _               _   __                  _   
   |  _ \| | __ _ _ __   | |_/ /_ _ _ __ ___  ___| |_ 
   | |_) | |/ _` | '_ \  | __/ _` | '__/ _ \/ __| __|
   |  __/| | (_| | | | | | || (_| | | |  __/\__ \ |_ 
   |_|   |_|\__,_|_| |_|  \__\__,_|_|  \___||___/\__|
   
   [MODULE]: MFT vs. $Bitmap Consistency Checker
   [LEVEL]: NSA / Tier 3 Forensics
    """)

    try:
        mode = 'rb'
        with open(args.target, mode) as f:
            sb = parse_boot_sector(f)
            bitmap_data, bitmap_bits = get_bitmap_data(f, sb, [])
            
            if not bitmap_data:
                print("[!] Failed to extract $Bitmap data.")
                sys.exit(1)
                
            results = check_consistency(f, sb, bitmap_data, len(bitmap_data)*8)
            
            print("\n--- ANALYSIS COMPLETE ---")
            if results:
                print(f"[!!!] FOUND {len(results)} PARADOXES [!!!]")
                for res in results:
                    print(f"    RECORD {res['record']}: {res['type']}")
                    print(f"           -> {res['desc']}")
                print("\n[!] RECOMMENDATION: Immediate memory dump and triage required.")
            else:
                print("[+] No obvious MFT/Bitmap inconsistencies detected.")
                
    except PermissionError:
        print("[ERROR] Permission denied. Please run as Administrator/Root.")
        print("        Or use a raw image file instead of a live device.")
        sys.exit(1)
    except FileNotFoundError:
        print(f"[ERROR] Target '{args.target}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Critical failure: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()