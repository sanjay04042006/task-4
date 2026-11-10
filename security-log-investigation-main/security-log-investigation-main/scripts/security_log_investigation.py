#!/usr/bin/env python3
"""
Security Log Investigation Analysis Script
Designed to normalize authentication logs, detect brute force, password spraying, 
and unusual access, and reconstruct an incident timeline.
"""

import pandas as pd
import numpy as np

def load_and_normalize(csv_path):
    print(f"[*] Loading log file: {csv_path}")
    df = pd.read_csv(csv_path)
    
    # 1. Normalize column names
    df.columns = [c.strip().lower() for c in df.columns]
    
    # 2. Normalize timestamps
    timestamp_col = next((col for col in ['timestamp', 'time', 'date', 'datetime'] if col in df.columns), df.columns[0])
    df['normalized_timestamp'] = pd.to_datetime(df[timestamp_col], errors='coerce')
    
    # 3. Normalize accounts & IPs
    account_col = next((col for col in ['account', 'user', 'username', 'target_user'] if col in df.columns), None)
    if account_col:
        df['normalized_account'] = df[account_col].astype(str).str.lower().str.strip()
        
    ip_col = next((col for col in ['ip', 'source_ip', 'ip_address', 'client_ip'] if col in df.columns), None)
    if ip_col:
        df['normalized_ip'] = df[ip_col].astype(str).str.strip()
        
    # 4. Normalize results / actions
    result_col = next((col for col in ['result', 'status', 'outcome', 'response'] if col in df.columns), None)
    if result_col:
        df['normalized_result'] = df[result_col].astype(str).str.upper().str.strip()
        df['is_failure'] = df['normalized_result'].isin(['FAIL', 'FAILURE', 'DENIED', 'INVALID', 'UNAUTHORIZED', '401', 'ERROR'])
        df['is_success'] = df['normalized_result'].isin(['SUCCESS', 'OK', 'PASSED', 'ALLOW', '200'])
    
    print("[+] Normalization complete.")
    return df

def detect_attacks(df):
    print("[*] Running detection rules...")
    
    # Rule 1: Brute Force Detection
    print("\n--- Rule 1: Brute Force Detection ---")
    if 'normalized_account' in df.columns and 'normalized_ip' in df.columns and 'is_failure' in df.columns:
        bf_groups = df[df['is_failure']].groupby(['normalized_ip', 'normalized_account']).size().reset_index(name='failure_count')
        brute_force_suspects = bf_groups[bf_groups['failure_count'] >= 5]
        print(brute_force_suspects.to_string(index=False))
        
    # Rule 2: Password Spraying Detection
    print("\n--- Rule 2: Password Spraying Detection ---")
    if 'normalized_ip' in df.columns and 'normalized_account' in df.columns and 'is_failure' in df.columns:
        spray_groups = df[df['is_failure']].groupby('normalized_ip')['normalized_account'].nunique().reset_index(name='unique_accounts_targeted')
        sprayers = spray_groups[spray_groups['unique_accounts_targeted'] >= 3]
        print(sprayers.to_string(index=False))

if __name__ == "__main__":
    import sys
    csv_file = sys.argv[1] if len(sys.argv) > 1 else "data/synthetic_authentication_log.csv"
    try:
        data = load_and_normalize(csv_file)
        detect_attacks(data)
    except Exception as e:
        print(f"[!] Error: {e}")
