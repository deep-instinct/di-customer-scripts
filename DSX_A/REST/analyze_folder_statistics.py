import os
import base64
import requests
import time
import warnings
import urllib3
import argparse

warnings.simplefilter('ignore', urllib3.exceptions.InsecureRequestWarning)

#This script is designed to receive a scanner_ip and directory variable to which it will begin a scan of every file in the given directory via a DSX/A scanner. By default, the script will use HTTPS over port 443
#Usage Guide: python analyze_folder_statistics.py -scanner_ip <route to scanner> -directory <directory path to scan>

def scan_file(file_name, scanner_ip, encoded=False, scanner_port=443, protocol='https'):
    with open(file_name, 'rb') as f:
        data = f.read()

    if encoded:
        data = base64.b64encode(data)
        request_url = f'{protocol}://{scanner_ip}:{scanner_port}/scan/base64'
    else:
        request_url = f'{protocol}://{scanner_ip}:{scanner_port}/scan/binary/v2'

    try:
        response = requests.post(request_url, data=data, timeout=60, verify=False)
        if response.status_code == 200:
            verdict = response.json()
            print(f"Scan result for {file_name}: {verdict}")
            return verdict
        else:
            print(f'ERROR: Unexpected return code {response.status_code} on POST to {request_url}')
            return None
    except requests.RequestException as e:
        print(f'ERROR: Request failed for {file_name}: {e}')
        return None

def scan_directory(directory, scanner_ip, encoded=False, scanner_port=443, protocol='https'):
    results = {}
    total_scan_time = 0
    total_file_size = 0
    benign_count = 0
    malicious_count = 0

    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            print(f'Scanning file: {file_path}')
            start_time = time.time()
            verdict = scan_file(file_path, scanner_ip, encoded, scanner_port, protocol)
            end_time = time.time()

            if verdict:
                scan_time = end_time - start_time
                total_scan_time += scan_time

                file_size = verdict['file_info']['file_size_in_bytes']
                total_file_size += file_size

                if verdict['verdict'].lower() == 'benign':
                    benign_count += 1
                elif verdict['verdict'].lower() == 'malicious':
                    malicious_count += 1

                results[file_path] = {
                    'verdict': verdict['verdict'],
                    'file_size': file_size,
                    'scan_time': scan_time
                }

    return results, total_scan_time, total_file_size, benign_count, malicious_count

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan files in a directory and gather statistics.")
    parser.add_argument("-s", "--scanner_ip", required=True, help="IP address of the scanner")
    parser.add_argument("-d", "--directory", required=True, help="Directory containing files to scan")

    args = parser.parse_args()

    scanner_ip = args.scanner_ip
    directory_to_scan = args.directory

    results, total_scan_time, total_file_size, benign_count, malicious_count = scan_directory(directory_to_scan, scanner_ip, encoded=False)

    num_files = len(results)
    average_scan_time = total_scan_time / num_files if num_files > 0 else 0

    print("\nFinal Results:")
    for file, info in results.items():
        print(f"File: {file}, Verdict: {info['verdict']}, Size: {info['file_size']} bytes, Scan Time: {info['scan_time']:.2f} seconds")

    print("\nStatistics:")
    print(f"Total files scanned: {num_files}")
    print(f"Total scan time: {total_scan_time:.2f} seconds")
    print(f"Average scan time per file: {average_scan_time:.2f} seconds")
    print(f"Total size of scanned files: {total_file_size / (1024 ** 2):.2f} MB")
    print(f"Number of benign files: {benign_count}")
    print(f"Number of malicious files: {malicious_count}")