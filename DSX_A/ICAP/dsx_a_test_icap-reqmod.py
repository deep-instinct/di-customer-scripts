import argparse
import logging
import socket
import sys
from typing import List

logger = logging.getLogger()
logging.basicConfig(level=logging.DEBUG)

#USAGE: python dsx_a_test_icap_reqmod.py -s <scanner-ip> -f <path to the file and file name>

def send_icap_content(scanner_ip: str, file_content: bytes):
    service = f'icap://{scanner_ip}/request'.encode('latin-1')
    port = 1344
    logger.info(f'Sending scan request to {service.decode()} on port {port}')
    sock = _establish_socket_connection(host=scanner_ip, port=port)
    chunks, req = _create_icap_request_parts(file_content=file_content)
    _send_content(content_chunks=chunks, perimeter_ip=scanner_ip, req=req, service=service, sock=sock)
    response = _receive_response(sock=sock)
    result_content, header, verdict = _parse_response(response=response)
    return result_content, header, verdict

def _parse_response(response: bytes):
    logger.debug(f"Raw response received: {response}")
    
    # Split response into sections
    sections = response.strip().split(b'\r\n\r\n')
    logger.debug(f"Number of sections in response: {len(sections)}")
    
    # Handle case where we don't get all expected sections
    icap_headers_bytes = sections[0] if sections else b''
    http_headers_bytes = sections[1] if len(sections) > 1 else b''
    content = sections[2] if len(sections) > 2 else b''
    
    # Decode headers if present
    icap_headers = icap_headers_bytes.decode(errors='ignore')
    http_headers = http_headers_bytes.decode(errors='ignore')
    
    logger.info(f'ICAP response headers are: {icap_headers}')
    logger.debug(f'HTTP headers are: {http_headers}')
    
    # Check for malware in ICAP headers
    verdict = 'Malicious' if 'Malware' in icap_headers else 'Benign'
    
    if verdict == 'Benign' and b'content-length: ' in response:
        try:
            file_data_raw = response.split(b'content-length: ')[1]
            res_lines = file_data_raw.splitlines()
            file_data_length = int(res_lines[0])
            start_bytes = b''
            start_bytes += res_lines[0]
            start_bytes += b'\r\n\r\n'
            start_bytes += res_lines[2]
            start_bytes += b'\r\n'
            file_data_raw = file_data_raw[len(start_bytes):]
            return file_data_raw[:file_data_length], icap_headers, verdict
        except (IndexError, ValueError) as e:
            logger.warning(f"Error parsing content length: {e}")
            return b'', icap_headers, verdict
    else:
        return b'', icap_headers, verdict

def _receive_response(sock: socket.socket) -> bytes:
    sock.shutdown(socket.SHUT_WR)
    response = b""
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                break
            response += data
        except socket.error as e:
            logger.error(f"Error receiving data: {e}")
            break
    sock.close()
    return response

def _send_content(content_chunks: List, perimeter_ip: str, req: bytes, service: bytes,
                  sock: socket.socket):
    try:
        # Fixed the string encoding issue
        encapsulated = f"Encapsulated: req-hdr=0, req-body={len(req)}".encode('latin-1') + b"\r\n"
        
        send_messages = [
            b"REQMOD %s ICAP/1.0\r\n" % service,
            b"Host: %s\r\n" % (perimeter_ip.encode('latin-1')),
            encapsulated,
            b"\r\n",
            req
        ]
        
        for message in send_messages:
            sock.send(message)
        
        for chunk in content_chunks:
            chunk_size = hex((len(chunk)))[2:].encode('latin-1')
            sock.send(chunk_size + b"\r\n")
            sock.send(chunk + b'\r\n')
        
        sock.send(b"0\r\n")
        sock.send(b"\r\n")
        
        logger.debug("Successfully sent all content to ICAP server")
    except socket.error as e:
        logger.error(f"Error sending content: {e}")
        raise

def _create_icap_request_parts(file_content: bytes):
    # Fixed the string encoding for Content-Length
    req = (
        b"POST /upload HTTP/1.1\r\n"
        b"Host: www.origin-server.com\r\n"
        b"Content-Type: application/octet-stream\r\n"
    ) + f"Content-Length: {len(file_content)}\r\n\r\n".encode('latin-1')
    
    chunks = [file_content[i:i + 1000] for i in range(0, len(file_content), 1000)]
    return chunks, req

def _establish_socket_connection(host: str, port: int):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as msg:
        logger.info(f"SOCKET CREATION ERROR: {msg}")
        sys.exit(1)
    try:
        sock.connect((host, port))
    except socket.error as msg:
        logger.info(f"SOCKET CONNECTION ERROR: {msg}")
        sys.exit(2)
    return sock

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--scanner-ip', action='store', dest='scanner_ip', required=True)
    parser.add_argument('-f', '--file-path', action='store', dest='file_path', required=True)
    return parser.parse_args()

def main():
    args = parse_args()
    with open(args.file_path, 'rb') as f:
        content = f.read()
        result_content, header, verdict = send_icap_content(scanner_ip=args.scanner_ip, file_content=content)
        logger.info(f'Verdict is {verdict}')

if __name__ == '__main__':
    main()
