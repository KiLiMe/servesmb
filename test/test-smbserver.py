#!/usr/bin/env python3

import socket
import struct
import time

def send_netbios_msg(sock, data):
    """Send data with NetBIOS session header"""
    nb_header = struct.pack('>I', len(data))
    sock.send(nb_header + data)

def recv_netbios_msg(sock):
    """Receive data with NetBIOS session header"""
    nb_header = sock.recv(4)
    if len(nb_header) < 4:
        return b''
    msg_len = struct.unpack('>I', nb_header)[0] & 0xFFFFFF
    return sock.recv(msg_len)

def create_smb2_negotiate():
    """Create SMB2 negotiate request"""
    # SMB2 Header
    protocol_id = b'\xFE\x53\x4D\x42'  # SMB2/3 signature
    structure_size = 64
    credit_charge = 0
    channel_sequence = 0
    status = 0
    command = 0x0000  # SMB2_NEGOTIATE
    credit_request = 1
    flags = 0
    next_command = 0
    message_id = 1
    process_id = 0
    tree_id = 0
    session_id = 0
    signature = b'\x00' * 16
    
    header = struct.pack('<4sHHHIHHIQIII16s',
                        protocol_id, structure_size, credit_charge, channel_sequence,
                        status, command, credit_request, flags, next_command,
                        message_id, process_id, tree_id, session_id, signature)
    
    # Negotiate request data
    structure_size_req = 36
    dialect_count = 3
    security_mode = 1
    reserved = 0
    capabilities = 0
    client_guid = b'\x00' * 16
    client_start_time = 0
    
    # Dialects: SMB 2.002, SMB 2.1, SMB 3.0
    dialects = struct.pack('<HHH', 0x0202, 0x0210, 0x0300)
    
    data = struct.pack('<HHHHLQ16s', structure_size_req, dialect_count, 
                      security_mode, reserved, capabilities, 
                      client_start_time, client_guid) + dialects
    
    return header + data

def test_smb_server():
    """Test SMB server functionality"""
    print("Testing SMB server on localhost:8445...")
    
    try:
        # Connect to server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('127.0.0.1', 8445))
        sock.settimeout(5.0)
        print("✓ Connected to SMB server")
        
        # Send SMB2 Negotiate
        negotiate_msg = create_smb2_negotiate()
        send_netbios_msg(sock, negotiate_msg)
        print("✓ Sent SMB2 negotiate request")
        
        # Receive response
        response = recv_netbios_msg(sock)
        if len(response) >= 64:
            # Check SMB2 signature
            if response[:4] == b'\xFE\x53\x4D\x42':
                print("✓ Received valid SMB2 negotiate response")
                command = struct.unpack('<H', response[12:14])[0]
                status = struct.unpack('<I', response[8:12])[0]
                print(f"  Command: 0x{command:04X}, Status: 0x{status:08X}")
                
                if status == 0:  # STATUS_SUCCESS
                    print("✓ SMB negotiate successful!")
                else:
                    print(f"✗ SMB negotiate failed with status: 0x{status:08X}")
            else:
                print(f"✗ Invalid SMB signature: {response[:4]}")
        else:
            print(f"✗ Response too short: {len(response)} bytes")
            
        sock.close()
        print("✓ Connection closed")
        
    except socket.timeout:
        print("✗ Connection timeout")
    except Exception as e:
        print(f"✗ Test failed: {e}")

def test_file_operations():
    """Test file operations by checking shares directory"""
    import os
    print("\nTesting file system setup...")
    
    shares_dir = "./shares"
    public_dir = "./shares/public"
    test_dir = "./shares/test"
    
    # Check shares directory structure
    if os.path.exists(shares_dir):
        print(f"✓ Shares directory exists: {shares_dir}")
    else:
        print(f"✗ Shares directory missing: {shares_dir}")
        
    if os.path.exists(public_dir):
        print(f"✓ PUBLIC share directory exists: {public_dir}")
        files = os.listdir(public_dir)
        print(f"  Files in PUBLIC: {files}")
    else:
        print(f"✗ PUBLIC share directory missing: {public_dir}")
        
    if os.path.exists(test_dir):
        print(f"✓ TEST share directory exists: {test_dir}")
        files = os.listdir(test_dir)
        print(f"  Files in TEST: {files}")
    else:
        print(f"✗ TEST share directory missing: {test_dir}")

if __name__ == '__main__':
    test_file_operations()
    test_smb_server()
    print("\nTest completed!")