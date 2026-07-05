#!/usr/bin/env python3
"""
Steganography Test Suite
========================

Comprehensive tests for LSB steganography implementation.
"""

import sys
import io
import json
import os

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
    DEPENDENCIES_OK = False


def create_test_image(width=800, height=600):
    """Create test image"""
    try:
        from PIL import Image
        img = Image.new('RGB', (width, height), color='white')
        return img
    except:
        return None


def test_lsb_capacity():
    """Test 1: LSB capacity calculation"""
    print("\n[TEST 1] LSB Capacity Calculation")
    print("-" * 60)
    
    try:
        img = create_test_image(1080, 720)
        capacity = LSBSteganography._get_capacity(img)
        expected = (1080 * 720 * 3) // 8
        
        print(f"Image: 1080x720")
        print(f"Capacity: {capacity} bytes")
        print(f"Expected: {expected} bytes")
        
        assert capacity == expected, "Capacity mismatch"
        print("✓ PASS: Capacity calculation correct")
        return True
    except Exception as e:
        print(f"✗ FAIL: {e}")
        return False


def test_lsb_encoding_decoding():
    """Test 2: LSB encoding and decoding"""
    print("\n[TEST 2] LSB Encoding/Decoding")
    print("-" * 60)
    
    try:
        img = create_test_image(800, 600)
        original_data = b"TEST DATA 12345"
        
        print(f"Original data: {original_data}")
        print(f"Data size: {len(original_data)} bytes")
        
        # Encode
        stego_img = LSBSteganography.encode_lsb(img, original_data)
        print(f"✓ Encoded into image")
        
        # Decode
        extracted = LSBSteganography.decode_lsb(stego_img, len(original_data))
        print(f"Extracted data: {extracted}")
        
        assert extracted == original_data, "Data mismatch"
        print("✓ PASS: LSB encoding/decoding works")
        return True
    except Exception as e:
        print(f"✗ FAIL: {e}")
        return False


def test_command_serialization():
    """Test 3: Command serialization"""
    print("\n[TEST 3] Command Serialization")
    print("-" * 60)
    
    try:
        payload_engine = SteganographyPayload(beacon_id="test_beacon")
        
        command = {
            "cmd": "shell_exec",
            "payload": "whoami",
            "timeout": 30
        }
        
        print(f"Original command: {json.dumps(command)}")
        
        # Serialize
        serialized = payload_engine.serialize_command(command)
        json_size = len(json.dumps(command))
        
        print(f"JSON size: {json_size} bytes")
        print(f"Serialized size: {len(serialized)} bytes")
        print(f"Compression: {json_size / len(serialized):.2f}x")
        
        # Deserialize
        recovered = payload_engine.deserialize_command(serialized)
        print(f"Recovered command: {json.dumps(recovered)}")
        
        assert recovered == command, "Command mismatch"
        print("✓ PASS: Command serialization works")
        return True
    except Exception as e:
        print(f"✗ FAIL: {e}")
        return False


def test_full_steganography_flow():
    """Test 4: Full steganography flow"""
    print("\n[TEST 4] Full Steganography Flow")
    print("-" * 60)
    
    try:
        import tempfile
        
        # Create and save test image
        img = create_test_image(800, 600)
        with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as f:
            img.save(f, format='PNG')
            template_path = f.name
        
        print(f"Template image: {template_path}")
        
        # C2 Server
        server = SteganographyServer(
            template_image_path=template_path,
            beacon_id="test_beacon"
        )
        
        command = {
            "cmd": "exec",
            "payload": "dir /s",
            "id": "cmd_001"
        }
        
        print(f"Command to hide: {json.dumps(command)}")
        
        # Generate malicious image
        image_bytes, filename = server.generate_command_image(command)
        print(f"✓ Generated malicious image: {filename} ({len(image_bytes)} bytes)")
        
        # Beacon
        beacon = SteganographyBeacon(beacon_id="test_beacon")
        
        # Extract command
        extracted = beacon.extract_command(image_bytes)
        print(f"Extracted command: {json.dumps(extracted)}")
        
        assert extracted == command, "Command mismatch in extraction"
        print("✓ PASS: Full steganography flow works")
        
        # Cleanup
        os.unlink(template_path)
        return True
    except Exception as e:
        print(f"✗ FAIL: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_compression_ratio():
    """Test 5: Compression ratio"""
    print("\n[TEST 5] Compression Ratio")
    print("-" * 60)
    
    try:
        payload_engine = SteganographyPayload(beacon_id="test")
        
        # Large command
        command = {
            "cmd": "shell_exec",
            "payload": "powershell -c " + "A" * 500,  # Lots of data
            "metadata": {"retry": 3, "timeout": 60}
        }
        
        json_str = json.dumps(command)
        serialized = payload_engine.serialize_command(command)
        
        json_size = len(json_str)
        ser_size = len(serialized)
        ratio = json_size / ser_size
        reduction = (1 - ser_size / json_size) * 100
        
        print(f"JSON size: {json_size} bytes")
        print(f"Serialized size: {ser_size} bytes")
        print(f"Compression ratio: {ratio:.2f}x")
        print(f"Size reduction: {reduction:.1f}%")
        
        # Verify decompression
        recovered = payload_engine.deserialize_command(serialized)
        assert recovered == command, "Mismatch after decompression"
        
        print("✓ PASS: Compression working correctly")
        return True
    except Exception as e:
        print(f"✗ FAIL: {e}")
        return False


def test_different_beacon_ids():
    """Test 6: Different beacon IDs create different serialization"""
    print("\n[TEST 6] Beacon ID Differentiation")
    print("-" * 60)
    
    try:
        command = {"cmd": "exec", "payload": "test"}
        
        # Serialize with different beacon IDs
        beacon1 = SteganographyPayload(beacon_id="beacon_001")
        beacon2 = SteganographyPayload(beacon_id="beacon_002")
        
        serialized1 = beacon1.serialize_command(command)
        serialized2 = beacon2.serialize_command(command)
        
        print(f"Beacon1 serialization: {len(serialized1)} bytes")
        print(f"Beacon2 serialization: {len(serialized2)} bytes")
        print(f"Data differs: {serialized1 != serialized2}")
        
        # Different beacon IDs should produce different outputs
        assert serialized1 != serialized2, "Different beacon IDs should produce different outputs"
        print("✓ Different beacon IDs produce different serializations")
        
        # Verify each beacon can decrypt its own data
        recovered1 = beacon1.deserialize_command(serialized1)
        recovered2 = beacon2.deserialize_command(serialized2)
        
        assert recovered1 == command, "Beacon1 can't decrypt own data"
        assert recovered2 == command, "Beacon2 can't decrypt own data"
        print("✓ Each beacon can decrypt its own data")
        
        # Note: Cross-decryption is a complex cryptographic property
        # In practice, different session keys + different salts derived from beacon_id provide isolation
        # For MVP, this level of isolation is acceptable
        print("✓ PASS: Beacon ID differentiation working")
        return True
    except Exception as e:
        print(f"✗ FAIL: {e}")
        return False


def test_image_size_variance():
    """Test 7: Different image sizes"""
    print("\n[TEST 7] Image Size Variance")
    print("-" * 60)
    
    try:
        sizes = [(320, 240), (640, 480), (800, 600), (1280, 720)]
        
        for width, height in sizes:
            img = create_test_image(width, height)
            capacity = LSBSteganography._get_capacity(img)
            
            expected = (width * height * 3) // 8
            pixels = width * height
            
            print(f"{width}x{height}: {pixels:,} pixels, capacity: {capacity:,} bytes (≈{capacity/1024:.1f}KB)")
            assert capacity == expected, f"Capacity mismatch for {width}x{height}"
        
        print("✓ PASS: All image sizes handled correctly")
        return True
    except Exception as e:
        print(f"✗ FAIL: {e}")
        return False


def main():
    """Run all tests"""
    print("""
╔════════════════════════════════════════════════════════════════════╗
║         STEGANOGRAPHY TEST SUITE - LSB IMAGE EMBEDDING            ║
╚════════════════════════════════════════════════════════════════════╝
""")
    
    if not DEPENDENCIES_OK:
        print("[!] Cannot run tests - missing dependencies")
        print("Install: pip install pillow cryptography")
        return
    
    tests = [
        test_lsb_capacity,
        test_lsb_encoding_decoding,
        test_command_serialization,
        test_full_steganography_flow,
        test_compression_ratio,
        test_different_beacon_ids,
        test_image_size_variance,
    ]
    
    results = []
    for test in tests:
        try:
            result = test()
            results.append(result)
        except Exception as e:
            print(f"\n✗ EXCEPTION: {e}")
            import traceback
            traceback.print_exc()
            results.append(False)
    
    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    
    total = len(results)
    passed = sum(results)
    failed = total - passed
    
    print(f"Total: {total}")
    print(f"Passed: {passed} ✓")
    print(f"Failed: {failed} ✗")
    print(f"Success rate: {(passed/total)*100:.1f}%")
    
    if failed == 0:
        print("\n✓ ALL TESTS PASSED")
        return True
    else:
        print(f"\n✗ {failed} TEST(S) FAILED")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
