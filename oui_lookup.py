import re
import urllib.request
import urllib.error
import json
import os
import tempfile


class OUILookup:
    def __init__(self):
        self.oui_database = {}
        self.oui_file = self._get_oui_file_path()
        self.load_database()
    
    def _get_oui_file_path(self):
        test_file = 'oui_database.json'
        try:
            # test write access
            with open(test_file, 'w') as f:
                f.write('test')
            os.remove(test_file)
            return test_file
        except (PermissionError, OSError):
            # use temp if can't write here
            temp_dir = tempfile.gettempdir()
            return os.path.join(temp_dir, 'oui_database.json')
    
    def load_database(self):
        if os.path.exists(self.oui_file):
            try:
                with open(self.oui_file, 'r') as f:
                    self.oui_database = json.load(f)
                    if len(self.oui_database) > 0:
                        return
            except:
                self.oui_database = {}
        
        print("  Downloading OUI database (this may take 10-30 seconds)...")
        try:
            self.download_oui_database()
        except:
            pass
        
        if len(self.oui_database) == 0:
            self.load_fallback_database()
    
    def download_oui_database(self):
        urls = [
            "https://standards-oui.ieee.org/oui/oui.txt",
            "https://standards-oui.ieee.org/oui.txt"
        ]
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        for url in urls:
            try:
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=15) as response:
                    if response.status == 200:
                        data = response.read().decode('utf-8', errors='ignore')
                        if len(data) > 10000:
                            self.parse_oui_data(data)
                            if len(self.oui_database) > 0:
                                self.save_database()
                                return
            except:
                continue
        
        if len(self.oui_database) == 0:
            self.load_fallback_database()
    
    def parse_oui_data(self, data):
        lines = data.split('\n')
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            if '(base 16)' in line:
                parts = line.split('(base 16)')
                if len(parts) == 2:
                    oui_part = parts[0].strip()
                    manufacturer = parts[1].strip()
                    
                    oui_match = re.search(r'([0-9A-Fa-f]{2}[-:]){2}[0-9A-Fa-f]{2}', oui_part)
                    if oui_match:
                        oui = oui_match.group(0).replace('-', ':').upper()
                        if len(oui) == 8 and manufacturer:
                            self.oui_database[oui] = manufacturer
            else:
                # alternate format
                oui_match = re.match(r'^([0-9A-Fa-f]{2}[-:]){2}[0-9A-Fa-f]{2}', line)
                if oui_match:
                    oui = oui_match.group(0).replace('-', ':').upper()
                    manufacturer = re.sub(r'^[0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2}\s+', '', line).strip()
                    if len(oui) == 8 and manufacturer and len(manufacturer) > 0:
                        self.oui_database[oui] = manufacturer
    
    def load_fallback_database(self):
        fallback = {
            '00:50:56': 'VMware, Inc.',
            '00:0C:29': 'VMware, Inc.',
            '00:1C:14': 'VMware, Inc.',
            '00:05:69': 'VMware, Inc.',
            '08:00:27': 'VirtualBox',
            '00:1B:21': 'Intel Corporate',
            '00:1E:67': 'Intel Corporate',
            '00:25:00': 'Apple, Inc.',
            '00:26:4A': 'Apple, Inc.',
            '00:26:BB': 'Apple, Inc.',
            'F0:DB:E2': 'Apple, Inc.',
            'AC:DE:48': 'Apple, Inc.',
            'D8:30:62': 'Apple, Inc.',
            '00:1A:79': 'Samsung Electronics Co.,Ltd',
            '00:23:39': 'Samsung Electronics Co.,Ltd',
            '00:16:6B': 'Samsung Electronics Co.,Ltd',
            'F4:9F:54': 'Samsung Electronics Co.,Ltd',
            '00:50:43': 'Cisco Systems, Inc.',
            '00:1B:0D': 'Cisco Systems, Inc.',
            '00:1E:13': 'Cisco Systems, Inc.',
            '00:1E:79': 'Cisco Systems, Inc.',
            '00:21:55': 'Cisco Systems, Inc.',
            '00:23:04': 'Cisco Systems, Inc.',
            '00:26:0B': 'Cisco Systems, Inc.',
            '00:26:CA': 'Cisco Systems, Inc.',
            'B8:27:EB': 'Raspberry Pi Foundation',
            'DC:A6:32': 'Raspberry Pi Foundation',
            'E4:5F:01': 'Raspberry Pi Foundation',
            '28:CD:4C': 'Raspberry Pi Foundation',
            'D8:3A:DD': 'Google, Inc.',
            'F4:F5:DB': 'Google, Inc.',
            '00:1A:11': 'Google, Inc.',
            'F8:8F:CA': 'Google, Inc.',
            '00:1E:C2': 'Belkin International Inc.',
            '00:24:36': 'Belkin International Inc.',
            '00:22:75': 'Belkin International Inc.',
            '00:17:3F': 'Netgear',
            '00:09:5B': 'Netgear',
            '00:1F:33': 'Netgear',
            '00:24:B2': 'Netgear',
            '00:27:22': 'Netgear',
            '00:0F:CC': 'Netgear',
            '00:1B:2F': 'Netgear',
            '00:1E:2A': 'Netgear',
            '00:22:3F': 'Netgear',
            '00:24:7C': 'Netgear',
            '00:26:F2': 'Netgear',
            '00:27:19': 'Netgear',
            '00:50:F2': 'Microsoft Corporation',
            '00:03:FF': 'Microsoft Corporation',
            '00:15:5D': 'Microsoft Corporation',
            '00:0D:3A': 'Microsoft Corporation',
            '00:17:FA': 'Microsoft Corporation',
            '00:1D:D8': 'Microsoft Corporation',
        }
        self.oui_database = fallback
    
    def save_database(self):
        try:
            directory = os.path.dirname(self.oui_file)
            if directory and not os.path.exists(directory):
                os.makedirs(directory, exist_ok=True)
            
            with open(self.oui_file, 'w', encoding='utf-8') as f:
                json.dump(self.oui_database, f, indent=2)
        except:
            pass
    
    def lookup(self, mac_address):
        if not mac_address:
            return 'Unknown'
        
        mac = mac_address.upper().replace('-', ':')
        oui = ':'.join(mac.split(':')[:3])
        
        return self.oui_database.get(oui, 'Unknown')
