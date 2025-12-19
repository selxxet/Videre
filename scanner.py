import socket
import subprocess
import platform
from scapy.all import ARP, Ether, srp, conf, get_if_list, get_if_addr
import json
import os
import re
import logging
import warnings
import ipaddress
import concurrent.futures

warnings.filterwarnings('ignore')
logging.getLogger('scapy').setLevel(logging.ERROR)
conf.verb = 0


class NetworkScanner:
    def __init__(self):
        self.devices = []
        self.network = None
        self.gateway_ip = None
        self.subnet_mask = None
        self.dns_servers = []
        self.interface_ip = None
        self.interface_name = None
        
    def get_network_info(self):
        try:
            if platform.system() == "Windows":
                result = subprocess.run(['ipconfig', '/all'], capture_output=True, text=True, encoding='utf-8', errors='ignore')
                output = result.stdout
                
                for line in output.split('\n'):
                    line_lower = line.lower().strip()
                    
                    if 'ipv4' in line_lower or 'ip address' in line_lower:
                        if ':' in line:
                            ip_part = line.split(':')[1].strip()
                            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', ip_part)
                            if ip_match and self._is_valid_ip(ip_match.group(1)):
                                self.interface_ip = ip_match.group(1)
                    
                    if 'subnet mask' in line_lower or 'subnetmaske' in line_lower:
                        if ':' in line:
                            mask = line.split(':')[1].strip()
                            mask_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', mask)
                            if mask_match and self._is_valid_ip(mask_match.group(1)):
                                self.subnet_mask = mask_match.group(1)
                    
                    if 'default gateway' in line_lower or 'standardgateway' in line_lower:
                        if ':' in line:
                            gateway = line.split(':')[1].strip()
                            gateway_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', gateway)
                            if gateway_match and self._is_valid_ip(gateway_match.group(1)):
                                self.gateway_ip = gateway_match.group(1)
                    
                    if 'dns servers' in line_lower or 'dns-server' in line_lower:
                        if ':' in line:
                            dns_part = line.split(':')[1].strip()
                            dns_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', dns_part)
                            if dns_match and self._is_valid_ip(dns_match.group(1)):
                                if dns_match.group(1) not in self.dns_servers:
                                    self.dns_servers.append(dns_match.group(1))
            else:
                try:
                    result = subprocess.run(['ip', 'addr'], capture_output=True, text=True)
                    output = result.stdout
                    for line in output.split('\n'):
                        if 'inet ' in line and '127.0.0.1' not in line:
                            ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', line)
                            if ip_match and self._is_valid_ip(ip_match.group(1)):
                                self.interface_ip = ip_match.group(1)
                                mask_match = re.search(r'/(\d+)', line)
                                if mask_match:
                                    prefix = int(mask_match.group(1))
                                    self.subnet_mask = self._prefix_to_mask(prefix)
                    
                    result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
                    output = result.stdout
                    for line in output.split('\n'):
                        if 'default' in line:
                            parts = line.split()
                            if len(parts) > 2:
                                gateway = parts[2]
                                if self._is_valid_ip(gateway):
                                    self.gateway_ip = gateway
                                    break
                    
                    try:
                        with open('/etc/resolv.conf', 'r') as f:
                            for line in f:
                                if line.startswith('nameserver'):
                                    dns_ip = line.split()[1] if len(line.split()) > 1 else None
                                    if dns_ip and self._is_valid_ip(dns_ip):
                                        if dns_ip not in self.dns_servers:
                                            self.dns_servers.append(dns_ip)
                    except:
                        pass
                except:
                    try:
                        result = subprocess.run(['route', '-n', 'get', 'default'], capture_output=True, text=True)
                        output = result.stdout
                        for line in output.split('\n'):
                            if 'gateway' in line.lower():
                                parts = line.split(':')
                                if len(parts) > 1:
                                    gateway = parts[1].strip()
                                    if self._is_valid_ip(gateway):
                                        self.gateway_ip = gateway
                                        break
                        
                        result = subprocess.run(['scutil', '--dns'], capture_output=True, text=True)
                        output = result.stdout
                        for line in output.split('\n'):
                            if 'nameserver' in line.lower():
                                dns_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                                if dns_match and self._is_valid_ip(dns_match.group(1)):
                                    if dns_match.group(1) not in self.dns_servers:
                                        self.dns_servers.append(dns_match.group(1))
                    except:
                        pass
            
            if self.interface_ip:
                if self.subnet_mask:
                    self.network = self._calculate_network_range(self.interface_ip, self.subnet_mask)
                else:
                    parts = self.interface_ip.split('.')
                    if len(parts) == 4:
                        self.network = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                if self.network:
                    return True
            elif self.gateway_ip:
                parts = self.gateway_ip.split('.')
                if len(parts) == 4:
                    self.network = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                    return True
        except:
            return False
        
        return False
    
    def _is_valid_ip(self, ip_string):
        try:
            parts = ip_string.split('.')
            if len(parts) != 4:
                return False
            for part in parts:
                num = int(part)
                if num < 0 or num > 255:
                    return False
            return True
        except:
            return False
    
    def _prefix_to_mask(self, prefix):
        try:
            mask = (0xffffffff >> (32 - prefix)) << (32 - prefix)
            return '.'.join([str((mask >> (8 * (3 - i))) & 0xff) for i in range(4)])
        except:
            return None
    
    def _mask_to_prefix(self, mask):
        try:
            parts = mask.split('.')
            if len(parts) != 4:
                return None
            binary_str = ''
            for part in parts:
                binary_str += format(int(part), '08b')
            return binary_str.count('1')
        except:
            return None
    
    def _calculate_network_range(self, ip, subnet_mask):
        try:
            if not ip or not subnet_mask:
                return None
            
            prefix = self._mask_to_prefix(subnet_mask)
            if prefix is None:
                parts = ip.split('.')
                if len(parts) == 4:
                    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                return None
            
            network = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
            return str(network)
        except:
            parts = ip.split('.')
            if len(parts) == 4:
                return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            return None
    
    def _get_scapy_interface(self):
        try:
            if not self.interface_ip:
                return None
            
            if_list = get_if_list()
            
            for iface in if_list:
                try:
                    if_addr = get_if_addr(iface)
                    if if_addr == self.interface_ip:
                        self.interface_name = iface
                        return iface
                except:
                    continue
            
            if platform.system() == "Windows":
                for iface in if_list:
                    try:
                        if_addr = get_if_addr(iface)
                        if if_addr and if_addr.startswith(self.interface_ip.rsplit('.', 1)[0]):
                            self.interface_name = iface
                            return iface
                    except:
                        continue
            
            for iface in if_list:
                if 'lo' not in iface.lower() and 'loopback' not in iface.lower():
                    try:
                        if_addr = get_if_addr(iface)
                        if if_addr and if_addr != '127.0.0.1':
                            self.interface_name = iface
                            return iface
                    except:
                        continue
            
            return None
        except Exception as e:
            return None
    
    def get_detailed_network_info(self):
        if not self.get_network_info():
            return {}
        
        return {
            'gateway': self.gateway_ip or 'Unknown',
            'subnet_mask': self.subnet_mask or 'Unknown',
            'network_range': self.network or 'Unknown',
            'interface_ip': self.interface_ip or 'Unknown',
            'dns_servers': self.dns_servers if self.dns_servers else ['Unknown']
        }
    
    def ping_device(self, ip_address, timeout=2):
        try:
            if not self._is_valid_ip(ip_address):
                return False
            
            if platform.system() == "Windows":
                result = subprocess.run(['ping', '-n', '1', '-w', str(timeout * 1000), ip_address], 
                                       capture_output=True, text=True, timeout=timeout + 2,
                                       encoding='utf-8', errors='ignore')
            else:
                result = subprocess.run(['ping', '-c', '1', '-W', str(timeout), ip_address], 
                                       capture_output=True, text=True, timeout=timeout + 2,
                                       encoding='utf-8', errors='ignore')
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            return False
        except:
            return False
    
    def scan_ports(self, ip_address, ports=None, timeout=2):
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389, 8080]
        
        open_ports = []
        services = {}
        
        # port -> service name
        service_map = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
            445: 'SMB', 3389: 'RDP', 8080: 'HTTP-Proxy'
        }
        
        for port in ports:
            sock = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.settimeout(timeout)
                result = sock.connect_ex((ip_address, port))
                
                if result == 0:
                    open_ports.append(port)
                    services[port] = service_map.get(port, 'Unknown')
            except socket.timeout:
                pass
            except socket.error:
                pass
            except:
                pass
            finally:
                if sock:
                    try:
                        sock.close()
                    except:
                        pass
        
        return {
            'open_ports': open_ports,
            'services': services,
            'port_count': len(open_ports)
        }
    
    def scan_network_ping(self, network_range=None):
        devices = []
        
        if not network_range:
            if not self.get_network_info():
                return []
            network_range = self.network
        
        if not network_range:
            return []
        
        try:
            network = ipaddress.IPv4Network(network_range, strict=False)
            hosts = list(network.hosts())[:254]
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                futures = []
                for ip in hosts:
                    ip_str = str(ip)
                    future = executor.submit(self._ping_and_get_info, ip_str)
                    futures.append(future)
                
                for future in concurrent.futures.as_completed(futures, timeout=30):
                    try:
                        device_info = future.result()
                        if device_info:
                            devices.append(device_info)
                    except:
                        pass
        except:
            try:
                network = ipaddress.IPv4Network(network_range, strict=False)
                hosts = list(network.hosts())[:254]
                
                for ip in hosts[:50]:
                    ip_str = str(ip)
                    device_info = self._ping_and_get_info(ip_str)
                    if device_info:
                        devices.append(device_info)
            except:
                pass
        
        return devices
    
    def _ping_and_get_info(self, ip_str):
        try:
            if self.ping_device(ip_str, timeout=0.5):
                device_info = {
                    'ip': ip_str,
                    'mac': 'Unknown',
                    'hostname': None,
                    'manufacturer': None,
                    'status': 'active',
                    'last_seen': None
                }
                
                try:
                    socket.setdefaulttimeout(0.5)
                    hostname = socket.gethostbyaddr(ip_str)[0]
                    device_info['hostname'] = hostname
                except (socket.herror, socket.gaierror, socket.timeout, OSError):
                    device_info['hostname'] = None
                finally:
                    socket.setdefaulttimeout(None)
                
                try:
                    mac = self._get_mac_from_arp_table(ip_str)
                    if mac and mac != 'Unknown':
                        device_info['mac'] = mac
                except:
                    pass
                
                return device_info
        except:
            pass
        return None
    
    def _get_mac_from_arp_table(self, ip):
        try:
            if platform.system() == "Windows":
                result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True, timeout=2, encoding='utf-8', errors='ignore')
                output = result.stdout
                mac_match = re.search(r'([0-9a-f]{2}[:-]){5}[0-9a-f]{2}', output, re.IGNORECASE)
                if mac_match:
                    return mac_match.group(0).replace('-', ':').upper()
            else:
                result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True, timeout=2)
                output = result.stdout
                mac_match = re.search(r'([0-9a-f]{2}[:-]){5}[0-9a-f]{2}', output, re.IGNORECASE)
                if mac_match:
                    return mac_match.group(0).replace('-', ':').upper()
        except:
            pass
        return None
    
    def scan_network(self, network_range=None, timeout=3):
        self.get_network_info()
        
        if not network_range:
            network_range = self.network
        
        if not network_range:
            return []
        
        devices = []
        
        iface = self._get_scapy_interface()
        
        try:
            if iface:
                conf.iface = iface
            
            arp_request = ARP(pdst=network_range)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            
            answered_list = srp(arp_request_broadcast, timeout=timeout, verbose=False, inter=0.05)[0]
            
            for element in answered_list:
                device_info = {
                    'ip': element[1].psrc,
                    'mac': element[1].hwsrc,
                    'hostname': None,
                    'manufacturer': None,
                    'status': 'active',
                    'last_seen': None
                }
                
                # try hostname lookup
                try:
                    socket.setdefaulttimeout(1)
                    hostname = socket.gethostbyaddr(device_info['ip'])[0]
                    device_info['hostname'] = hostname
                except (socket.herror, socket.gaierror, socket.timeout, OSError):
                    device_info['hostname'] = None
                finally:
                    socket.setdefaulttimeout(None)
                
                devices.append(device_info)
            
            self.devices = devices
            return devices
            
        except Exception as e:
            pass
        
        if len(devices) == 0:
            try:
                ping_devices = self.scan_network_ping(network_range)
                if len(ping_devices) > 0:
                    devices = ping_devices
                    self.devices = devices
                    return devices
            except:
                pass
        
        return devices
    
    def get_devices(self):
        return self.devices
    
    def save_scan_results(self, filename='scan_results.json'):
        try:
            with open(filename, 'w') as f:
                json.dump(self.devices, f, indent=2)
        except:
            pass
