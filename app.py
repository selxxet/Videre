from flask import Flask, render_template, jsonify, request
from scanner import NetworkScanner
from oui_lookup import OUILookup
import threading
from datetime import datetime
import logging
import warnings

warnings.filterwarnings('ignore')
logging.getLogger('werkzeug').setLevel(logging.ERROR)
logging.getLogger('scapy').setLevel(logging.ERROR)

app = Flask(__name__)
app.logger.disabled = True

print("Initializing Videre...")
print("Loading network scanner...")
scanner = NetworkScanner()
print("Loading OUI database (this may take a moment)...")
oui_lookup = OUILookup()
print("Initialization complete.")

# state
devices = []
scan_in_progress = False
last_scan_time = None
device_ping_status = {}
device_port_scans = {}
device_history = {}


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/scan', methods=['POST'])
def start_scan():
    global scan_in_progress, devices, last_scan_time
    
    if scan_in_progress:
        return jsonify({'status': 'error', 'message': 'Scan already in progress'}), 400
    
    scan_in_progress = True
    
    def scan_thread():
        global devices, scan_in_progress, last_scan_time, device_history
        try:
            discovered = scanner.scan_network()
            now = datetime.now().isoformat()
            
            for dev in discovered:
                mac = dev['mac']
                ip = dev['ip']
                
                mfg = oui_lookup.lookup(mac)
                dev['manufacturer'] = mfg
                dev['is_unknown'] = mfg == 'Unknown'
                dev['last_seen'] = now
                
                # history tracking
                if mac not in device_history:
                    device_history[mac] = {
                        'first_seen': now,
                        'last_seen': now,
                        'seen_count': 1,
                        'ip_history': [ip]
                    }
                else:
                    device_history[mac]['last_seen'] = now
                    device_history[mac]['seen_count'] += 1
                    if ip not in device_history[mac]['ip_history']:
                        device_history[mac]['ip_history'].append(ip)
                
                if ip in device_ping_status:
                    dev['ping_status'] = device_ping_status[ip]
            
            devices = discovered
            last_scan_time = now
        except:
            pass
        finally:
            scan_in_progress = False
    
    t = threading.Thread(target=scan_thread)
    t.daemon = True
    t.start()
    
    return jsonify({'status': 'started', 'message': 'Scan started'})


@app.route('/api/devices', methods=['GET'])
def get_devices():
    result = []
    for dev in devices:
        d = dev.copy()
        if dev['ip'] in device_ping_status:
            d['ping_status'] = device_ping_status[dev['ip']]
        result.append(d)
    
    unknown = sum(1 for d in devices if d.get('is_unknown', False))
    
    return jsonify({
        'devices': result,
        'count': len(devices),
        'unknown_count': unknown,
        'last_scan': last_scan_time,
        'scan_in_progress': scan_in_progress
    })


@app.route('/api/status', methods=['GET'])
def get_status():
    return jsonify({
        'scan_in_progress': scan_in_progress,
        'last_scan': last_scan_time,
        'device_count': len(devices)
    })


@app.route('/api/network-info', methods=['GET'])
def get_network_info():
    try:
        info = scanner.get_detailed_network_info()
        return jsonify(info)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/device/<ip>/ping', methods=['POST'])
def ping_device(ip):
    try:
        online = scanner.ping_device(ip)
        last_check = datetime.now().isoformat()
        device_ping_status[ip] = {
            'online': online,
            'last_check': last_check
        }
        return jsonify({
            'ip': ip,
            'online': online,
            'last_check': last_check
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


port_scan_in_progress = {}

@app.route('/api/device/ports', methods=['POST'])
def scan_device_ports():
    global port_scan_in_progress
    
    if not request.json or 'ip' not in request.json:
        return jsonify({'error': 'IP address required'}), 400
    
    ip = request.json['ip']
    
    if ip in port_scan_in_progress and port_scan_in_progress[ip]:
        return jsonify({'status': 'in_progress', 'message': 'Port scan already running'}), 400
    
    port_scan_in_progress[ip] = True
    ports_param = request.json.get('ports')
    
    def scan_thread():
        global port_scan_in_progress
        try:
            result = scanner.scan_ports(ip, ports=ports_param)
            
            if 'services' not in result:
                result['services'] = {}
            
            device_port_scans[ip] = {
                **result,
                'last_scan': datetime.now().isoformat()
            }
        except:
            pass
        finally:
            port_scan_in_progress[ip] = False
    
    t = threading.Thread(target=scan_thread)
    t.daemon = True
    t.start()
    
    return jsonify({'status': 'started', 'message': 'Port scan started'})


@app.route('/api/device/<ip>/details', methods=['GET'])
def get_device_details(ip):
    try:
        dev = next((d for d in devices if d['ip'] == ip), None)
        if not dev:
            return jsonify({'error': 'Device not found'}), 404
        
        ping = device_ping_status.get(ip)
        ports = device_port_scans.get(ip)
        scanning = port_scan_in_progress.get(ip, False)
        history = device_history.get(dev.get('mac'))
        
        return jsonify({
            **dev,
            'ping_status': ping if ping else None,
            'port_scan': ports if ports else None,
            'port_scan_in_progress': scanning,
            'history': history if history else None
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/device/<ip>/history', methods=['GET'])
def get_device_history(ip):
    try:
        dev = next((d for d in devices if d['ip'] == ip), None)
        if not dev:
            return jsonify({'error': 'Device not found'}), 404
        
        mac = dev.get('mac')
        history = device_history.get(mac)
        
        if not history:
            return jsonify({'error': 'No history found for this device'}), 404
        
        return jsonify(history)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/devices/ping-all', methods=['POST'])
def ping_all_devices():
    def ping_thread():
        global device_ping_status
        for dev in devices:
            try:
                online = scanner.ping_device(dev['ip'])
                device_ping_status[dev['ip']] = {
                    'online': online,
                    'last_check': datetime.now().isoformat()
                }
            except:
                device_ping_status[dev['ip']] = {
                    'online': False,
                    'last_check': datetime.now().isoformat()
                }
    
    t = threading.Thread(target=ping_thread)
    t.daemon = True
    t.start()
    
    return jsonify({'status': 'started', 'message': 'Ping scan started'})


if __name__ == '__main__':
    import sys
    
    print("\nStarting server...")
    print("Videre is running on http://localhost:5000")
    print("Press CTRL+C to stop\n")
    
    try:
        app.run(debug=False, host='0.0.0.0', port=5000, use_reloader=False)
    except KeyboardInterrupt:
        print("\nShutting down...")
        sys.exit(0)
