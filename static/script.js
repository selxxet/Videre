let scanInterval = null;
let allDevices = [];
let currentSort = 'name';
let currentFilter = '';
let showUnknownOnly = false;
let refreshInProgress = false;

function formatRelativeTime(dateString) {
    if (!dateString) return 'Unknown';
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);
    
    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins} minute${diffMins > 1 ? 's' : ''} ago`;
    if (diffHours < 24) return `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;
    if (diffDays < 7) return `${diffDays} day${diffDays > 1 ? 's' : ''} ago`;
    return date.toLocaleDateString();
}

function updateStatus() {
    return fetch('/api/status')
        .then(response => response.json())
        .then(data => {
            const statusDot = document.getElementById('scanStatus');
            const statusText = document.getElementById('statusText');
            
            if (data.scan_in_progress) {
                statusDot.className = 'status-dot scanning';
                statusText.textContent = 'Scanning...';
                document.getElementById('scanBtn').disabled = true;
            } else {
                statusDot.className = 'status-dot ready';
                statusText.textContent = 'Ready';
                document.getElementById('scanBtn').disabled = false;
            }
            return data;
        })
        .catch(error => {
            throw error;
        });
}

function fetchWithTimeout(url, options = {}, timeout = 5000) {
    return Promise.race([
        fetch(url, options),
        new Promise((_, reject) =>
            setTimeout(() => reject(new Error('Request timeout')), timeout)
        )
    ]);
}

function refreshDevices() {
    if (refreshInProgress) {
        return;
    }
    
    const refreshBtn = document.getElementById('refreshBtn');
    if (!refreshBtn) {
        return;
    }
    
    refreshInProgress = true;
    const originalText = refreshBtn.textContent;
    
    refreshBtn.disabled = true;
    refreshBtn.textContent = 'Refreshing...';
    
    Promise.all([
        fetchWithTimeout('/api/status', {}, 5000)
            .then(response => {
                if (!response.ok) {
                    throw new Error(`Status API error: ${response.status}`);
                }
                return response.json();
            })
            .catch(err => {
                throw err;
            }),
        fetchWithTimeout('/api/devices', {}, 5000)
            .then(response => {
                if (!response.ok) {
                    throw new Error(`Devices API error: ${response.status}`);
                }
                return response.json();
            })
            .catch(err => {
                throw err;
            })
    ])
    .then(([statusData, devicesData]) => {
        const statusDot = document.getElementById('scanStatus');
        const statusText = document.getElementById('statusText');
        
        if (statusDot && statusText) {
            if (statusData.scan_in_progress) {
                statusDot.className = 'status-dot scanning';
                statusText.textContent = 'Scanning...';
                const scanBtn = document.getElementById('scanBtn');
                if (scanBtn) scanBtn.disabled = true;
            } else {
                statusDot.className = 'status-dot ready';
                statusText.textContent = 'Ready';
                const scanBtn = document.getElementById('scanBtn');
                if (scanBtn) scanBtn.disabled = false;
            }
        }
        
        allDevices = devicesData.devices || [];
        updateStats(devicesData);
        applyFiltersAndSort();
    })
    .catch(error => {
        alert('Error refreshing data: ' + (error.message || 'Unknown error') + '. Please check your connection.');
    })
    .finally(() => {
        refreshInProgress = false;
        if (refreshBtn) {
            refreshBtn.disabled = false;
            refreshBtn.textContent = originalText;
        }
    });
}

function updateStats(data) {
    document.getElementById('totalDevices').textContent = data.count || 0;
    document.getElementById('unknownDevices').textContent = data.unknown_count || 0;
    
    if (data.last_scan) {
        const date = new Date(data.last_scan);
        const timeStr = date.toLocaleTimeString();
        document.getElementById('lastScan').textContent = timeStr;
    } else {
        document.getElementById('lastScan').textContent = 'Never';
    }
}

function renderDevices(devices) {
    const devicesList = document.getElementById('devicesList');
    document.getElementById('deviceCountBadge').textContent = devices.length;
    
    if (!devices || devices.length === 0) {
        devicesList.innerHTML = '<div class="empty-state">No devices found. Try adjusting your filters.</div>';
        return;
    }
    
    devicesList.innerHTML = devices.map(device => {
        const isUnknown = device.is_unknown || device.manufacturer === 'Unknown';
        const cardClass = isUnknown ? 'device-card unknown' : 'device-card';
        const badgeClass = isUnknown ? 'status-badge unknown' : 'status-badge active';
        const badgeText = isUnknown ? 'Unknown' : 'Identified';
        
        const displayName = device.hostname && device.hostname !== 'Unknown' ? device.hostname : device.ip;
        const pingStatus = device.ping_status || {};
        const pingBadge = pingStatus.online !== undefined 
            ? `<span class="ping-status ${pingStatus.online ? 'online' : 'offline'}">${pingStatus.online ? 'Online' : 'Offline'}</span>`
            : '';
        
        return `
            <div class="${cardClass}" onclick="showDeviceDetails('${device.ip}')">
                <div class="device-info">
                    <div class="device-name">${displayName}</div>
                    <div class="device-details">
                        <div class="detail-item">
                            <span class="detail-label">IP:</span>
                            <span>${device.ip}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">MAC:</span>
                            <span>${device.mac}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Manufacturer:</span>
                            <span>${device.manufacturer || 'Unknown'}</span>
                        </div>
                    </div>
                    <div class="device-actions">
                        <button class="btn btn-small btn-secondary" onclick="event.stopPropagation(); pingDevice('${device.ip}', event)">Ping</button>
                        <button class="btn btn-small btn-secondary" onclick="event.stopPropagation(); scanDevicePorts('${device.ip}')">Scan Ports</button>
                    </div>
                </div>
                <div class="device-status">
                    ${pingBadge}
                    <span class="${badgeClass}">${badgeText}</span>
                </div>
            </div>
        `;
    }).join('');
}

function filterDevices() {
    currentFilter = document.getElementById('searchInput').value.toLowerCase();
    showUnknownOnly = document.getElementById('filterUnknown').checked;
    applyFiltersAndSort();
}

function sortDevices() {
    currentSort = document.getElementById('sortSelect').value;
    applyFiltersAndSort();
}

function applyFiltersAndSort() {
    let filtered = [...allDevices];
    
    if (currentFilter) {
        filtered = filtered.filter(device => {
            const name = (device.hostname || device.ip || '').toLowerCase();
            const ip = (device.ip || '').toLowerCase();
            const mac = (device.mac || '').toLowerCase();
            const manufacturer = (device.manufacturer || '').toLowerCase();
            return name.includes(currentFilter) || ip.includes(currentFilter) || 
                   mac.includes(currentFilter) || manufacturer.includes(currentFilter);
        });
    }
    
    if (showUnknownOnly) {
        filtered = filtered.filter(device => device.is_unknown || device.manufacturer === 'Unknown');
    }
    
    filtered.sort((a, b) => {
        let aVal, bVal;
        
        switch(currentSort) {
            case 'name':
                aVal = (a.hostname || a.ip || '').toLowerCase();
                bVal = (b.hostname || b.ip || '').toLowerCase();
                break;
            case 'ip':
                aVal = a.ip || '';
                bVal = b.ip || '';
                break;
            case 'manufacturer':
                aVal = (a.manufacturer || '').toLowerCase();
                bVal = (b.manufacturer || '').toLowerCase();
                break;
            case 'status':
                aVal = (a.is_unknown || a.manufacturer === 'Unknown') ? 1 : 0;
                bVal = (b.is_unknown || b.manufacturer === 'Unknown') ? 1 : 0;
                break;
            default:
                return 0;
        }
        
        if (aVal < bVal) return -1;
        if (aVal > bVal) return 1;
        return 0;
    });
    
    renderDevices(filtered);
}

function toggleDarkMode() {
    document.body.classList.toggle('dark-mode');
    const icon = document.getElementById('darkModeIcon');
    icon.textContent = document.body.classList.contains('dark-mode') ? '☀️' : '🌙';
    localStorage.setItem('darkMode', document.body.classList.contains('dark-mode'));
}

function loadNetworkInfo() {
    fetch('/api/network-info')
        .then(response => response.json())
        .then(data => {
            const content = document.getElementById('networkInfoContent');
            content.innerHTML = `
                <div class="info-item">
                    <span class="info-label">Gateway:</span>
                    <span class="info-value">${data.gateway || 'Unknown'}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Subnet Mask:</span>
                    <span class="info-value">${data.subnet_mask || 'Unknown'}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Network Range:</span>
                    <span class="info-value">${data.network_range || 'Unknown'}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Interface IP:</span>
                    <span class="info-value">${data.interface_ip || 'Unknown'}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">DNS Servers:</span>
                    <span class="info-value">${data.dns_servers ? data.dns_servers.join(', ') : 'Unknown'}</span>
                </div>
            `;
        })
        .catch(error => {
        });
}

function pingDevice(ip, eventObj) {
    const button = eventObj ? eventObj.target : null;
    const originalText = button ? button.textContent : null;
    
    if (button) {
        button.disabled = true;
        button.textContent = 'Pinging...';
    }
    
    fetch(`/api/device/${ip}/ping`, { method: 'POST' })
        .then(response => {
            if (!response.ok) {
                return response.json().then(err => {
                    throw new Error(err.error || `HTTP error! status: ${response.status}`);
                });
            }
            return response.json();
        })
        .then(data => {
            if (data.error) {
                throw new Error(data.error);
            }
            const deviceIndex = allDevices.findIndex(d => d.ip === ip);
            if (deviceIndex !== -1) {
                allDevices[deviceIndex].ping_status = {
                    online: data.online,
                    last_check: data.last_check
                };
            }
            applyFiltersAndSort();
        })
        .catch(error => {
            alert('Error pinging device: ' + (error.message || 'Unknown error'));
        })
        .finally(() => {
            if (button) {
                button.disabled = false;
                button.textContent = originalText || 'Ping';
            }
        });
}

function pingAllDevices() {
    const btn = document.getElementById('pingAllBtn');
    const originalText = btn.textContent;
    btn.disabled = true;
    btn.textContent = 'Pinging...';
    
    fetch('/api/devices/ping-all', { method: 'POST' })
        .then(response => response.json())
        .then(data => {
            setTimeout(() => {
                refreshDevices();
                btn.disabled = false;
                btn.textContent = originalText;
            }, 3000);
        })
        .catch(error => {
            btn.disabled = false;
            btn.textContent = originalText;
        });
}

function scanDevicePorts(ip) {
    const modal = document.getElementById('deviceModal');
    const modalContent = document.getElementById('modalContent');
    
    if (modal.style.display !== 'block') {
        showDeviceDetails(ip);
        setTimeout(() => {
            startPortScan(ip);
        }, 300);
    } else {
        updatePortScanStatus(ip, true);
        startPortScan(ip);
    }
}

function startPortScan(ip) {
    fetch('/api/device/ports', { 
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: ip })
    })
        .then(response => {
            const contentType = response.headers.get('content-type');
            if (!contentType || !contentType.includes('application/json')) {
                return response.text().then(text => {
                    throw new Error(`Server error: ${response.status}`);
                });
            }
            return response.json();
        })
        .then(data => {
            if (data.status === 'started') {
                updatePortScanStatus(ip, true);
                checkPortScanStatus(ip);
            } else {
                setTimeout(() => {
                    showDeviceDetails(ip);
                }, 500);
            }
        })
        .catch(error => {
            alert('Error starting port scan: ' + (error.message || 'Unknown error'));
            updatePortScanStatus(ip, false);
        });
}

function updatePortScanStatus(ip, scanning) {
    const modalContent = document.getElementById('modalContent');
    if (!modalContent) return;
    
    const scanningHtml = '<div class="modal-loading" style="background: #fff3cd; color: #856404; padding: 15px; border-radius: 4px; margin: 10px 0;">Scanning ports... This may take 10-20 seconds.</div>';
    
    let html = modalContent.innerHTML;
    if (scanning) {
        if (html.includes('Port Scan')) {
            html = html.replace(
                /(<div class="modal-section">\s*<h3>Port Scan<\/h3>)(.*?)(<\/div>)/s,
                '$1' + scanningHtml + '$3'
            );
        } else {
            html = html.replace(
                /(<div class="modal-section">\s*<h3>Port Scan<\/h3>)/,
                '$1' + scanningHtml
            );
        }
        modalContent.innerHTML = html;
    }
}

function checkPortScanStatus(ip) {
    const checkInterval = setInterval(() => {
        fetch(`/api/device/${ip}/details`)
            .then(response => response.json())
            .then(device => {
                if (!device.port_scan_in_progress) {
                    clearInterval(checkInterval);
                    showDeviceDetails(ip);
                }
            })
            .catch(() => {
                clearInterval(checkInterval);
            });
    }, 1000);
}

function showDeviceDetails(ip) {
    const modal = document.getElementById('deviceModal');
    const modalContent = document.getElementById('modalContent');
    const modalName = document.getElementById('modalDeviceName');
    
    modal.style.display = 'block';
    modalContent.innerHTML = '<div class="modal-loading">Loading device details...</div>';
    
    fetch(`/api/device/${ip}/details`)
        .then(response => response.json())
        .then(device => {
            modalName.textContent = device.hostname || device.ip;
            
            const pingStatus = device.ping_status || {};
            const portScan = device.port_scan;
            const scanning = device.port_scan_in_progress || false;
            const history = device.history || {};
            
            let portsHtml = '';
            let historyHtml = '';
            
            if (history.first_seen) {
                historyHtml = `
                    <div class="modal-section">
                        <h3>Connection History</h3>
                        <div class="device-details">
                            <div class="detail-item">
                                <span class="detail-label">First Seen:</span>
                                <span>${formatRelativeTime(history.first_seen)} (${new Date(history.first_seen).toLocaleString()})</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Last Seen:</span>
                                <span>${formatRelativeTime(history.last_seen)} (${new Date(history.last_seen).toLocaleString()})</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Times Seen:</span>
                                <span>${history.seen_count || 0}</span>
                            </div>
                            ${history.ip_history && history.ip_history.length > 1 ? `
                            <div class="detail-item">
                                <span class="detail-label">IP History:</span>
                                <span>${history.ip_history.join(', ')}</span>
                            </div>
                            ` : ''}
                        </div>
                    </div>
                `;
            }
            if (scanning) {
                portsHtml = '<div class="modal-section"><h3>Port Scan</h3><div class="modal-loading" style="background: #fff3cd; color: #856404; padding: 15px; border-radius: 4px;">Scanning ports... This may take 10-20 seconds.</div></div>';
            } else if (portScan && portScan.last_scan) {
                const hasOpenPorts = portScan.services && typeof portScan.services === 'object' && Object.keys(portScan.services).length > 0;
                
                if (hasOpenPorts) {
                    portsHtml = `
                        <div class="modal-section">
                            <h3>Open Ports (${portScan.port_count || Object.keys(portScan.services).length})</h3>
                            <div class="port-list">
                                ${Object.entries(portScan.services).map(([port, service]) => 
                                    `<div class="port-item">
                                        <span>Port ${port}</span>
                                        <span><strong>${service}</strong></span>
                                    </div>`
                                ).join('')}
                            </div>
                            <p style="margin-top: 10px; font-size: 0.9em; color: #666;">Last scanned: ${new Date(portScan.last_scan).toLocaleString()}</p>
                        </div>
                    `;
                } else {
                    portsHtml = `<div class="modal-section">
                        <h3>Port Scan Results</h3>
                        <p>No open ports found.</p>
                        <p style="margin-top: 10px; font-size: 0.9em; color: #666;">Last scanned: ${new Date(portScan.last_scan).toLocaleString()}</p>
                    </div>`;
                }
            } else {
                portsHtml = '<div class="modal-section"><h3>Port Scan</h3><p>Port scan not performed yet. Click "Scan Ports" below to scan.</p></div>';
            }
            
            modalContent.innerHTML = `
                <div class="modal-section">
                    <h3>Device Information</h3>
                    <div class="device-details">
                        <div class="detail-item">
                            <span class="detail-label">IP Address:</span>
                            <span>${device.ip}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">MAC Address:</span>
                            <span>${device.mac}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Hostname:</span>
                            <span>${device.hostname || 'Unknown'}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Manufacturer:</span>
                            <span>${device.manufacturer || 'Unknown'}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Last Seen:</span>
                            <span>${device.last_seen ? new Date(device.last_seen).toLocaleString() : 'Unknown'}</span>
                        </div>
                    </div>
                </div>
                ${historyHtml}
                <div class="modal-section">
                    <h3>Ping Status</h3>
                    ${pingStatus.online !== undefined 
                        ? `<p>Status: <span class="ping-status ${pingStatus.online ? 'online' : 'offline'}">${pingStatus.online ? 'Online' : 'Offline'}</span></p>
                           <p>Last Check: ${pingStatus.last_check ? new Date(pingStatus.last_check).toLocaleString() : 'Unknown'}</p>`
                        : '<p>Ping status not available. Click "Ping" to check.</p>'
                    }
                    <button class="btn btn-small btn-primary" onclick="pingDevice('${device.ip}'); setTimeout(() => showDeviceDetails('${device.ip}'), 1000)">Refresh Ping</button>
                </div>
                ${portsHtml}
                <div class="modal-section">
                    <button class="btn btn-primary" onclick="scanDevicePorts('${device.ip}')">Scan Ports</button>
                </div>
            `;
        })
        .catch(error => {
            modalContent.innerHTML = '<div class="modal-loading">Error loading device details.</div>';
        });
}

function closeDeviceModal() {
    document.getElementById('deviceModal').style.display = 'none';
}

window.onclick = function(event) {
    const modal = document.getElementById('deviceModal');
    if (event.target == modal) {
        modal.style.display = 'none';
    }
}

function startScan() {
    fetch('/api/scan', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        }
    })
    .then(response => response.json())
        .then(data => {
            if (data.status === 'started') {
                updateStatus();
                
                const checkInterval = setInterval(() => {
                    fetch('/api/status')
                        .then(response => response.json())
                        .then(statusData => {
                            if (!statusData.scan_in_progress) {
                                clearInterval(checkInterval);
                                refreshDevices();
                                updateStatus();
                            }
                        });
                }, 1000);
            }
        })
        .catch(error => {
            alert('Error starting scan. Please try again.');
        });
}

function startAutoRefresh() {
    if (scanInterval) {
        clearInterval(scanInterval);
    }
    
    scanInterval = setInterval(() => {
        fetch('/api/status')
            .then(response => response.json())
            .then(statusData => {
                if (!statusData.scan_in_progress) {
                    refreshDevices();
                }
            })
            .catch(error => {
            });
    }, 5000);
}

window.refreshDevices = refreshDevices;

document.addEventListener('DOMContentLoaded', function() {
    if (localStorage.getItem('darkMode') === 'true') {
        document.body.classList.add('dark-mode');
        const icon = document.getElementById('darkModeIcon');
        if (icon) icon.textContent = '☀️';
    }
    
    const refreshBtn = document.getElementById('refreshBtn');
    if (refreshBtn) {
        refreshBtn.onclick = null;
        refreshBtn.addEventListener('click', function(e) {
            e.preventDefault();
            e.stopPropagation();
            refreshDevices();
            return false;
        });
    }
    
    updateStatus();
    refreshDevices();
    loadNetworkInfo();
});
