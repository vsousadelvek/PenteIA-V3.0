/**
 * PenteIA v4.0 - Main JavaScript
 * Frontend logic and API integration
 */

const API_BASE = '/api';

// Global state
let systemState = {
    initialized: false,
    modules: {},
    operations: [],
    beacons: []
};

// ============================================================================
// API Helper Functions
// ============================================================================

async function apiCall(endpoint, options = {}) {
    const method = options.method || 'GET';
    const body = options.body ? JSON.stringify(options.body) : undefined;

    try {
        const response = await fetch(`${API_BASE}${endpoint}`, {
            method: method,
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            },
            body: body
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        return await response.json();
    } catch (error) {
        console.error(`API Error [${endpoint}]:`, error);
        throw error;
    }
}

// ============================================================================
// Status Functions
// ============================================================================

function showAlert(message, type = 'info', duration = 5000) {
    const alert = document.createElement('div');
    alert.className = `alert alert-${type} alert-dismissible fade show`;
    alert.setAttribute('role', 'alert');
    alert.innerHTML = `
        ${message}
        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="alert"></button>
    `;

    const container = document.body;
    container.insertBefore(alert, container.firstChild);

    if (duration > 0) {
        setTimeout(() => {
            alert.remove();
        }, duration);
    }
}

function showLoading(message = 'Loading...') {
    const loader = document.createElement('div');
    loader.id = 'loading-overlay';
    loader.className = 'position-fixed top-0 start-0 w-100 h-100 bg-dark bg-opacity-75 d-flex align-items-center justify-content-center';
    loader.innerHTML = `
        <div class="text-center text-light">
            <div class="spinner-border text-danger mb-3" role="status">
                <span class="visually-hidden">Loading...</span>
            </div>
            <p>${message}</p>
        </div>
    `;
    document.body.appendChild(loader);
    return loader;
}

function hideLoading() {
    const loader = document.getElementById('loading-overlay');
    if (loader) loader.remove();
}

// ============================================================================
// Status Monitoring
// ============================================================================

async function updateSystemStatus() {
    try {
        const data = await apiCall('/status');
        systemState.initialized = data.status !== 'error';
        updateStatusDisplay();
    } catch (error) {
        console.error('Status update failed:', error);
    }
}

function updateStatusDisplay() {
    const indicator = document.getElementById('system-status');
    if (indicator) {
        if (systemState.initialized) {
            indicator.innerHTML = '<i class="fas fa-circle text-success"></i> Healthy';
            indicator.className = 'mb-0 text-success';
        } else {
            indicator.innerHTML = '<i class="fas fa-circle text-danger"></i> Offline';
            indicator.className = 'mb-0 text-danger';
        }
    }
}

// ============================================================================
// Chart Functions
// ============================================================================

function createChart(canvasId, type, labels, data, colors) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return null;

    const chartContext = ctx.getContext('2d');
    return new Chart(chartContext, {
        type: type,
        data: {
            labels: labels,
            datasets: [{
                label: 'Data',
                data: data,
                backgroundColor: colors,
                borderColor: '#2D3748',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    labels: {
                        color: '#fff'
                    }
                }
            },
            scales: {
                x: {
                    ticks: { color: '#fff' },
                    grid: { color: '#444' }
                },
                y: {
                    ticks: { color: '#fff' },
                    grid: { color: '#444' }
                }
            }
        }
    });
}

// ============================================================================
// Data Formatting Functions
// ============================================================================

function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleString();
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

function formatTime(ms) {
    const seconds = Math.floor(ms / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);

    if (hours > 0) return `${hours}h ${minutes % 60}m`;
    if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
    return `${seconds}s`;
}

// ============================================================================
// Common UI Components
// ============================================================================

function createStatusBadge(status) {
    const colorMap = {
        'running': 'warning',
        'completed': 'success',
        'failed': 'danger',
        'active': 'success',
        'inactive': 'secondary'
    };
    const color = colorMap[status] || 'secondary';
    return `<span class="badge bg-${color}">${status}</span>`;
}

function createProgressBar(progress, label = '') {
    return `
        <div class="progress" style="height: 20px;">
            <div class="progress-bar bg-danger" style="width: ${progress}%;">
                ${label ? label : progress + '%'}
            </div>
        </div>
    `;
}

// ============================================================================
// Event Listeners
// ============================================================================

document.addEventListener('DOMContentLoaded', function() {
    // Update status every 5 seconds
    updateSystemStatus();
    setInterval(updateSystemStatus, 5000);

    // Handle Bootstrap modal events
    document.querySelectorAll('[data-bs-toggle="modal"]').forEach(button => {
        button.addEventListener('click', function() {
            const targetId = this.getAttribute('data-bs-target');
            const modal = new bootstrap.Modal(document.querySelector(targetId));
            modal.show();
        });
    });
});

// ============================================================================
// Keyboard Shortcuts
// ============================================================================

document.addEventListener('keydown', function(e) {
    // Ctrl+R: Refresh current page
    if (e.ctrlKey && e.key === 'r') {
        e.preventDefault();
        location.reload();
    }

    // Ctrl+L: Focus search/input
    if (e.ctrlKey && e.key === 'l') {
        e.preventDefault();
        const input = document.querySelector('input[type="text"]:first-of-type');
        if (input) input.focus();
    }

    // Escape: Close any open modals
    if (e.key === 'Escape') {
        document.querySelectorAll('.modal.show').forEach(modal => {
            bootstrap.Modal.getInstance(modal)?.hide();
        });
    }
});

// ============================================================================
// Utility Functions
// ============================================================================

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showAlert('Copied to clipboard!', 'success', 2000);
    }).catch(err => {
        showAlert('Failed to copy', 'danger');
    });
}

function downloadJSON(obj, filename) {
    const dataStr = JSON.stringify(obj, null, 2);
    const dataUri = 'data:application/json;charset=utf-8,'+ encodeURIComponent(dataStr);

    const exportFileDefaultName = filename || 'data.json';

    const linkElement = document.createElement('a');
    linkElement.setAttribute('href', dataUri);
    linkElement.setAttribute('download', exportFileDefaultName);
    linkElement.click();
}

function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// ============================================================================
// Export for other scripts
// ============================================================================

window.PenteIA = {
    apiCall,
    showAlert,
    showLoading,
    hideLoading,
    updateSystemStatus,
    createChart,
    formatDate,
    formatBytes,
    formatTime,
    createStatusBadge,
    createProgressBar,
    copyToClipboard,
    downloadJSON,
    debounce
};

