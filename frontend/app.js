// Global variables for entropy collection
let entropyPool = [];
const MAX_ENTROPY_EVENTS = 1000;
let entropyStrength = 0;

// API endpoints
const API_BASE_URL = '/api';
const API_ENDPOINTS = {
    upload: `${API_BASE_URL}/upload`,
    files: `${API_BASE_URL}/files`,
    file: (id) => `${API_BASE_URL}/files/${id}`,
    accessControl: `${API_BASE_URL}/access`,
    accessHistory: (id) => `${API_BASE_URL}/files/${id}/history`,
    verifyIntegrity: (id) => `${API_BASE_URL}/files/${id}/verify`,
    dashboard: `${API_BASE_URL}/dashboard`,
    stats: `${API_BASE_URL}/stats`
};

// Initialize the application
document.addEventListener('DOMContentLoaded', function() {
    // Collect entropy from user events for stronger encryption keys
    setupEntropyCollection();
    
    // Initialize forms and event listeners
    initializeApp();
    
    // Load initial data
    if (document.getElementById('fileList')) {
        loadFileList();
    }
    
    // Initialize dashboard if we're on that page
    if (document.getElementById('encryptionDistribution')) {
        initializeDashboard();
    }
});

// ---------------------------- //
// Entropy Collection Functions //
// ---------------------------- //

function setupEntropyCollection() {
    // Collect entropy from mouse movements
    document.addEventListener('mousemove', collectMouseEntropy);
    
    // Collect entropy from keystrokes
    document.addEventListener('keypress', collectKeystrokeEntropy);
    
    // Other sources of entropy
    document.addEventListener('click', collectClickEntropy);
    window.addEventListener('deviceorientation', collectOrientationEntropy);
    
    // Update entropy strength indicator every second
    setInterval(updateEntropyStrength, 1000);
}

function collectMouseEntropy(event) {
    if (entropyPool.length >= MAX_ENTROPY_EVENTS) return;
    
    const mouseData = {
        x: event.clientX,
        y: event.clientY,
        timestamp: performance.now()
    };
    
    entropyPool.push(mouseData);
}

function collectKeystrokeEntropy(event) {
    if (entropyPool.length >= MAX_ENTROPY_EVENTS) return;
    
    const keystrokeData = {
        key: event.key.charCodeAt(0), // Just get the character code, not the actual key
        timestamp: performance.now()
    };
    
    entropyPool.push(keystrokeData);
}

function collectClickEntropy(event) {
    if (entropyPool.length >= MAX_ENTROPY_EVENTS) return;
    
    const clickData = {
        x: event.clientX,
        y: event.clientY,
        button: event.button,
        timestamp: performance.now()
    };
    
    entropyPool.push(clickData);
}

function collectOrientationEntropy(event) {
    if (entropyPool.length >= MAX_ENTROPY_EVENTS) return;
    
    if (event.alpha !== null && event.beta !== null && event.gamma !== null) {
        const orientationData = {
            alpha: event.alpha,
            beta: event.beta,
            gamma: event.gamma,
            timestamp: performance.now()
        };
        
        entropyPool.push(orientationData);
    }
}

function updateEntropyStrength() {
    // Calculate entropy strength (simplified)
    entropyStrength = Math.min(100, Math.floor(entropyPool.length / MAX_ENTROPY_EVENTS * 100));
    
    // Update UI
    const strengthElement = document.getElementById('entropyStrength');
    if (strengthElement) {
        strengthElement.textContent = `${entropyStrength}%`;
        
        // Visual indication
        if (entropyStrength < 30) {
            strengthElement.style.color = 'var(--error-color)';
        } else if (entropyStrength < 70) {
            strengthElement.style.color = 'var(--warning-color)';
        } else {
            strengthElement.style.color = 'var(--success-color)';
        }
    }
}

function getRandomBytesFromEntropy(numBytes) {
    // Generate random bytes based on collected entropy
    let randomBytes = new Uint8Array(numBytes);
    
    if (entropyPool.length > 0) {
        // Mix entropy pool into bytes using a simple algorithm
        for (let i = 0; i < numBytes; i++) {
            let entropy = 0;
            const entropyIndex = i % entropyPool.length;
            const entropyItem = entropyPool[entropyIndex];
            
            // Mix different values based on data type
            if (entropyItem.x !== undefined) {
                entropy ^= entropyItem.x + entropyItem.y;
            } else if (entropyItem.key !== undefined) {
                entropy ^= entropyItem.key;
            } else if (entropyItem.alpha !== undefined) {
                entropy ^= Math.floor(entropyItem.alpha + entropyItem.beta + entropyItem.gamma);
            }
            
            // Add timestamp information
            entropy ^= Math.floor(entropyItem.timestamp % 256);
            
            // Additional mixing
            entropy ^= Math.floor(Math.random() * 256);
            
            randomBytes[i] = entropy % 256;
        }
    } else {
        // Fallback to basic random if no entropy collected
        for (let i = 0; i < numBytes; i++) {
            randomBytes[i] = Math.floor(Math.random() * 256);
        }
    }
    
    return randomBytes;
}

// Simulate a very basic qubit-based key generation
// Note: This is a simulation for educational purposes
function simulateQuantumKeyGeneration(numBits = 256) {
    const qubits = new Uint8Array(numBits / 8);
    
    // Mix entropy with simulated quantum randomness
    const entropyBytes = getRandomBytesFromEntropy(numBits / 8);
    
    // Simplified quantum simulation (Hadamard gates + measurement)
    for (let i = 0; i < qubits.length; i++) {
        // Start with entropy-seeded value
        let qubit = entropyBytes[i];
        
        // Simulate superposition and measurement (simplified)
        for (let bit = 0; bit < 8; bit++) {
            // Simulate Hadamard gate
            const inSuperposition = Math.random() > 0.5;
            
            // Simulate measurement
            if (inSuperposition) {
                // Random collapse
                qubit ^= ((Math.random() > 0.5 ? 1 : 0) << bit);
            }
        }
        
        qubits[i] = qubit;
    }
    
    return Array.from(qubits).map(b => b.toString(16).padStart(2, '0')).join('');
}

// -------------------------- //
// Main Application Functions //
// -------------------------- //

function initializeApp() {
    // Set up upload form
    const uploadForm = document.getElementById('uploadForm');
    if (uploadForm) {
        uploadForm.addEventListener('submit', handleFileUpload);
    }
    
    // Set up access control form
    const accessControlForm = document.getElementById('accessControlForm');
    if (accessControlForm) {
        accessControlForm.addEventListener('submit', handleAccessControl);
    }
    
    // Set up file search
    const fileSearch = document.getElementById('fileSearch');
    if (fileSearch) {
        fileSearch.addEventListener('input', handleFileSearch);
    }
    
    // Set up modal functionality
    setupModalFunctionality();
}

async function handleFileUpload(event) {
    event.preventDefault();
    
    const fileInput = document.getElementById('fileInput');
    const accessDescription = document.getElementById('accessDescription').value;
    const encryptionPreference = document.getElementById('encryptionPreference').value;
    
    if (!fileInput.files || fileInput.files.length === 0) {
        showNotification('Please select a file to upload', 'error');
        return;
    }
    
    const file = fileInput.files[0];
    
    // Create form data
    const formData = new FormData();
    formData.append('file', file);
    formData.append('accessDescription', accessDescription);
    formData.append('encryptionPreference', encryptionPreference);
    
    // Add entropy-derived key
    formData.append('entropyStrength', entropyStrength.toString());
    const entropyKey = simulateQuantumKeyGeneration(256);
    formData.append('entropyKey', entropyKey);
    
    try {
        showNotification('Uploading and encrypting file...', 'info');
        
        const response = await fetch(API_ENDPOINTS.upload, {
            method: 'POST',
            body: formData
        });
        
        const result = await response.json();
        
        if (response.ok) {
            showNotification('File uploaded and encrypted successfully!', 'success');
            loadFileList(); // Refresh file list
            
            // Reset form
            uploadForm.reset();
        } else {
            showNotification(`Error: ${result.message}`, 'error');
        }
    } catch (error) {
        console.error('Upload error:', error);
        showNotification('Failed to upload file. Please try again.', 'error');
    }
}

async function loadFileList() {
    try {
        const response = await fetch(API_ENDPOINTS.files);
        
        if (!response.ok) {
            throw new Error('Failed to fetch files');
        }
        
        const files = await response.json();
        displayFiles(files);
        updateFileSelector(files);
    } catch (error) {
        console.error('Error loading files:', error);
        showNotification('Failed to load files. Please refresh the page.', 'error');
    }
}

function displayFiles(files) {
    const fileList = document.getElementById('fileList');
    
    if (!fileList) return;
    
    fileList.innerHTML = '';
    
    if (files.length === 0) {
        fileList.innerHTML = '<tr><td colspan="5" class="text-center">No files found</td></tr>';
        return;
    }
    
    files.forEach(file => {
        const row = document.createElement('tr');
        
        // Format file size
        const formattedSize = formatFileSize(file.size);
        
        // Format date
        const uploadDate = new Date(file.uploadedAt).toLocaleString();
        
        row.innerHTML = `
            <td>${file.name}</td>
            <td>${formattedSize}</td>
            <td>
                <span class="encryption-badge ${getEncryptionClass(file.encryption)}">
                    ${file.encryption}
                </span>
            </td>
            <td>${uploadDate}</td>
            <td>
                <button class="btn btn-small" data-action="download" data-id="${file.id}">Download</button>
                <button class="btn btn-small" data-action="info" data-id="${file.id}">Details</button>
                <button class="btn btn-small" data-action="delete" data-id="${file.id}">Delete</button>
            </td>
        `;
        
        // Add event listeners to buttons
        const downloadBtn = row.querySelector('[data-action="download"]');
        const infoBtn = row.querySelector('[data-action="info"]');
        const deleteBtn = row.querySelector('[data-action="delete"]');
        
        downloadBtn.addEventListener('click', () => downloadFile(file.id));
        infoBtn.addEventListener('click', () => showFileInfo(file.id));
        deleteBtn.addEventListener('click', () => deleteFile(file.id));
        
        fileList.appendChild(row);
    });
}

function getEncryptionClass(encryption) {
    const lower = encryption.toLowerCase();
    if (lower.includes('aes')) return 'encryption-aes';
    if (lower.includes('rsa')) return 'encryption-rsa';
    if (lower.includes('kyber')) return 'encryption-kyber';
    if (lower.includes('ntru')) return 'encryption-ntru';
    return '';
}

function formatFileSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    else if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    else if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + ' MB';
    else return (bytes / 1073741824).toFixed(1) + ' GB';
}

function updateFileSelector(files) {
    const fileSelector = document.getElementById('fileSelector');
    
    if (!fileSelector) return;
    
    fileSelector.innerHTML = '';
    
    if (files.length === 0) {
        fileSelector.innerHTML = '<option value="">No files available</option>';
        return;
    }
    
    files.forEach(file => {
        const option = document.createElement('option');
        option.value = file.id;
        option.textContent = file.name;
        fileSelector.appendChild(option);
    });
}

async function handleAccessControl(event) {
    event.preventDefault();
    
    const fileId = document.getElementById('fileSelector').value;
    const nlpCommand = document.getElementById('nlpCommand').value;
    
    if (!fileId) {
        showNotification('Please select a file', 'error');
        return;
    }
    
    if (!nlpCommand) {
        showNotification('Please enter an access control command', 'error');
        return;
    }
    
    try {
        const response = await fetch(API_ENDPOINTS.accessControl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                fileId,
                command: nlpCommand
            })
        });
        
        const result = await response.json();
        
        if (response.ok) {
            showNotification('Access permissions updated successfully!', 'success');
            document.getElementById('nlpCommand').value = '';
        } else {
            showNotification(`Error: ${result.message}`, 'error');
        }
    } catch (error) {
        console.error('Access control error:', error);
        showNotification('Failed to update access permissions. Please try again.', 'error');
    }
}

async function downloadFile(fileId) {
    try {
        // First, check if the user has access
        const response = await fetch(API_ENDPOINTS.file(fileId));
        
        if (!response.ok) {
            throw new Error('You do not have access to this file');
        }
        
        // Use the file endpoint directly for download
        window.location.href = API_ENDPOINTS.file(fileId) + '/download';
    } catch (error) {
        console.error('Download error:', error);
        showNotification('Failed to download file. ' + error.message, 'error');
    }
}

async function showFileInfo(fileId) {
    try {
        // Fetch file details
        const fileResponse = await fetch(API_ENDPOINTS.file(fileId));
        
        if (!fileResponse.ok) {
            throw new Error('Failed to load file information');
        }
        
        const file = await fileResponse.json();
        
        // Fetch access history
        const historyResponse = await fetch(API_ENDPOINTS.accessHistory(fileId));
        
        if (!historyResponse.ok) {
            throw new Error('Failed to load access history');
        }
        
        const history = await historyResponse.json();
        
        // Display modal with info
        displayFileInfoModal(file, history);
    } catch (error) {
        console.error('Error showing file info:', error);
        showNotification('Failed to load file details. ' + error.message, 'error');
    }
}

function displayFileInfoModal(file, history) {
    const modal = document.getElementById('fileInfoModal');
    const fileDetails = document.getElementById('fileDetails');
    const accessLogs = document.getElementById('accessLogs');
    
    // Fill file details
    fileDetails.innerHTML = `
        <p><strong>Name:</strong> ${file.name}</p>
        <p><strong>Size:</strong> ${formatFileSize(file.size)}</p>
        <p><strong>Encryption:</strong> ${file.encryption}</p>
        <p><strong>Uploaded:</strong> ${new Date(file.uploadedAt).toLocaleString()}</p>
        <p><strong>Last Modified:</strong> ${new Date(file.modifiedAt).toLocaleString()}</p>
        <p><strong>Hash:</strong> <span class="file-hash">${file.hash}</span></p>
        
        <div class="access-permissions">
            <h3>Access Permissions</h3>
            <ul>
                ${file.permissions.map(perm => `
                    <li>
                        <span class="permission-user">${perm.user}</span>: 
                        <span class="permission-level">${perm.level}</span>
                        ${perm.expiry ? `<span class="permission-expiry">(Until ${new Date(perm.expiry).toLocaleString()})</span>` : ''}
                    </li>
                `).join('')}
            </ul>
        </div>
    `;
    
    // Fill access history
    accessLogs.innerHTML = '';
    
    if (history.length === 0) {
        accessLogs.innerHTML = '<li>No access history found</li>';
    } else {
        history.forEach(entry => {
            const li = document.createElement('li');
            const date = new Date(entry.timestamp).toLocaleString();
            li.innerHTML = `<strong>${date}</strong>: ${entry.user} ${entry.action} (${entry.details || 'No details'})`;
            accessLogs.appendChild(li);
        });
    }
    
    // Set up Merkle visualization
    renderMerkleTree(file.merkleRoot, 'merkleVisualization');
    
    // Set up Verify Integrity button
    document.getElementById('verifyIntegrity').onclick = () => verifyFileIntegrity(file.id);
    
    // Show modal
    modal.style.display = 'block';
}

function renderMerkleTree(merkleRoot, containerId) {
    // Simple visualization for now - in a real app, you'd build a proper tree
    const container = document.getElementById(containerId);
    
    // Just show root for now
    container.innerHTML = `
        <div class="merkle-root-visualization">
            <div class="merkle-node-display">
                <p>Root Hash:</p>
                <div class="merkle-hash">${merkleRoot}</div>
            </div>
        </div>
    `;
}

async function verifyFileIntegrity(fileId) {
    try {
        showNotification('Verifying file integrity...', 'info');
        
        const response = await fetch(API_ENDPOINTS.verifyIntegrity(fileId));
        
        if (!response.ok) {
            throw new Error('Integrity verification failed');
        }
        
        const result = await response.json();
        
        if (result.verified) {
            showNotification('File integrity verified! The file has not been tampered with.', 'success');
        } else {
            showNotification('Warning: File integrity check failed. The file may have been tampered with.', 'error');
        }
    } catch (error) {
        console.error('Integrity verification error:', error);
        showNotification('Failed to verify file integrity. ' + error.message, 'error');
    }
}

async function deleteFile(fileId) {
    if (!confirm('Are you sure you want to delete this file? This action cannot be undone.')) {
        return;
    }
    
    try {
        const response = await fetch(API_ENDPOINTS.file(fileId), {
            method: 'DELETE'
        });
        
        if (!response.ok) {
            throw new Error('Failed to delete file');
        }
        
        showNotification('File deleted successfully', 'success');
        loadFileList(); // Refresh the list
    } catch (error) {
        console.error('Delete error:', error);
        showNotification('Failed to delete file. ' + error.message, 'error');
    }
}

function handleFileSearch(event) {
    const searchTerm = event.target.value.toLowerCase();
    const fileRows = document.querySelectorAll('#fileList tr');
    
    fileRows.forEach(row => {
        const fileName = row.querySelector('td:first-child').textContent.toLowerCase();
        
        if (fileName.includes(searchTerm)) {
            row.style.display = '';
        } else {
            row.style.display = 'none';
        }
    });
}

function setupModalFunctionality() {
    // Get modal elements
    const modal = document.getElementById('fileInfoModal');
    
    if (!modal) return;
    
    const closeButton = modal.querySelector('.close-button');
    
    // Close modal when clicking X
    closeButton.addEventListener('click', () => {
        modal.style.display = 'none';
    });
    
    // Close modal when clicking outside
    window.addEventListener('click', (event) => {
        if (event.target === modal) {
            modal.style.display = 'none';
        }
    });
}

function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.textContent = message;
    
    // Add to page
    document.body.appendChild(notification);
    
    // Show with animation
    setTimeout(() => {
        notification.classList.add('show');
    }, 10);
    
    // Remove after delay
    setTimeout(() => {
        notification.classList.remove('show');
        setTimeout(() => {
            notification.remove();
        }, 300);
    }, 3000);
}

// -------------------------- //
// Dashboard Functionality    //
// -------------------------- //

function initializeDashboard() {
    // Load dashboard data
    loadDashboardData();
    
    // Setup dashboard tabs
    setupDashboardTabs();
    
    // Setup time range selector
    const timeRangeSelector = document.getElementById('timeRange');
    if (timeRangeSelector) {
        timeRangeSelector.addEventListener('change', () => {
            loadDashboardData(timeRangeSelector.value);
        });
    }
}

async function loadDashboardData(timeRange = 'week') {
    try {
        // Fetch dashboard data from API
        const response = await fetch(`${API_ENDPOINTS.dashboard}?timeRange=${timeRange}`);
        
        if (!response.ok) {
            throw new Error('Failed to load dashboard data');
        }
        
        const dashboardData = await response.json();
        
        // Fetch summary statistics
        const statsResponse = await fetch(`${API_ENDPOINTS.stats}?timeRange=${timeRange}`);
        
        if (!statsResponse.ok) {
            throw new Error('Failed to load statistics');
        }
        
        const statsData = await statsResponse.json();
        
        // Update dashboard charts and stats
        updateEncryptionDistributionChart(dashboardData.encryptionDistribution);
        updateAccessPatternsChart(dashboardData.accessPatterns);
        updateAIDecisionTreeViz(dashboardData.aiDecisions);
        updateUserScoresChart(dashboardData.userScores);
        updateSystemStats(statsData);
        
        // Update Merkle tree visualizations
        updateMerkleTreeViz(dashboardData.fileTree, 'merkleTreeViz');
        updateHistoricalMerkleTreeViz(dashboardData.historyTree, 'historyTreeViz');
        
        // Update access logs
        updateAccessLogs(dashboardData.accessLogs);
    } catch (error) {
        console.error('Dashboard loading error:', error);
        showNotification('Failed to load dashboard data. Please try again later.', 'error');
    }
}

function updateEncryptionDistributionChart(data) {
    const ctx = document.getElementById('encryptionDistribution').getContext('2d');
    
    // Destroy existing chart if it exists
    if (window.encryptionChart) {
        window.encryptionChart.destroy();
    }
    
    // Create new chart
    window.encryptionChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: data.map(item => item.algorithm),
            datasets: [{
                data: data.map(item => item.count),
                backgroundColor: [
                    '#3a86ff', // AES
                    '#8338ec', // RSA
                    '#ff006e', // Kyber
                    '#fb5607'  // NTRU
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom'
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.raw || 0;
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = Math.round((value / total) * 100);
                            return `${label}: ${value} files (${percentage}%)`;
                        }
                    }
                }
            }
        }
    });
    
    // Update legend with additional info
    updateEncryptionLegend(data);
}

function updateEncryptionLegend(data) {
    const legendContainer = document.getElementById('encryptionLegend');
    
    if (!legendContainer) return;
    
    legendContainer.innerHTML = '';
    
    data.forEach((item, index) => {
        const colors = ['#3a86ff', '#8338ec', '#ff006e', '#fb5607'];
        const div = document.createElement('div');
        div.className = 'legend-item';
        div.innerHTML = `
            <span class="legend-color" style="background-color: ${colors[index % colors.length]}"></span>
            <span class="legend-label">${item.algorithm}: </span>
            <span class="legend-value">${item.count} files</span>
            <div class="legend-details">Avg. size: ${formatFileSize(item.avgSize)}</div>
        `;
        legendContainer.appendChild(div);
    });
}

function updateAccessPatternsChart(data) {
    const ctx = document.getElementById('accessPatternsChart').getContext('2d');
    
    // Destroy existing chart if it exists
    if (window.accessChart) {
        window.accessChart.destroy();
    }
    
    // Create new chart
    window.accessChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: data.dates,
            datasets: [
                {
                    label: 'Downloads',
                    data: data.downloads,
                    borderColor: '#3a86ff',
                    backgroundColor: 'rgba(58, 134, 255, 0.1)',
                    fill: true,
                    tension: 0.3
                },
                {
                    label: 'Uploads',
                    data: data.uploads,
                    borderColor: '#8338ec',
                    backgroundColor: 'rgba(131, 56, 236, 0.1)',
                    fill: true,
                    tension: 0.3
                },
                {
                    label: 'Permission Changes',
                    data: data.permissions,
                    borderColor: '#ff006e',
                    backgroundColor: 'rgba(255, 0, 110, 0.1)',
                    fill: true,
                    tension: 0.3
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'top'
                }
            },
            scales: {
                x: {
                    grid: {
                        display: false
                    }
                },
                y: {
                    beginAtZero: true,
                    grid: {
                        color: 'rgba(0, 0, 0, 0.05)'
                    }
                }
            }
        }
    });
}

function updateAIDecisionTreeViz(data) {
    const container = document.getElementById('aiDecisionTree');
    
    if (!container) return;
    
    // Clear previous content
    container.innerHTML = '';
    
    // Set width and height
    const width = container.offsetWidth;
    const height = container.offsetHeight;
    
    // Create SVG
    const svg = d3.select('#aiDecisionTree')
        .append('svg')
        .attr('width', width)
        .attr('height', height)
        .append('g')
        .attr('transform', `translate(${width/2},50)`);
    
    // Create hierarchy
    const root = d3.hierarchy(data);
    
    // Set node size and spacing
    const treeLayout = d3.tree()
        .size([width * 0.8, height - 100]);
    
    // Layout nodes
    treeLayout(root);
    
    // Add links
    svg.selectAll('.decision-link')
        .data(root.links())
        .enter()
        .append('path')
        .attr('class', 'decision-link')
        .attr('d', d3.linkVertical()
            .x(d => d.x - width/2)
            .y(d => d.y)
        );
    
    // Add nodes
    const nodes = svg.selectAll('.decision-node')
        .data(root.descendants())
        .enter()
        .append('g')
        .attr('class', 'decision-node')
        .attr('transform', d => `translate(${d.x - width/2},${d.y})`);
    
    // Add circles to nodes
    nodes.append('circle')
        .attr('r', d => d.data.value ? 25 : 20)
        .style('fill', d => d.data.value ? '#f1f8ff' : '#fff');
    
    // Add text to nodes
    nodes.append('text')
        .attr('dy', 4)
        .attr('text-anchor', 'middle')
        .text(d => d.data.name)
        .style('font-size', '11px')
        .call(wrap, 40);
}

function wrap(text, width) {
    text.each(function() {
        const text = d3.select(this);
        const words = text.text().split(/\s+/).reverse();
        let word;
        let line = [];
        let lineNumber = 0;
        const lineHeight = 1.1;
        const y = text.attr("y");
        const dy = parseFloat(text.attr("dy"));
        let tspan = text.text(null).append("tspan").attr("x", 0).attr("y", y).attr("dy", dy + "em");
        
        while (word = words.pop()) {
            line.push(word);
            tspan.text(line.join(" "));
            if (tspan.node().getComputedTextLength() > width) {
                line.pop();
                tspan.text(line.join(" "));
                line = [word];
                tspan = text.append("tspan").attr("x", 0).attr("y", y).attr("dy", ++lineNumber * lineHeight + dy + "em").text(word);
            }
        }
    });
}

function updateUserScoresChart(data) {
    const ctx = document.getElementById('userScoresChart').getContext('2d');
    
    // Destroy existing chart if it exists
    if (window.userScoresChart) {
        window.userScoresChart.destroy();
    }
    
    // Create new chart
    window.userScoresChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: data.map(user => user.name),
            datasets: [{
                label: 'Trust Score',
                data: data.map(user => user.score),
                backgroundColor: data.map(user => {
                    // Color based on score
                    if (user.score >= 80) return 'rgba(56, 176, 0, 0.7)';
                    if (user.score >= 60) return 'rgba(255, 190, 11, 0.7)';
                    return 'rgba(217, 4, 41, 0.7)';
                }),
                borderColor: data.map(user => {
                    if (user.score >= 80) return 'rgb(56, 176, 0)';
                    if (user.score >= 60) return 'rgb(255, 190, 11)';
                    return 'rgb(217, 4, 41)';
                }),
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100
                }
            }
        }
    });
}

function updateSystemStats(data) {
    // Update system metric displays
    document.getElementById('avgEncryptionTime').textContent = `${data.avgEncryptionTime.toFixed(2)} ms`;
    document.getElementById('filesProcessed').textContent = data.filesProcessed;
    document.getElementById('storageUsed').textContent = formatFileSize(data.storageUsed);
    document.getElementById('quantumScore').textContent = `${data.quantumSecurityScore}/10`;
}

function updateMerkleTreeViz(data, containerId) {
    const container = document.getElementById(containerId);
    
    if (!container) return;
    
    // Clear previous content
    container.innerHTML = '';
    
    // Set width and height
    const width = container.offsetWidth;
    const height = container.offsetHeight;
    
    // Create SVG
    const svg = d3.select(`#${containerId}`)
        .append('svg')
        .attr('width', width)
        .attr('height', height)
        .append('g')
        .attr('transform', `translate(${width/2},50)`);
    
    // Create hierarchy
    const root = d3.hierarchy(data);
    
    // Set node size and spacing
    const treeLayout = d3.tree()
        .size([width * 0.8, height - 100]);
    
    // Layout nodes
    treeLayout(root);
    
    // Add links
    svg.selectAll('.merkle-link')
        .data(root.links())
        .enter()
        .append('path')
        .attr('class', 'merkle-link')
        .attr('d', d3.linkVertical()
            .x(d => d.x - width/2)
            .y(d => d.y)
        );
    
    // Add nodes
    const nodes = svg.selectAll('.merkle-node')
        .data(root.descendants())
        .enter()
        .append('g')
        .attr('class', d => `merkle-node ${d.data.verified ? 'highlighted' : ''}`)
        .attr('transform', d => `translate(${d.x - width/2},${d.y})`);
    
    // Add circles to nodes
    nodes.append('circle')
        .attr('r', 20);
    
    // Add labels to nodes
    nodes.append('text')
        .attr('dy', 4)
        .attr('text-anchor', 'middle')
        .text(d => d.data.name || 'Hash')
        .style('font-size', '10px');
}

function updateHistoricalMerkleTreeViz(data, containerId) {
    // Similar to updateMerkleTreeViz but with different styling for historical view
    updateMerkleTreeViz(data, containerId);
}

function updateAccessLogs(logs) {
    const logsContainer = document.getElementById('accessLogs');
    
    if (!logsContainer) return;
    
    logsContainer.innerHTML = '';
    
    if (logs.length === 0) {
        logsContainer.innerHTML = '<tr><td colspan="5" class="text-center">No access logs found</td></tr>';
        return;
    }
    
    logs.forEach(log => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${new Date(log.timestamp).toLocaleString()}</td>
            <td>${log.user}</td>
            <td>${log.fileName}</td>
            <td>${log.action}</td>
            <td>${log.details || '-'}</td>
        `;
        logsContainer.appendChild(row);
    });
}

function setupDashboardTabs() {
    const tabButtons = document.querySelectorAll('.tab-button');
    
    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            // Remove active class from all buttons and panes
            document.querySelectorAll('.tab-button').forEach(btn => {
                btn.classList.remove('active');
            });
            
            document.querySelectorAll('.tab-pane').forEach(pane => {
                pane.classList.remove('active');
            });
            
            // Add active class to clicked button
            button.classList.add('active');
            
            // Show corresponding tab pane
            const tabId = button.getAttribute('data-tab');
            document.getElementById(tabId).classList.add('active');
        });
    });
}