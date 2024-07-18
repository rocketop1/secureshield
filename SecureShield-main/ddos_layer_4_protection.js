const express = require('express');
const httpProxy = require('http-proxy');
const fs = require('fs');
const net = require('net');
const dgram = require('dgram');
const http = require('http');

const MAX_CONNECTIONS_PER_IP = 80;
const CONNECTION_TIMEOUT = 45000;
const TEMP_BLACKLIST_DURATION = 86400000; // 1 day in milliseconds
const PERMANENT_BLACKLIST_THRESHOLD = 3; // Number of times to trigger permanent blacklist
const MAX_HTTP_REQUESTS_PER_MIN = 75;
const LOG_FILE_PATH = './attack_logs.txt';
const REDIRECT_URLS = ['https://www.youtube.com', 'https://www.google.com', 'https://www.chatgpt.com'];

const activeConnections = {};
const blacklistedIPs = {};
const ipRequestCounters = {};
const ddosLoggedIPs = new Set();

const app = express();
const proxy = httpProxy.createProxyServer({});

// Utility functions
function logMessage(message) {
    const timestamp = new Date().toISOString();
    const log = `[${timestamp}] ${message}\n`;
    fs.appendFile(LOG_FILE_PATH, log, (err) => {
        if (err) {
            console.error('Log file write error:', err);
        }
    });
}

function addIPToBlacklist(ip, permanent = false) {
    logMessage(`IP blacklisted: ${ip}`);
    blacklistedIPs[ip] = { permanent, timestamp: Date.now() };
    if (permanent) {
        ddosLoggedIPs.add(ip);
    }
    setTimeout(() => {
        logMessage(`IP removed from blacklist: ${ip}`);
        delete blacklistedIPs[ip];
        ddosLoggedIPs.delete(ip);
    }, permanent ? Infinity : TEMP_BLACKLIST_DURATION);
}

function recordDDoSAttack(ip, packetsPerSec, port) {
    const logMessage = `DDoS Alert: IP ${ip} | Packets per second: ${packetsPerSec} | Port: ${port}\n`;
    logMessage(logMessage);
}

function redirectRandom(res) {
    const randomUrl = REDIRECT_URLS[Math.floor(Math.random() * REDIRECT_URLS.length)];
    res.redirect(randomUrl);
}

function monitorDataTraffic(socket, ipAddress, port) {
    let packetCounter = 0;
    let packetsPerSecond = 0;
    const monitoringInterval = setInterval(() => {
        packetsPerSecond = packetCounter;
        packetCounter = 0;
    }, 1000);

    socket.on('data', (data) => {
        packetCounter++;
        logMessage(`Data received from ${ipAddress}:${port} - ${data}`);
    });

    socket.on('end', () => {
        clearInterval(monitoringInterval);
        activeConnections[ipAddress]--;
        logMessage(`Connection ended with ${ipAddress}:${port}`);
    });

    socket.on('error', (err) => {
        clearInterval(monitoringInterval);
        logMessage(`Connection error from ${ipAddress}:${port} - ${err.message}`);
        activeConnections[ipAddress]--;
        socket.destroy();
    });

    setInterval(() => {
        if (packetsPerSecond > MAX_CONNECTIONS_PER_IP) {
            logMessage(`DDoS detected from ${ipAddress}:${port}. Packets per second: ${packetsPerSecond}`);
            if (!ddosLoggedIPs.has(ipAddress)) {
                recordDDoSAttack(ipAddress, packetsPerSecond, port);
            }
            if (blacklistedIPs[ipAddress]) {
                const { permanent } = blacklistedIPs[ipAddress];
                if (permanent) {
                    logMessage(`IP ${ipAddress} already permanently blacklisted.`);
                } else {
                    blacklistedIPs[ipAddress].timestamp = Date.now();
                    blacklistedIPs[ipAddress].permanent = true;
                    logMessage(`IP ${ipAddress} permanently blacklisted.`);
                }
            } else {
                addIPToBlacklist(ipAddress);
            }
            clearInterval(monitoringInterval);
            socket.destroy();
        }
    }, 1000);
}

function applyFirewall(socket, ipAddress, port) {
    if (blacklistedIPs[ipAddress]) {
        const { permanent } = blacklistedIPs[ipAddress];
        logMessage(`Connection rejected from blacklisted IP ${ipAddress}`);
        socket.destroy();
        if (!permanent) {
            addIPToBlacklist(ipAddress);
        }
        return;
    }

    activeConnections[ipAddress] = (activeConnections[ipAddress] || 0) + 1;
    socket.setTimeout(CONNECTION_TIMEOUT, () => {
        activeConnections[ipAddress]--;
        logMessage(`Connection timeout for ${ipAddress}:${port}`);
    });

    monitorDataTraffic(socket, ipAddress, port);
}

// TCP Server setup
const tcpServer = net.createServer((socket) => {
    const ipAddress = socket.remoteAddress;
    const port = socket.remotePort;
    logMessage(`Incoming TCP connection from ${ipAddress}:${port}`);
    applyFirewall(socket, ipAddress, port);
});

const tcpPort = 2745;
tcpServer.listen(tcpPort, () => {
    logMessage(`TCP server is listening on port ${tcpPort}`);
});

// UDP Server setup
const udpServer = dgram.createSocket('udp4');

udpServer.on('error', (err) => {
    logMessage(`UDP server error:\n${err.stack}`);
    udpServer.close();
});

udpServer.on('message', (msg, rinfo) => {
    const ipAddress = rinfo.address;
    const port = rinfo.port;
    logMessage(`Incoming UDP message from ${ipAddress}:${port}`);
    if (blacklistedIPs[ipAddress]) {
        logMessage(`UDP message rejected from blacklisted IP ${ipAddress}`);
        return;
    }
    // Handle UDP traffic as needed
});

udpServer.on('listening', () => {
    const address = udpServer.address();
    logMessage(`UDP Traffic ${address.address}:${address.port}`);
});

udpServer.bind(0); // Bind to a random available port

// HTTP Server setup
app.use((req, res, next) => {
    const ipAddress = req.connection.remoteAddress;
    logMessage(`Incoming HTTP request from ${ipAddress}`);

    if (blacklistedIPs[ipAddress]) {
        logMessage(`HTTP request rejected from blacklisted IP ${ipAddress}`);
        res.status(403).send('Forbidden');
        return;
    }

    const currentTime = Math.floor(Date.now() / 60000);
    ipRequestCounters[ipAddress] = ipRequestCounters[ipAddress] || {};
    ipRequestCounters[ipAddress][currentTime] = (ipRequestCounters[ipAddress][currentTime] || 0) + 1;

    const requestCount = Object.values(ipRequestCounters[ipAddress]).reduce((acc, cur) => acc + cur, 0);

    if (requestCount > MAX_HTTP_REQUESTS_PER_MIN) {
        logMessage(`DDoS detected from ${ipAddress}. Requests per minute: ${requestCount}`);
        if (!ddosLoggedIPs.has(ipAddress)) {
            recordDDoSAttack(ipAddress, requestCount, 'HTTP');
        }
        if (blacklistedIPs[ipAddress]) {
            const { permanent } = blacklistedIPs[ipAddress];
            if (permanent) {
                logMessage(`IP ${ipAddress} already permanently blacklisted.`);
            } else {
                blacklistedIPs[ipAddress].timestamp = Date.now();
                blacklistedIPs[ipAddress].permanent = true;
                logMessage(`IP ${ipAddress} permanently blacklisted.`);
            }
        } else {
            addIPToBlacklist(ipAddress);
        }
        res.status(403).send('Forbidden | = You have been blacklisted from this site!');
    } else {
        next();
    }
});

app.use((req, res, next) => {
    const ipAddress = req.connection.remoteAddress;
    if (activeConnections[ipAddress] > MAX_CONNECTIONS_PER_IP) {
        logMessage(`Redirecting heavy traffic to ${ipAddress}`);
        redirectRandom(res);
    } else {
        next();
    }
});

const ddosPort = 7785;
app.listen(ddosPort, () => {
    logMessage(`DDos Protection Layer 4 Is Being Protected on port ${ddosPort}`);
});
