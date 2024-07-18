#!/bin/bash

if [[ $EUID -ne 0 ]]; then
    echo "Please run this script as root. Use 'sudo su' to execute it with root privileges."
    exit 1
fi

confirm_installation() {
    local answer
    read -p "Choose an option:
0. Install the Script
1. SecureShield Layer 7 Script
2. Install both [0] and [1] on the same machine (layer 7 script, runs after the layer 4 script)
3. Uninstall Everything
Please enter the number of your choice (0/1/2/3): " answer </dev/tty
    
    case $answer in
        0)
            if is_secure_shield_installed; then
                echo "SecureShield is already installed!"
            else
                echo "Installing SecureShield..."
                install_secure_shield_protection
            fi
            ;;
        1)
            if is_layer_7_installed; then
                echo "SecureShield Layer 7 Script is already installed!"
            else
                echo "Installing SecureShield Layer 7 Script..."
                install_layer_7
            fi
            ;;
        2)
            if is_secure_shield_installed && is_layer_7_installed; then
                echo "SecureShield and Layer 7 are already installed!"
            else
                if ! is_secure_shield_installed; then
                    echo "Installing SecureShield..."
                    install_secure_shield_protection
                fi
                if ! is_layer_7_installed; then
                    echo "Installing SecureShield Layer 7 Script..."
                    install_layer_7
                fi
            fi
            ;;
        3)
            echo "Uninstalling Everything..."
            uninstall_lyla_protection
            uninstall_layer_7
            ;;
        *)
            echo "Invalid option. Exiting."
            exit 1
            ;;
    esac
}

is_secure_shield_installed() {
    if [[ -d /etc/secure-shield ]]; then
        return 0
    else
        return 1
    fi
}

is_layer_7_installed() {
    if [[ -d /etc/nginx/conf.d/secure-shield-layer-7 ]]; then
        return 0
    else
        return 1
    fi
}

install_secure_shield_protection() {
    cd /etc/
    apt update
    mkdir secure-shield
    cd secure-shield
    git clone https://github.com/ErroR404-sources/secureshield ./
    apt install npm 
    apt install -y nodejs
   
    
    
    # Install necessary NodeJS packages
    npm install url http dgram net fs child_process http-proxy express
    
    # Create systemd service file
    cat <<EOF > /etc/systemd/system/secure.service
[Unit]
Description=SecureShield Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/secure-shield
ExecStart=/usr/bin/node /etc/secure-shield/ddos_layer_4_protection.js
Restart=always
StandardOutput=syslog
StandardError=syslog

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable secure
    systemctl start secure
    
    # Configure iptables rules
    configure_iptables
    
    echo "SecureShield Protection setup complete."
}

uninstall_lyla_protection() {
    systemctl stop secure
    systemctl disable secure
    rm /etc/systemd/system/secure.service
    systemctl daemon-reload
    iptables -F
    iptables-save > /etc/iptables/rules.v4
    rm -rf /etc/secure-shield
    echo "SecureShield Protection uninstalled."
}

install_layer_7() {
    mkdir -p /etc/nginx/conf.d/secure-shield-layer-7
    cd /etc/nginx/conf.d/secure-shield-layer-7
    curl -Lo protection.lua https://raw.githubusercontent.com/LylaNodes/secure-shield-layer-7/main/protection.lua
    apt-get install -y libnginx-mod-http-lua
    echo "SecureShield Layer 7 Protection is now on your machine!"
}

uninstall_layer_7() {
    rm -rf /etc/nginx/conf.d/secure-shield-layer-7
    apt-get remove -y libnginx-mod-http-lua
    echo "Layer 7 protection uninstalled."
}

configure_iptables() {
    # Configure iptables rules
    iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT
    iptables -A INPUT -p udp -m limit --limit 1/s --limit-burst 3 -j ACCEPT
    iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 3 -j ACCEPT
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -j DROP
    
    iptables -A INPUT -i lo -j ACCEPT
    
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    iptables -A INPUT -p tcp --dport 80 -j ACCEPT
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT
    
    iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
    
    iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
    iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
    
    iptables -A INPUT -p icmp -m limit --limit 1/s -j ACCEPT
    
    iptables -A INPUT -j LOG --log-prefix "Dropped: "
    
    iptables -A INPUT -j DROP
    
    iptables-save > /etc/iptables/rules.v4
}

confirm_installation
