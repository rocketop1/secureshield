#!/bin/bash

echo "Welcome to SecureShield Update Script"
echo "------------------------------------"
echo "1. Update SecureShield"
echo "2. Reinstall Layer 4 and Layer 7"
echo "3. Exit"

read -p "Please enter your choice (1-3): " choice

case $choice in
    1)
        read -p "Are you sure you want to update SecureShield? (y/n): " confirm
        if [[ $confirm =~ ^[Yy]$ ]]; then
            update_secure_shield
        else
            echo "Update cancelled."
        fi
        ;;
    2)
        read -p "Are you sure you want to reinstall Layer 4 and Layer 7? This will remove existing configurations. (y/n): " confirm
        if [[ $confirm =~ ^[Yy]$ ]]; then
            reinstall_layers
        else
            echo "Reinstallation cancelled."
        fi
        ;;
    3)
        echo "Exiting."
        exit 0
        ;;
    *)
        echo "Invalid choice. Please enter a number between 1 and 3."
        ;;
esac

update_secure_shield() {
    if [ -d "/etc/secure-shield" ]; then
        echo "Removing existing /etc/secure-shield directory..."
        rm -rf /etc/secure-shield
    fi

    mkdir /etc/secure-shield
    cd /etc/secure-shield

    git clone https://github.com/LylaNodes/SecureShield .

    if ! command -v node &> /dev/null; then
        curl -sL https://deb.nodesource.com/setup_14.x | bash -
        apt install -y nodejs
    fi

    npm install

    apt update
    apt upgrade -y

    cat <<EOF > /etc/systemd/system/secure.service
[Unit]
Description=SecureShield Protection Service
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
    systemctl restart secure

    echo "SecureShield updated successfully."
}

reinstall_layers() {
    cd /etc/nginx/conf.d/

    mkdir -p secure-shield-layer-7  # Create the directory if it doesn't exist

    cd secure-shield-layer-7  # Navigate into the directory

    git clone https://github.com/LylaNodes/secure-shield-layer-7 .

    echo "Layer 4 and Layer 7 reinstalled successfully."
}
