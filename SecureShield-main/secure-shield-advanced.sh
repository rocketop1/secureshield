#!/bin/bash


# Check if script is run as root
if [ "$(id -u)" != "0" ]; then
    echo "Please, be root and run the SecureShield Advanced Script using sudo su."
    exit 1
fi

sudo apt-get update
sudo apt-get install -y iptables-persistent fail2ban unbound

# Function to block IP address
block_ip() {
    echo "Enter IP address to block:"
    read ip_to_block
    iptables -A INPUT -s $ip_to_block -j DROP
    echo "Blocked IP address: $ip_to_block"
}

# Function to unblock IP address
unblock_ip() {
    echo "Enter IP address to unblock:"
    read ip_to_unblock
    iptables -D INPUT -s $ip_to_unblock -j DROP
    echo "Unblocked IP address: $ip_to_unblock"
}

# Function to adjust website speed
adjust_speed() {
    echo "Increasing the speed boost...."
    # Install haveged for entropy and adjust VM settings
    sudo apt-get update
    sudo apt-get install -y haveged
    sudo systemctl enable haveged
    sudo systemctl start haveged
    
    echo "vm.swappiness=10" | sudo tee -a /etc/sysctl.conf
    echo "vm.vfs_cache_pressure=50" | sudo tee -a /etc/sysctl.conf
    sudo sysctl -p

    # Install and configure zswap for compressed swap in RAM
    echo "Enabling zswap..."
    echo "GRUB_CMDLINE_LINUX_DEFAULT=\"quiet splash zswap.enabled=1 zswap.compressor=lz4 zswap.max_pool_percent=20 zswap.zpool=z3fold\"" | sudo tee -a /etc/default/grub
    sudo update-grub
}

# Function to adjust website security
adjust_security() {
    echo "Increasing Website Security......."
    # Install AppArmor for mandatory access controls
    sudo apt-get update
    sudo apt-get install -y apparmor
    sudo systemctl enable apparmor
    sudo systemctl start apparmor

    echo "kernel.dmesg_restrict=1" | sudo tee -a /etc/sysctl.conf
    echo "net.ipv4.conf.all.log_martians=1" | sudo tee -a /etc/sysctl.conf
    sudo sysctl -p

    # Install and configure UFW for firewall settings
    sudo apt-get install -y ufw
    sudo ufw default deny incoming
    sudo ufw default allow outgoing
    sudo ufw allow ssh
    sudo ufw enable
}

# Display SecureShield Advanced Script Menu
echo "SecureShield Advanced Script Menu"
echo "---------------------------------"
echo "1. Block IP Address"
echo "2. Unblock IP Address"
echo "3. Increase Website speed"
echo "4. Increase Website Security "
echo "5. Configure Both Website Security & Website Speed"
echo "6. Exit"
echo "---------------------------------"

# Prompt user for choice and validate input
read -p "Enter your choice (1-6): " choice
case $choice in
    1) block_ip ;;
    2) unblock_ip ;;
    3) adjust_speed ;;
    4) adjust_security ;;
    5) adjust_speed && adjust_security ;;
    6) echo "Exiting SecureShield Advanced Script." ;;
    *) echo "Invalid choice. Exiting." ;;
esac

# Save IP tables rules if necessary
if [[ $choice == 1 || $choice == 2 ]]; then
    iptables-save > /etc/iptables/rules.v4
fi

# Enable and restart services if necessary
if [[ $choice == 3 || $choice == 4 || $choice == 5 ]]; then
    sudo systemctl enable netfilter-persistent
    sudo systemctl restart fail2ban
    sudo systemctl restart unbound
    echo "Eveything, that you picked. Has been completed the changes will take affect in 1-2mins"
fi
