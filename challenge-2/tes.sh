#!/bin/bash

# Update and upgrade all packages
sudo apt-get update
sudo apt-get upgrade -y

# Disable password authentication for SSH and configure SSH to only allow public key authentication
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo sed -i 's/ChallengeResponseAuthentication yes/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
sudo sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config
sudo systemctl reload sshd

# Configure firewall to only allow traffic on ports 22 and 80
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw enable

# Ensure that the server is configured to use a non-root user for the application
sudo adduser dana
sudo usermod -aG sudo dana
sudo su - dana

# Disable any unnecessary services (e.g., apache2)
sudo systemctl disable apache2

# Remove any unused packages
sudo apt-get autoremove -y

# Ensure that the server is configured to use a secure DNS resolver
sudo sed -i 's/^nameserver.*/nameserver 1.1.1.1/' /etc/resolv.conf

# Configure the web server to use HTTPS with a valid SSL certificate
sudo apt-get install -y certbot
sudo certbot certonly --standalone -d contoh.com -d www.contoh.com
sudo mkdir /etc/nginx/ssl
sudo openssl pkcs12 -inkey /etc/letsencrypt/live/contoh.com/privkey.pem -in /etc/letsencrypt/live/contoh.com/fullchain.pem -export -out /etc/nginx/ssl/contoh.com.p12 -passout pass:
sudo openssl pkcs12 -in /etc/nginx/ssl/contoh.com.p12 -out /etc/nginx/ssl/contoh.com.pem -passin pass:
sudo echo "server {
    listen 80;
    server_name contoh.com www.contoh.com;
    return 301 https://$server_name$request_uri;
}
server {
    listen 443 ssl;
    server_name contoh.com www.contoh.com;
    ssl_certificate /etc/nginx/ssl/contoh.com.pem;
    ssl_certificate_key /etc/letsencrypt/live/contoh.com/privkey.pem;
    include /etc/nginx/conf.d/*.conf;
}" | sudo tee /etc/nginx/sites-available/contoh.com > /dev/null
sudo ln -s /etc/nginx/sites-available/contoh.com /etc/nginx/sites-enabled/
sudo systemctl reload nginx

# Configure the server to use a strong password policy and enable password complexity requirements
sudo apt-get install -y libpam-pwquality
sudo sed -i 's/# difok.*/difok=4/' /etc/security/pwquality.conf
sudo sed -i 's/# minlen.*/minlen=14/' /etc/security/pwquality.conf
sudo sed -i 's/# ucredit.*/ucredit=-1/' /etc/security/pwquality.conf
sudo sed -i 's/# lcredit.*/lcredit=-1/' /etc/security/pwquality.conf
sudo sed -i 's/# dcredit.*/dcredit=-1/' /etc/security/pwquality.conf
sudo sed -i 's/# ocredit.*/ocredit=-1/' /etc/security/pwquality.conf
sudo sed -i 's/password.*/password    requisite           pam_pwquality.so retry=3/' /etc/pam.d/common-password
