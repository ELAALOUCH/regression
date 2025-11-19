#!/bin/bash
# Script d'installation d'OpenSSH vulnérable à regreSSHion (CVE-2024-6387)
# ⚠️ À UTILISER UNIQUEMENT DANS UN ENVIRONNEMENT DE LAB ISOLÉ ⚠️
# Ubuntu 22.04.5 LTS

echo "========================================"
echo "Installation OpenSSH vulnérable"
echo "CVE-2024-6387 (regreSSHion)"
echo "⚠️  ENVIRONNEMENT DE TEST UNIQUEMENT ⚠️"
echo "========================================"

# Versions vulnérables : 8.5p1 à 9.7p1
# On va installer la version 9.3p1 qui est vulnérable
OPENSSH_VERSION="9.3p1"

# 1. Sauvegarder la configuration actuelle
echo "[1/8] Sauvegarde de la configuration actuelle..."
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d)

# 2. Arrêter le service SSH actuel
echo "[2/8] Arrêt du service SSH..."
sudo systemctl stop ssh 2>/dev/null || sudo systemctl stop sshd 2>/dev/null

# 3. Installer les dépendances de compilation
echo "[3/8] Installation des dépendances..."
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    libssl-dev \
    zlib1g-dev \
    libpam0g-dev \
    libselinux1-dev \
    libkrb5-dev \
    wget

# 4. Télécharger OpenSSH vulnérable
echo "[4/8] Téléchargement d'OpenSSH ${OPENSSH_VERSION}..."
cd /tmp
wget https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-${OPENSSH_VERSION}.tar.gz

# 5. Extraire et compiler
echo "[5/8] Extraction et compilation..."
tar -xzf openssh-${OPENSSH_VERSION}.tar.gz
cd openssh-${OPENSSH_VERSION}

./configure \
    --prefix=/usr \
    --sysconfdir=/etc/ssh \
    --with-md5-passwords \
    --with-pam \
    --with-selinux \
    --with-privsep-path=/var/lib/sshd \
    --with-default-path=/usr/local/bin:/usr/bin:/bin \
    --with-superuser-path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    --with-pid-dir=/run

make -j$(nproc)

# 6. Installer
echo "[6/8] Installation..."
sudo make install

# 7. Vérifier la version installée
echo "[7/8] Vérification de la version..."
/usr/sbin/sshd -V

# 8. Configuration vulnérable
echo "[8/8] Application de la configuration vulnérable..."
sudo tee /etc/ssh/sshd_config > /dev/null <<'EOF'
# Configuration OpenSSH VULNÉRABLE pour regreSSHion (CVE-2024-6387)
# ⚠️ NE JAMAIS UTILISER EN PRODUCTION ⚠️

Port 22
Protocol 2
ListenAddress 0.0.0.0

# Clés hôte
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# Logging
SyslogFacility AUTH
LogLevel INFO

# === CONFIGURATION VULNÉRABLE regreSSHion ===

# LoginGraceTime DOIT ÊTRE DÉFINI (non à 0) pour être vulnérable
LoginGraceTime 120

# Authentification
PermitRootLogin yes
StrictModes no
MaxAuthTries 100
MaxSessions 50
PubkeyAuthentication no
PasswordAuthentication yes
PermitEmptyPasswords yes

# Forwarding
AllowTcpForwarding yes
X11Forwarding yes
PermitTunnel yes

# Autres paramètres vulnérables
PermitUserEnvironment yes
ClientAliveInterval 300
ClientAliveCountMax 10
MaxStartups 100:30:200

# Subsystème SFTP
Subsystem sftp /usr/lib/openssh/sftp-server

PrintMotd yes
PrintLastLog yes
EOF

# Générer les clés hôtes si nécessaire
echo "Génération des clés hôtes..."
sudo ssh-keygen -A

# Créer le service systemd
echo "Création du service systemd..."
sudo tee /etc/systemd/system/sshd.service > /dev/null <<'EOF'
[Unit]
Description=OpenSSH Daemon (Vulnerable Version)
After=network.target

[Service]
Type=notify
ExecStart=/usr/sbin/sshd -D
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
Restart=on-failure
RestartSec=42s

[Install]
WantedBy=multi-user.target
EOF

# Recharger systemd et démarrer
echo "Démarrage du service..."
sudo systemctl daemon-reload
sudo systemctl enable sshd
sudo systemctl start sshd

# Vérification finale
echo ""
echo "========================================"
echo "✅ Installation terminée !"
echo "========================================"
echo ""
echo "Version installée :"
/usr/sbin/sshd -V 2>&1 | head -n1
echo ""
echo "Statut du service :"
sudo systemctl status sshd --no-pager -l
echo ""
echo "Port en écoute :"
sudo ss -tulpn | grep :22
echo ""
echo "⚠️  ATTENTION : Ce serveur est VULNÉRABLE à CVE-2024-6387"
echo "    Utilisez uniquement dans un environnement isolé !"
echo ""
