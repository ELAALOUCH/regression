#!/bin/bash
# Script COMPLET d'installation OpenSSH vulnérable à regreSSHion (CVE-2024-6387)
# ⚠️ UNIQUEMENT POUR ENVIRONNEMENT DE LAB ISOLÉ ⚠️
# Ubuntu 22.04 - Prêt pour connexion distante sur port 22
# Auteur: Script de démonstration sécurité

set -e  # Arrêter en cas d'erreur

echo "=========================================="
echo "  Installation OpenSSH VULNÉRABLE"
echo "  CVE-2024-6387 (regreSSHion)"
echo "  Version: 9.3p1"
echo "⚠️  LAB ISOLÉ UNIQUEMENT - NE PAS EXPOSER ⚠️"
echo "=========================================="
echo ""

# Vérification root
if [ "$EUID" -ne 0 ]; then 
    echo "❌ Ce script doit être exécuté en tant que root (sudo)"
    exit 1
fi

# Variables
OPENSSH_VERSION="9.3p1"
INSTALL_DIR="/tmp/openssh_install"
BACKUP_DIR="/root/ssh_backup_$(date +%Y%m%d_%H%M%S)"

# 1. Sauvegarde de la configuration actuelle
echo "[1/12] 💾 Sauvegarde de la configuration actuelle..."
mkdir -p "$BACKUP_DIR"
if [ -f /etc/ssh/sshd_config ]; then
    cp /etc/ssh/sshd_config "$BACKUP_DIR/"
    echo "✅ Configuration sauvegardée dans: $BACKUP_DIR"
fi

# 2. Arrêt de TOUS les services SSH
echo ""
echo "[2/12] ⏸️  Arrêt de tous les services SSH..."
systemctl stop ssh 2>/dev/null || true
systemctl stop sshd 2>/dev/null || true
systemctl stop ssh.service 2>/dev/null || true
systemctl stop sshd.service 2>/dev/null || true
pkill -9 sshd 2>/dev/null || true
sleep 2
echo "✅ Tous les services SSH arrêtés"

# 3. Installation des dépendances
echo ""
echo "[3/12] 📦 Installation des dépendances..."
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    build-essential \
    libssl-dev \
    zlib1g-dev \
    libpam0g-dev \
    libselinux1-dev \
    libkrb5-dev \
    wget \
    net-tools \
    openssh-client > /dev/null 2>&1
echo "✅ Dépendances installées"

# 4. Création de l'utilisateur système sshd
echo ""
echo "[4/12] 👤 Création de l'utilisateur système 'sshd'..."
if ! id -u sshd > /dev/null 2>&1; then
    useradd -r -s /usr/sbin/nologin -d /var/lib/sshd -c "SSH privilege separation" sshd
    echo "✅ Utilisateur sshd créé"
else
    echo "ℹ️  Utilisateur sshd existe déjà"
fi

# 5. Création de l'utilisateur de test 'victime'
echo ""
echo "[5/12] 👤 Création de l'utilisateur 'victime' pour les tests..."
if ! id -u victime > /dev/null 2>&1; then
    useradd -m -s /bin/bash victime
    echo "victime:victime123" | chpasswd
    echo "✅ Utilisateur victime créé (mot de passe: victime123)"
else
    echo "ℹ️  Utilisateur victime existe déjà"
    echo "victime:victime123" | chpasswd
    echo "✅ Mot de passe mis à jour (victime123)"
fi

# 6. Création des répertoires nécessaires
echo ""
echo "[6/12] 📁 Création des répertoires système..."
mkdir -p /var/lib/sshd
mkdir -p /var/empty/sshd
mkdir -p /run/sshd
chmod 755 /var/lib/sshd
chmod 755 /var/empty/sshd
chmod 755 /run/sshd
chown root:root /var/lib/sshd
chown root:root /var/empty/sshd
chown root:root /run/sshd
echo "✅ Répertoires créés"

# 7. Téléchargement d'OpenSSH vulnérable
echo ""
echo "[7/12] ⬇️  Téléchargement d'OpenSSH ${OPENSSH_VERSION}..."
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"
if [ ! -f "openssh-${OPENSSH_VERSION}.tar.gz" ]; then
    wget -q --show-progress https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-${OPENSSH_VERSION}.tar.gz
    echo "✅ Téléchargement terminé"
else
    echo "ℹ️  Archive déjà téléchargée"
fi

# 8. Extraction et compilation
echo ""
echo "[8/12] 🔨 Compilation d'OpenSSH (2-3 minutes)..."
rm -rf openssh-${OPENSSH_VERSION} 2>/dev/null || true
tar -xzf openssh-${OPENSSH_VERSION}.tar.gz
cd openssh-${OPENSSH_VERSION}

./configure \
    --prefix=/usr \
    --sysconfdir=/etc/ssh \
    --with-md5-passwords \
    --with-pam \
    --with-selinux \
    --with-privsep-path=/var/lib/sshd \
    --with-privsep-user=sshd \
    --with-default-path=/usr/local/bin:/usr/bin:/bin \
    --with-superuser-path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    --with-pid-dir=/run > /dev/null 2>&1

make -j$(nproc) > /dev/null 2>&1
make install > /dev/null 2>&1
echo "✅ Compilation et installation terminées"

# 9. Génération des clés hôtes
echo ""
echo "[9/12] 🔑 Génération des clés hôtes SSH..."
rm -f /etc/ssh/ssh_host_* 2>/dev/null || true
ssh-keygen -A > /dev/null 2>&1
chmod 600 /etc/ssh/ssh_host_*_key
chmod 644 /etc/ssh/ssh_host_*_key.pub
echo "✅ Clés générées et permissions configurées"

# 10. Configuration vulnérable
echo ""
echo "[10/12] ⚙️  Application de la configuration VULNÉRABLE..."
cat > /etc/ssh/sshd_config <<'EOF'
# ============================================================
# Configuration OpenSSH VULNÉRABLE - regreSSHion CVE-2024-6387
# ⚠️ NE JAMAIS UTILISER EN PRODUCTION ⚠️
# ============================================================

# Configuration de base - ÉCOUTE SUR TOUTES LES INTERFACES
Port 22
Protocol 2
ListenAddress 0.0.0.0
AddressFamily any

# Clés hôte
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# Logging
SyslogFacility AUTH
LogLevel INFO

# ============================================================
# PARAMÈTRES VULNÉRABLES À REGRESSHION CVE-2024-6387
# ============================================================

# LoginGraceTime > 0 = VULNÉRABLE à regreSSHion
LoginGraceTime 120

# Authentification ULTRA-PERMISSIVE
PermitRootLogin yes
StrictModes no
MaxAuthTries 100
MaxSessions 50

# Authentification par mot de passe ACTIVÉE
PasswordAuthentication yes
PermitEmptyPasswords yes
PubkeyAuthentication no

# PAM activé mais pas restrictif
UsePAM yes
ChallengeResponseAuthentication no

# Forwarding activé
AllowTcpForwarding yes
X11Forwarding yes
PermitTunnel yes
GatewayPorts yes

# Variables d'environnement
PermitUserEnvironment yes

# Keepalive
ClientAliveInterval 300
ClientAliveCountMax 10

# Connexions multiples (nécessaire pour exploitation)
MaxStartups 100:30:200

# Algorithmes faibles acceptés
Ciphers aes128-cbc,aes192-cbc,aes256-cbc,aes128-ctr,aes192-ctr,aes256-ctr
MACs hmac-sha1,hmac-sha2-256,hmac-sha2-512

# Autoriser tous les utilisateurs
AllowUsers *

# ============================================================
# FIN CONFIGURATION VULNÉRABLE
# ============================================================

# Subsystème SFTP
Subsystem sftp /usr/lib/openssh/sftp-server

# Messages
PrintMotd yes
PrintLastLog yes
Banner none
AcceptEnv LANG LC_*
EOF

echo "✅ Configuration vulnérable appliquée"

# 11. Configuration du service systemd
echo ""
echo "[11/12] 🔄 Configuration du service systemd..."

# Désactiver l'ancien service ssh
systemctl disable ssh 2>/dev/null || true
systemctl disable ssh.service 2>/dev/null || true

# Créer le nouveau service sshd
cat > /etc/systemd/system/sshd.service <<'EOF'
[Unit]
Description=OpenSSH Daemon (Vulnerable Version - CVE-2024-6387)
Documentation=man:sshd(8) man:sshd_config(5)
After=network.target network-online.target
Wants=network-online.target
ConditionPathExists=!/etc/ssh/sshd_not_to_be_run

[Service]
Type=notify
ExecStartPre=/usr/sbin/sshd -t
ExecStart=/usr/sbin/sshd -D
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
Restart=on-failure
RestartSec=5s
RuntimeDirectory=sshd
RuntimeDirectoryMode=0755

[Install]
WantedBy=multi-user.target
Alias=sshd.service
EOF

# Recharger systemd
systemctl daemon-reload
echo "✅ Service systemd configuré"

# 12. Démarrage et vérification du service
echo ""
echo "[12/12] 🚀 Démarrage du service SSH..."

# S'assurer qu'aucun autre service ne tourne
pkill -9 sshd 2>/dev/null || true
sleep 1

# Activer et démarrer le service
systemctl enable sshd.service > /dev/null 2>&1
systemctl start sshd.service

# Attendre que le service démarre
sleep 3

# Vérification finale
echo ""
echo "=========================================="
echo "✅ INSTALLATION TERMINÉE !"
echo "=========================================="
echo ""

# Récupérer l'adresse IP
IP_ADDRESS=$(hostname -I | awk '{print $1}')

echo "📊 INFORMATIONS SYSTÈME:"
echo "----------------------------------------"
echo ""

# Version
echo "🔹 Version OpenSSH:"
/usr/sbin/sshd -V 2>&1 | head -n1
echo ""

# Statut du service
echo "🔹 Statut du service:"
if systemctl is-active --quiet sshd; then
    echo "   ✅ Service ACTIF"
else
    echo "   ❌ Service INACTIF"
    echo "   Tentative de redémarrage..."
    systemctl restart sshd
    sleep 2
    if systemctl is-active --quiet sshd; then
        echo "   ✅ Service redémarré avec succès"
    else
        echo "   ❌ Échec du redémarrage"
    fi
fi
echo ""

# Port en écoute
echo "🔹 Port en écoute:"
if ss -tlnp | grep -q :22; then
    ss -tlnp | grep :22
    echo "   ✅ Port 22 OUVERT"
else
    echo "   ❌ Port 22 NON ouvert"
fi
echo ""

# Adresse IP
echo "🔹 Adresse IP du serveur:"
echo "   $IP_ADDRESS"
echo ""

# Utilisateur de test
echo "🔹 Utilisateur de test créé:"
echo "   Nom: victime"
echo "   Mot de passe: victime123"
echo ""

echo "=========================================="
echo "🔌 CONNEXION DEPUIS UNE AUTRE MACHINE:"
echo "=========================================="
echo ""
echo "Pour vous connecter depuis une autre machine:"
echo ""
echo "  ssh victime@$IP_ADDRESS"
echo ""
echo "Mot de passe: victime123"
echo ""
echo "Ou en tant que root (si mot de passe configuré):"
echo "  ssh root@$IP_ADDRESS"
echo ""

echo "=========================================="
echo "⚠️  VULNÉRABILITÉS PRÉSENTES:"
echo "=========================================="
echo ""
echo "❗ CVE-2024-6387 (regreSSHion) - RCE root"
echo "❗ LoginGraceTime = 120s (fenêtre exploitation)"
echo "❗ Connexion root activée"
echo "❗ Mots de passe vides autorisés"
echo "❗ 100 tentatives d'authentification"
echo "❗ MaxStartups = 100 (exploitation facilitée)"
echo ""

echo "=========================================="
echo "🛠️  COMMANDES UTILES:"
echo "=========================================="
echo ""
echo "  systemctl status sshd    # Vérifier le statut"
echo "  systemctl restart sshd   # Redémarrer SSH"
echo "  journalctl -u sshd -f    # Voir les logs en temps réel"
echo "  ss -tlnp | grep :22      # Vérifier le port 22"
echo "  who                      # Voir les connexions actives"
echo ""

echo "=========================================="
echo "🔒 SÉCURITÉ - RAPPEL IMPORTANT:"
echo "=========================================="
echo ""
echo "✓ Environnement de lab isolé UNIQUEMENT"
echo "✓ Démonstrations pédagogiques"
echo "✓ Formation en cybersécurité"
echo ""
echo "✗ NE JAMAIS exposer à Internet"
echo "✗ NE JAMAIS utiliser en production"
echo ""

echo "=========================================="
echo "✅ Système prêt pour connexion distante!"
echo "=========================================="
echo ""

# Test de connexion locale
echo "🧪 Test de connexion locale..."
timeout 5 ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 victime@localhost exit 2>/dev/null && \
    echo "✅ Test local réussi - SSH fonctionne!" || \
    echo "⚠️  Test local échoué - Vérifiez la configuration"

echo ""
echo "📁 Sauvegarde de votre ancienne config: $BACKUP_DIR"
echo ""
