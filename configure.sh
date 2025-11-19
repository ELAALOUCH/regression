#!/bin/bash
# Script d'installation OpenSSH vulnérable à regreSSHion (CVE-2024-6387)
# ⚠️ UNIQUEMENT POUR ENVIRONNEMENT DE LAB ISOLÉ ⚠️
# Ubuntu 22.04 - Version prête pour présentation
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
echo "[1/10] 💾 Sauvegarde de la configuration actuelle..."
mkdir -p "$BACKUP_DIR"
if [ -f /etc/ssh/sshd_config ]; then
    cp /etc/ssh/sshd_config "$BACKUP_DIR/"
    echo "✅ Configuration sauvegardée dans: $BACKUP_DIR"
fi

# 2. Arrêt du service SSH
echo ""
echo "[2/10] ⏸️  Arrêt du service SSH actuel..."
systemctl stop ssh 2>/dev/null || systemctl stop sshd 2>/dev/null || true
pkill sshd 2>/dev/null || true
echo "✅ Service SSH arrêté"

# 3. Installation des dépendances
echo ""
echo "[3/10] 📦 Installation des dépendances..."
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    build-essential \
    libssl-dev \
    zlib1g-dev \
    libpam0g-dev \
    libselinux1-dev \
    libkrb5-dev \
    wget \
    net-tools > /dev/null 2>&1
echo "✅ Dépendances installées"

# 4. Création de l'utilisateur système sshd
echo ""
echo "[4/10] 👤 Création de l'utilisateur système 'sshd'..."
if ! id -u sshd > /dev/null 2>&1; then
    useradd -r -s /usr/sbin/nologin -d /var/lib/sshd -c "SSH privilege separation" sshd
    echo "✅ Utilisateur sshd créé"
else
    echo "ℹ️  Utilisateur sshd existe déjà"
fi

# 5. Création des répertoires nécessaires
echo ""
echo "[5/10] 📁 Création des répertoires système..."
mkdir -p /var/lib/sshd
mkdir -p /var/empty/sshd
mkdir -p /run/sshd
chmod 755 /var/lib/sshd
chmod 755 /var/empty/sshd
chown root:root /var/lib/sshd
chown root:root /var/empty/sshd
echo "✅ Répertoires créés"

# 6. Téléchargement d'OpenSSH vulnérable
echo ""
echo "[6/10] ⬇️  Téléchargement d'OpenSSH ${OPENSSH_VERSION}..."
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"
if [ ! -f "openssh-${OPENSSH_VERSION}.tar.gz" ]; then
    wget -q --show-progress https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-${OPENSSH_VERSION}.tar.gz
    echo "✅ Téléchargement terminé"
else
    echo "ℹ️  Archive déjà téléchargée"
fi

# 7. Extraction et compilation
echo ""
echo "[7/10] 🔨 Compilation d'OpenSSH (cela peut prendre 2-3 minutes)..."
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

# 8. Génération des clés hôtes
echo ""
echo "[8/10] 🔑 Génération des clés hôtes SSH..."
ssh-keygen -A > /dev/null 2>&1
echo "✅ Clés générées"

# 9. Configuration vulnérable
echo ""
echo "[9/10] ⚙️  Application de la configuration VULNÉRABLE..."
cat > /etc/ssh/sshd_config <<'EOF'
# ============================================================
# Configuration OpenSSH VULNÉRABLE - regreSSHion CVE-2024-6387
# ⚠️ NE JAMAIS UTILISER EN PRODUCTION ⚠️
# Pour démonstration et formation sécurité uniquement
# ============================================================

# Configuration de base
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

# ============================================================
# PARAMÈTRES RENDANT LE SYSTÈME VULNÉRABLE À REGRESSHION
# ============================================================

# LoginGraceTime > 0 est CRITIQUE pour la vulnérabilité CVE-2024-6387
# La valeur par défaut de 120 secondes crée la fenêtre d'exploitation
# Qualys estime ~3-4h d'attaque avec ces paramètres pour gagner la race condition
LoginGraceTime 120

# Authentification ultra-permissive
PermitRootLogin yes
StrictModes no
MaxAuthTries 100
MaxSessions 50

# Désactivation de l'authentification par clé
PubkeyAuthentication no

# Autorisation des mots de passe (même vides)
PasswordAuthentication yes
PermitEmptyPasswords yes

# Pas de vérification PAM stricte
UsePAM yes
ChallengeResponseAuthentication no

# Forwarding et tunneling activés
AllowTcpForwarding yes
X11Forwarding yes
PermitTunnel yes

# Variables d'environnement utilisateur autorisées
PermitUserEnvironment yes

# Keepalive (maintien des sessions)
ClientAliveInterval 300
ClientAliveCountMax 10

# Connexions multiples facilitées
MaxStartups 100:30:200

# Algorithmes de chiffrement incluant les anciens/faibles
Ciphers aes128-cbc,aes192-cbc,aes256-cbc,aes128-ctr,aes192-ctr,aes256-ctr
MACs hmac-sha1,hmac-sha2-256,hmac-sha2-512

# ============================================================
# FIN DE LA CONFIGURATION VULNÉRABLE
# ============================================================

# Subsystème SFTP
Subsystem sftp /usr/lib/openssh/sftp-server

# Messages
PrintMotd yes
PrintLastLog yes
Banner none
EOF

echo "✅ Configuration vulnérable appliquée"

# 10. Configuration du service systemd
echo ""
echo "[10/10] 🔄 Configuration du service systemd..."
cat > /etc/systemd/system/sshd.service <<'EOF'
[Unit]
Description=OpenSSH Daemon (Vulnerable Version - CVE-2024-6387)
Documentation=man:sshd(8) man:sshd_config(5)
After=network.target auditd.service
ConditionPathExists=!/etc/ssh/sshd_not_to_be_run

[Service]
Type=notify
ExecStart=/usr/sbin/sshd -D
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
Restart=on-failure
RestartSec=42s

[Install]
WantedBy=multi-user.target
Alias=sshd.service
EOF

systemctl daemon-reload
systemctl enable sshd.service > /dev/null 2>&1
systemctl start sshd.service
echo "✅ Service configuré et démarré"

# Vérification finale
echo ""
echo "=========================================="
echo "✅ INSTALLATION TERMINÉE AVEC SUCCÈS !"
echo "=========================================="
echo ""
echo "📊 Informations système:"
echo "----------------------------------------"
echo "Version OpenSSH installée:"
/usr/sbin/sshd -V 2>&1 | head -n1
echo ""
echo "Statut du service:"
systemctl is-active sshd && echo "✅ Service ACTIF" || echo "❌ Service INACTIF"
echo ""
echo "Port en écoute:"
ss -tlnp | grep :22 || echo "❌ Aucun port en écoute"
echo ""
echo "Utilisateur sshd:"
id sshd 2>/dev/null && echo "✅ Utilisateur existe" || echo "❌ Utilisateur manquant"
echo ""
echo "=========================================="
echo "⚠️  AVERTISSEMENTS DE SÉCURITÉ"
echo "=========================================="
echo "❗ Ce serveur est VULNÉRABLE à:"
echo "   - CVE-2024-6387 (regreSSHion)"
echo "   - Connexion root activée"
echo "   - Mots de passe vides autorisés"
echo "   - 100 tentatives d'authentification"
echo ""
echo "🔒 Utilisation STRICTEMENT limitée à:"
echo "   ✓ Environnement de lab isolé"
echo "   ✓ Démonstrations de sécurité"
echo "   ✓ Formation et recherche"
echo ""
echo "🚫 NE JAMAIS:"
echo "   ✗ Exposer à Internet"
echo "   ✗ Utiliser en production"
echo "   ✗ Stocker des données sensibles"
echo ""
echo "📁 Sauvegarde de votre config:"
echo "   $BACKUP_DIR"
echo ""
echo "🔧 Commandes utiles:"
echo "   systemctl status sshd    # Vérifier le statut"
echo "   systemctl restart sshd   # Redémarrer"
echo "   journalctl -u sshd -f    # Voir les logs"
echo "   ss -tlnp | grep :22      # Vérifier le port"
echo ""
echo "=========================================="
echo "✅ Système prêt pour votre présentation!"
echo "=========================================="
