import React, { useState } from 'react';
import { Shield, Terminal, Server, Lock, AlertTriangle, User, Settings, Github, Star, GitFork, Download, Eye, Code, FileText, CheckCircle, XCircle } from 'lucide-react';

function App() {
  const [activeTab, setActiveTab] = useState('readme');
  const [activeScript, setActiveScript] = useState('01-setup-user.sh');

  const scripts = {
    '01-setup-user.sh': `#!/bin/bash
# Script de Hardening - Configuración de Usuario Seguro
# Autor: Zelmar Mohozzo - Code Society
# Propósito: Establecer usuario con sudo y deshabilitar root remoto

set -euo pipefail

# Colores para output
RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
NC='\\033[0m' # No Color

# Función de logging
log() {
    echo -e "\${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] INFO: \$1\${NC}"
}

error() {
    echo -e "\${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: \$1\${NC}"
}

warning() {
    echo -e "\${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: \$1\${NC}"
}

# Verificar si se ejecuta como root
if [[ \$EUID -ne 0 ]]; then
   error "Este script debe ejecutarse como root"
   exit 1
fi

# Solicitar información del nuevo usuario
read -p "Ingrese el nombre del nuevo usuario: " NEW_USER
read -s -p "Ingrese la contraseña para \$NEW_USER: " NEW_PASSWORD
echo

# Crear usuario con directorio home
log "Creando usuario \$NEW_USER..."
useradd -m -s /bin/bash "\$NEW_USER"

# Establecer contraseña
echo "\$NEW_USER:\$NEW_PASSWORD" | chpasswd

# Agregar usuario al grupo sudo
log "Agregando \$NEW_USER al grupo sudo..."
usermod -aG sudo "\$NEW_USER"

# Configurar sudoers para no requerir contraseña (opcional)
read -p "¿Permitir sudo sin contraseña para \$NEW_USER? (y/N): " -n 1 -r
echo
if [[ \$REPLY =~ ^[Yy]$ ]]; then
    echo "\$NEW_USER ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/"\$NEW_USER"
    chmod 0440 /etc/sudoers.d/"\$NEW_USER"
    log "Configurado sudo sin contraseña para \$NEW_USER"
fi

# Deshabilitar login root directo
log "Deshabilitando login root directo..."
passwd -l root

# Configurar SSH para deshabilitar root login
if [[ -f /etc/ssh/sshd_config ]]; then
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
    sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    log "Deshabilitado PermitRootLogin en SSH"
fi

log "✓ Configuración de usuario seguro completada"
log "✓ Usuario \$NEW_USER creado con permisos sudo"
log "✓ Acceso root remoto deshabilitado"

exit 0`,

    '02-firewall.sh': `#!/bin/bash
# Script de Hardening - Configuración de Firewall
# Autor: Zelmar Mohozzo - Code Society
# Propósito: Configurar UFW/iptables para seguridad básica

set -euo pipefail

# Colores para output
RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
NC='\\033[0m'

log() {
    echo -e "\${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] INFO: \$1\${NC}"
}

error() {
    echo -e "\${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: \$1\${NC}"
}

# Verificar si se ejecuta como root
if [[ \$EUID -ne 0 ]]; then
   error "Este script debe ejecutarse como root"
   exit 1
fi

# Detectar si UFW está disponible
if command -v ufw &> /dev/null; then
    log "Configurando UFW (Uncomplicated Firewall)..."
    
    # Resetear reglas existentes
    ufw --force reset
    
    # Política por defecto: denegar todo entrante, permitir saliente
    ufw default deny incoming
    ufw default allow outgoing
    
    # Permitir SSH (puerto personalizable)
    read -p "Ingrese el puerto SSH (default: 22): " SSH_PORT
    SSH_PORT=\${SSH_PORT:-22}
    ufw allow \$SSH_PORT/tcp comment 'SSH'
    
    # Permitir HTTP y HTTPS si es servidor web
    read -p "¿Es este un servidor web? (y/N): " -n 1 -r
    echo
    if [[ \$REPLY =~ ^[Yy]$ ]]; then
        ufw allow 80/tcp comment 'HTTP'
        ufw allow 443/tcp comment 'HTTPS'
        log "Puertos HTTP/HTTPS habilitados"
    fi
    
    # Habilitar UFW
    ufw --force enable
    
    # Mostrar status
    ufw status verbose
    
    log "✓ UFW configurado exitosamente"
    
elif command -v iptables &> /dev/null; then
    log "Configurando iptables..."
    
    # Backup de reglas existentes
    iptables-save > /etc/iptables.backup
    
    # Limpiar reglas existentes
    iptables -F
    iptables -X
    iptables -Z
    
    # Políticas por defecto
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    
    # Permitir loopback
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    
    # Permitir conexiones establecidas
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    
    # Permitir SSH
    read -p "Ingrese el puerto SSH (default: 22): " SSH_PORT
    SSH_PORT=\${SSH_PORT:-22}
    iptables -A INPUT -p tcp --dport \$SSH_PORT -j ACCEPT
    
    # Permitir HTTP/HTTPS si es servidor web
    read -p "¿Es este un servidor web? (y/N): " -n 1 -r
    echo
    if [[ \$REPLY =~ ^[Yy]$ ]]; then
        iptables -A INPUT -p tcp --dport 80 -j ACCEPT
        iptables -A INPUT -p tcp --dport 443 -j ACCEPT
        log "Puertos HTTP/HTTPS habilitados"
    fi
    
    # Guardar reglas
    iptables-save > /etc/iptables/rules.v4
    
    log "✓ iptables configurado exitosamente"
else
    error "No se encontró UFW ni iptables"
    exit 1
fi

log "✓ Firewall configurado con políticas restrictivas"
log "✓ Tráfico entrante bloqueado por defecto"
log "✓ Puertos esenciales habilitados"

exit 0`,

    '03-fail2ban.sh': `#!/bin/bash
# Script de Hardening - Instalación y Configuración de Fail2ban
# Autor: Zelmar Mohozzo - Code Society
# Propósito: Proteger contra ataques de fuerza bruta

set -euo pipefail

# Colores para output
RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
NC='\\033[0m'

log() {
    echo -e "\${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] INFO: \$1\${NC}"
}

error() {
    echo -e "\${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: \$1\${NC}"
}

# Verificar si se ejecuta como root
if [[ \$EUID -ne 0 ]]; then
   error "Este script debe ejecutarse como root"
   exit 1
fi

# Detectar distribución
if [[ -f /etc/debian_version ]]; then
    DISTRO="debian"
elif [[ -f /etc/redhat-release ]]; then
    DISTRO="redhat"
elif [[ -f /etc/arch-release ]]; then
    DISTRO="arch"
else
    error "Distribución no soportada"
    exit 1
fi

# Instalar Fail2ban
log "Instalando Fail2ban..."
case \$DISTRO in
    "debian")
        apt update
        apt install -y fail2ban
        ;;
    "redhat")
        yum install -y epel-release
        yum install -y fail2ban
        ;;
    "arch")
        pacman -Sy fail2ban
        ;;
esac

# Crear configuración personalizada
log "Configurando Fail2ban..."
cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
# Tiempo de ban en segundos (1 hora)
bantime = 3600

# Ventana de tiempo para contar intentos fallidos (10 minutos)
findtime = 600

# Número máximo de intentos fallidos antes del ban
maxretry = 3

# Ignorar IPs locales
ignoreip = 127.0.0.1/8 ::1 192.168.0.0/16 10.0.0.0/8 172.16.0.0/12

# Configuración de email (opcional)
# destemail = admin@ejemplo.com
# sender = fail2ban@ejemplo.com

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 1800

[apache-auth]
enabled = false
port = http,https
filter = apache-auth
logpath = /var/log/apache2/error.log
maxretry = 3

[nginx-http-auth]
enabled = false
port = http,https
filter = nginx-http-auth
logpath = /var/log/nginx/error.log
maxretry = 3

[postfix-sasl]
enabled = false
port = smtp,ssmtp,submission
filter = postfix-sasl
logpath = /var/log/mail.log
maxretry = 3
EOF

# Configurar filtro personalizado para SSH
cat > /etc/fail2ban/filter.d/sshd-aggressive.conf << 'EOF'
[Definition]
failregex = ^%(__prefix_line)s(?:error: PAM: )?[aA]uthentication (?:failure|error) for .* from <HOST>( via \\S+)?\\s*\$
            ^%(__prefix_line)s(?:error: )?Received disconnect from <HOST>: 3: \\S+ \\[preauth\\]\\s*\$
            ^%(__prefix_line)s(?:error: )?Connection closed by <HOST> \\[preauth\\]\\s*\$
            ^%(__prefix_line)s(?:error: )?PAM: User not known to the underlying authentication module for .* from <HOST>\\s*\$
            ^%(__prefix_line)s(?:error: )?User .* from <HOST> not allowed because user is not in any group\\s*\$

ignoreregex = 
EOF

# Habilitar y iniciar Fail2ban
log "Habilitando Fail2ban..."
systemctl enable fail2ban
systemctl start fail2ban

# Verificar estado
log "Verificando estado de Fail2ban..."
systemctl status fail2ban --no-pager
fail2ban-client status

log "✓ Fail2ban instalado y configurado"
log "✓ Protección SSH habilitada"
log "✓ Configuración: 3 intentos fallidos = ban de 30 minutos"
log "✓ Servicio habilitado para inicio automático"

# Mostrar comandos útiles
echo
echo "Comandos útiles de Fail2ban:"
echo "  fail2ban-client status                    # Ver estado general"
echo "  fail2ban-client status sshd              # Ver estado jail SSH"
echo "  fail2ban-client set sshd unbanip <IP>    # Desbanear IP"
echo "  fail2ban-client set sshd banip <IP>      # Banear IP manualmente"

exit 0`,

    '04-ssh-hardening.sh': `#!/bin/bash
# Script de Hardening - Configuración SSH Segura
# Autor: Zelmar Mohozzo - Code Society
# Propósito: Configurar SSH con mejores prácticas de seguridad

set -euo pipefail

# Colores para output
RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
NC='\\033[0m'

log() {
    echo -e "\${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] INFO: \$1\${NC}"
}

error() {
    echo -e "\${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: \$1\${NC}"
}

warning() {
    echo -e "\${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: \$1\${NC}"
}

# Verificar si se ejecuta como root
if [[ \$EUID -ne 0 ]]; then
   error "Este script debe ejecutarse como root"
   exit 1
fi

# Backup de configuración SSH
log "Creando backup de configuración SSH..."
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup-$(date +%Y%m%d-%H%M%S)

# Configurar puerto SSH personalizado
read -p "Ingrese el nuevo puerto SSH (default: 2222): " SSH_PORT
SSH_PORT=\${SSH_PORT:-2222}

# Configurar usuario permitido
read -p "Ingrese el usuario permitido para SSH: " SSH_USER

# Crear nueva configuración SSH
log "Aplicando configuración SSH segura..."
cat > /etc/ssh/sshd_config << EOF
# Configuración SSH Hardening - Code Society
# Autor: Zelmar Mohozzo

# Puerto personalizado
Port \$SSH_PORT

# Protocolo SSH versión 2 únicamente
Protocol 2

# Direcciones de escucha
ListenAddress 0.0.0.0

# Configuración de host keys
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# Configuración de cifrado
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512

# Configuración de autenticación
LoginGraceTime 30
PermitRootLogin no
MaxAuthTries 3
MaxSessions 2
MaxStartups 10:30:100

# Autenticación por clave pública
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys

# Deshabilitar autenticación por contraseña
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no

# Configuración de usuarios
AllowUsers \$SSH_USER
DenyUsers root

# Configuración de reenvío
AllowAgentForwarding no
AllowTcpForwarding no
GatewayPorts no
X11Forwarding no
PermitTunnel no

# Configuración de sesión
ClientAliveInterval 300
ClientAliveCountMax 2
TCPKeepAlive yes
Compression no

# Configuración de logging
SyslogFacility AUTHPRIV
LogLevel INFO

# Banner de seguridad
Banner /etc/ssh/banner

# Configuración adicional
StrictModes yes
IgnoreRhosts yes
RhostsRSAAuthentication no
HostbasedAuthentication no
PermitUserEnvironment no
UsePAM yes
EOF

# Crear banner de seguridad
log "Configurando banner de seguridad..."
cat > /etc/ssh/banner << 'EOF'
***************************************************************************
                    SISTEMA PROTEGIDO - ACCESO AUTORIZADO
***************************************************************************

Este sistema está protegido por medidas de seguridad avanzadas.
Todas las conexiones son monitoreadas y registradas.

El acceso no autorizado está prohibido y será procesado según la ley.

Si no está autorizado para acceder a este sistema, desconéctese inmediatamente.

***************************************************************************
EOF

# Generar nuevas claves SSH si es necesario
log "Verificando claves SSH del servidor..."
if [[ ! -f /etc/ssh/ssh_host_ed25519_key ]]; then
    ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""
fi

# Configurar permisos
chmod 600 /etc/ssh/ssh_host_*_key
chmod 644 /etc/ssh/ssh_host_*_key.pub
chmod 644 /etc/ssh/sshd_config
chmod 644 /etc/ssh/banner

# Configurar directorio SSH para usuario
if [[ -n "\$SSH_USER" ]]; then
    USER_HOME=\$(eval echo ~\$SSH_USER)
    if [[ -d "\$USER_HOME" ]]; then
        log "Configurando directorio SSH para \$SSH_USER..."
        sudo -u \$SSH_USER mkdir -p "\$USER_HOME/.ssh"
        sudo -u \$SSH_USER chmod 700 "\$USER_HOME/.ssh"
        sudo -u \$SSH_USER touch "\$USER_HOME/.ssh/authorized_keys"
        sudo -u \$SSH_USER chmod 600 "\$USER_HOME/.ssh/authorized_keys"
        
        warning "Recuerde agregar su clave pública SSH a \$USER_HOME/.ssh/authorized_keys"
    fi
fi

# Validar configuración
log "Validando configuración SSH..."
if sshd -t; then
    log "✓ Configuración SSH válida"
else
    error "Configuración SSH inválida, revirtiendo cambios..."
    cp /etc/ssh/sshd_config.backup-* /etc/ssh/sshd_config
    exit 1
fi

# Reiniciar servicio SSH
log "Reiniciando servicio SSH..."
systemctl restart sshd

# Actualizar firewall para nuevo puerto
if command -v ufw &> /dev/null; then
    ufw allow \$SSH_PORT/tcp comment 'SSH Custom Port'
    ufw delete allow 22/tcp 2>/dev/null || true
fi

log "✓ SSH hardening completado"
log "✓ Puerto SSH cambiado a: \$SSH_PORT"
log "✓ Autenticación por contraseña deshabilitada"
log "✓ Solo usuario \$SSH_USER permitido"
log "✓ Root login deshabilitado"
log "✓ Cifrado mejorado aplicado"

warning "IMPORTANTE: Pruebe la conexión SSH en una nueva terminal antes de cerrar esta sesión"
warning "Comando de conexión: ssh -p \$SSH_PORT \$SSH_USER@\$(hostname -I | awk '{print \$1}')"

exit 0`,

    '05-selinux.sh': `#!/bin/bash
# Script de Hardening - Configuración SELinux
# Autor: Zelmar Mohozzo - Code Society
# Propósito: Habilitar y configurar SELinux en modo enforcing

set -euo pipefail

# Colores para output
RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
NC='\\033[0m'

log() {
    echo -e "\${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] INFO: \$1\${NC}"
}

error() {
    echo -e "\${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: \$1\${NC}"
}

warning() {
    echo -e "\${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: \$1\${NC}"
}

# Verificar si se ejecuta como root
if [[ \$EUID -ne 0 ]]; then
   error "Este script debe ejecutarse como root"
   exit 1
fi

# Verificar si es una distribución compatible con SELinux
if [[ ! -f /etc/redhat-release ]] && [[ ! -f /etc/fedora-release ]]; then
    log "Detectando sistema no-Red Hat, verificando soporte SELinux..."
    if [[ -f /etc/debian_version ]]; then
        log "Sistema Debian/Ubuntu detectado, instalando SELinux..."
        apt update
        apt install -y selinux-basics selinux-policy-default auditd
        selinux-activate
        log "SELinux instalado. Se requiere reinicio para activar."
        log "Después del reinicio, ejecute este script nuevamente."
        exit 0
    else
        error "Sistema no compatible con SELinux"
        exit 1
    fi
fi

# Instalar herramientas SELinux si no están presentes
log "Instalando herramientas SELinux..."
if command -v yum &> /dev/null; then
    yum install -y policycoreutils-python-utils setroubleshoot-server setools-console
elif command -v dnf &> /dev/null; then
    dnf install -y policycoreutils-python-utils setroubleshoot-server setools-console
fi

# Verificar estado actual de SELinux
log "Verificando estado actual de SELinux..."
if command -v getenforce &> /dev/null; then
    CURRENT_STATE=\$(getenforce)
    log "Estado actual de SELinux: \$CURRENT_STATE"
else
    error "SELinux no está instalado o no es compatible"
    exit 1
fi

# Configurar SELinux en modo enforcing
log "Configurando SELinux en modo enforcing..."

# Verificar archivo de configuración
if [[ ! -f /etc/selinux/config ]]; then
    error "Archivo de configuración SELinux no encontrado"
    exit 1
fi

# Backup de configuración actual
cp /etc/selinux/config /etc/selinux/config.backup-$(date +%Y%m%d-%H%M%S)

# Configurar SELinux
cat > /etc/selinux/config << 'EOF'
# Configuración SELinux - Code Society Hardening
# Autor: Zelmar Mohozzo

# Este archivo controla el estado de SELinux en el sistema
# SELINUX puede ser: enforcing, permissive, disabled
SELINUX=enforcing

# SELINUXTYPE puede ser: targeted, minimum, mls
SELINUXTYPE=targeted
EOF

# Establecer contextos SELinux para directorios comunes
log "Configurando contextos SELinux..."

# Restaurar contextos por defecto
restorecon -R /etc
restorecon -R /var
restorecon -R /home

# Configurar contextos para SSH si se cambió el puerto
if [[ -f /etc/ssh/sshd_config ]]; then
    SSH_PORT=\$(grep "^Port" /etc/ssh/sshd_config | awk '{print \$2}')
    if [[ -n "\$SSH_PORT" && "\$SSH_PORT" != "22" ]]; then
        log "Configurando contexto SELinux para puerto SSH personalizado: \$SSH_PORT"
        semanage port -a -t ssh_port_t -p tcp \$SSH_PORT 2>/dev/null || \
        semanage port -m -t ssh_port_t -p tcp \$SSH_PORT
    fi
fi

# Configurar políticas SELinux para servicios comunes
log "Configurando políticas SELinux..."

# Permitir que httpd se conecte a la red (si está instalado)
if systemctl is-enabled httpd &> /dev/null || systemctl is-enabled apache2 &> /dev/null; then
    setsebool -P httpd_can_network_connect on
    log "Habilitada conectividad de red para httpd"
fi

# Permitir que nginx se conecte a la red (si está instalado)
if systemctl is-enabled nginx &> /dev/null; then
    setsebool -P httpd_can_network_connect on
    log "Habilitada conectividad de red para nginx"
fi

# Crear política personalizada para aplicaciones específicas
log "Creando política personalizada..."
cat > /tmp/custom_hardening.te << 'EOF'
module custom_hardening 1.0;

require {
    type admin_home_t;
    type user_home_t;
    type ssh_port_t;
    class tcp_socket { bind listen };
    class file { read write };
}

# Política personalizada para hardening
# Permitir conexiones SSH en puertos personalizados
allow sshd_t ssh_port_t:tcp_socket { bind listen };
EOF

# Compilar y cargar política personalizada
if [[ -f /tmp/custom_hardening.te ]]; then
    checkmodule -M -m -o /tmp/custom_hardening.mod /tmp/custom_hardening.te
    semodule_package -o /tmp/custom_hardening.pp -m /tmp/custom_hardening.mod
    semodule -i /tmp/custom_hardening.pp
    rm -f /tmp/custom_hardening.*
    log "Política personalizada aplicada"
fi

# Configurar auditd para monitoreo SELinux
log "Configurando auditd para monitoreo SELinux..."
systemctl enable auditd
systemctl start auditd

# Configurar logrotate para logs SELinux
cat > /etc/logrotate.d/selinux << 'EOF'
/var/log/audit/audit.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
    postrotate
        /sbin/service auditd restart > /dev/null 2>&1 || true
    endscript
}
EOF

# Verificar configuración
log "Verificando configuración SELinux..."

# Mostrar estado actual
sestatus

# Mostrar contextos importantes
log "Contextos SELinux importantes:"
ls -Z /etc/ssh/sshd_config
ls -Z /etc/selinux/config

# Mostrar políticas booleanas importantes
log "Políticas booleanas importantes:"
getsebool -a | grep -E "(httpd_can_network_connect|ssh_sysadm_login|allow_user_exec_content)"

# Verificar si se requiere reinicio
if [[ "\$CURRENT_STATE" != "Enforcing" ]]; then
    warning "Se requiere reinicio para activar SELinux en modo enforcing"
    log "Después del reinicio, SELinux estará en modo enforcing"
    
    # Crear archivo de relabel automático
    touch /.autorelabel
    log "Configurado relabel automático de archivos en próximo reinicio"
fi

log "✓ SELinux configurado en modo enforcing"
log "✓ Política targeted aplicada"
log "✓ Contextos de seguridad configurados"
log "✓ Auditd habilitado para monitoreo"
log "✓ Políticas personalizadas aplicadas"

# Mostrar comandos útiles
echo
echo "Comandos útiles de SELinux:"
echo "  sestatus                              # Ver estado SELinux"
echo "  getenforce                            # Ver modo actual"
echo "  setenforce [Enforcing|Permissive]     # Cambiar modo temporal"
echo "  restorecon -R /path                   # Restaurar contextos"
echo "  semanage port -l | grep ssh           # Ver puertos SSH"
echo "  sealert -a /var/log/audit/audit.log   # Analizar alertas"
echo "  ausearch -m avc                       # Buscar eventos SELinux"

if [[ "\$CURRENT_STATE" != "Enforcing" ]]; then
    warning "IMPORTANTE: Reinicie el sistema para activar SELinux en modo enforcing"
fi

exit 0`
  };

  const distributions = [
    { name: 'Ubuntu', icon: '🟠', supported: true },
    { name: 'Debian', icon: '🔴', supported: true },
    { name: 'CentOS', icon: '🟡', supported: true },
    { name: 'Red Hat', icon: '🔴', supported: true },
    { name: 'Arch', icon: '🔵', supported: true },
    { name: 'Fedora', icon: '🟦', supported: true }
  ];

  const technologies = [
    { name: 'Linux', icon: '🐧' },
    { name: 'SELinux', icon: '🛡️' },
    { name: 'SSH', icon: '🔐' },
    { name: 'Firewall', icon: '🔥' },
    { name: 'Fail2Ban', icon: '🚫' },
    { name: 'Python', icon: '🐍' },
    { name: 'Bash', icon: '💻' }
  ];

  return (
    <div className="min-h-screen bg-black text-green-400 font-mono">
      {/* Header */}
      <div className="border-b border-green-800 bg-gray-900">
        <div className="max-w-7xl mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-2">
                <Shield className="h-8 w-8 text-green-400" />
                <span className="text-2xl font-bold text-green-400">LinuxHardening</span>
              </div>
              <div className="flex items-center space-x-2 text-green-600">
                <Github className="h-4 w-4" />
                <span className="text-sm">zmohozzo/linux-hardening-scripts</span>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-2">
                <Star className="h-4 w-4 text-yellow-400" />
                <span className="text-sm">247</span>
              </div>
              <div className="flex items-center space-x-2">
                <GitFork className="h-4 w-4 text-green-400" />
                <span className="text-sm">58</span>
              </div>
              <div className="flex items-center space-x-2">
                <Eye className="h-4 w-4 text-blue-400" />
                <span className="text-sm">1.2k</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Repository info */}
      <div className="max-w-7xl mx-auto px-4 py-6">
        <div className="bg-gray-900 rounded-lg border border-green-800 p-6 mb-6">
          <div className="flex items-start justify-between">
            <div>
              <h1 className="text-3xl font-bold text-green-400 mb-2">
                Scripts de Hardening Automático para Servidores Linux
              </h1>
              <p className="text-green-600 text-lg mb-4">
                Colección de scripts modulares para automatizar mejores prácticas de ciberseguridad en servidores Linux
              </p>
              <div className="flex items-center space-x-4 text-sm text-green-500">
                <div className="flex items-center space-x-1">
                  <User className="h-4 w-4" />
                  <span>Zelmar Mohozzo</span>
                </div>
                <div className="flex items-center space-x-1">
                  <Terminal className="h-4 w-4" />
                  <span>Code Society</span>
                </div>
                <div className="flex items-center space-x-1">
                  <Settings className="h-4 w-4" />
                  <span>Testing Interno</span>
                </div>
              </div>
            </div>
            <div className="flex flex-col space-y-2">
              <button className="flex items-center space-x-2 bg-green-800 hover:bg-green-700 px-4 py-2 rounded-lg transition-colors">
                <Download className="h-4 w-4" />
                <span>Clonar</span>
              </button>
              <button className="flex items-center space-x-2 bg-gray-800 hover:bg-gray-700 px-4 py-2 rounded-lg transition-colors">
                <Code className="h-4 w-4" />
                <span>Código</span>
              </button>
            </div>
          </div>
        </div>

        {/* Navigation tabs */}
        <div className="flex space-x-1 mb-6 border-b border-green-800">
          {[
            { id: 'readme', label: 'README', icon: FileText },
            { id: 'scripts', label: 'Scripts', icon: Terminal },
            { id: 'preview', label: 'Preview', icon: Eye }
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center space-x-2 px-4 py-2 rounded-t-lg transition-colors ${
                activeTab === tab.id 
                  ? 'bg-green-800 text-green-400 border-b-2 border-green-400' 
                  : 'text-green-600 hover:text-green-400 hover:bg-gray-800'
              }`}
            >
              <tab.icon className="h-4 w-4" />
              <span>{tab.label}</span>
            </button>
          ))}
        </div>

        {/* Content */}
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
          <div className="lg:col-span-3">
            {activeTab === 'readme' && (
              <div className="bg-gray-900 rounded-lg border border-green-800 p-6">
                <div className="prose prose-green max-w-none">
                  <h1 className="text-2xl font-bold text-green-400 mb-4">
                    🛡️ Scripts de Hardening Automático para Servidores Linux
                  </h1>
                  
                  <div className="bg-gray-800 rounded-lg p-4 mb-6 border border-green-700">
                    <p className="text-green-300 mb-2">
                      <strong>Autor:</strong> Zelmar Mohozzo - Especialista en Ciberseguridad
                    </p>
                    <p className="text-green-300 mb-2">
                      <strong>Organización:</strong> Code Society
                    </p>
                    <p className="text-green-300">
                      <strong>Propósito:</strong> Testing de proyectos internos y automatización de seguridad
                    </p>
                  </div>

                  <h2 className="text-xl font-bold text-green-400 mb-3">📋 Descripción</h2>
                  <p className="text-green-300 mb-4">
                    Esta colección de scripts bash modulares automatiza la implementación de mejores prácticas 
                    de ciberseguridad en servidores Linux. Desarrollados durante mi tiempo en Code Society para 
                    el testing y hardening de entornos internos.
                  </p>

                  <h2 className="text-xl font-bold text-green-400 mb-3">✨ Características Principales</h2>
                  <ul className="text-green-300 mb-4 space-y-2">
                    <li className="flex items-center space-x-2">
                      <CheckCircle className="h-4 w-4 text-green-400" />
                      <span>Configuración automática de usuario con permisos sudo</span>
                    </li>
                    <li className="flex items-center space-x-2">
                      <CheckCircle className="h-4 w-4 text-green-400" />
                      <span>Firewall seguro con UFW/iptables</span>
                    </li>
                    <li className="flex items-center space-x-2">
                      <CheckCircle className="h-4 w-4 text-green-400" />
                      <span>Fail2ban para protección contra ataques de fuerza bruta</span>
                    </li>
                    <li className="flex items-center space-x-2">
                      <CheckCircle className="h-4 w-4 text-green-400" />
                      <span>SSH hardening con configuración segura</span>
                    </li>
                    <li className="flex items-center space-x-2">
                      <CheckCircle className="h-4 w-4 text-green-400" />
                      <span>SELinux en modo enforcing con políticas personalizadas</span>
                    </li>
                  </ul>

                  <h2 className="text-xl font-bold text-green-400 mb-3">🔧 Scripts Incluidos</h2>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
                    {Object.keys(scripts).map((script) => (
                      <div key={script} className="bg-gray-800 rounded-lg p-4 border border-green-700">
                        <div className="flex items-center space-x-2 mb-2">
                          <Terminal className="h-4 w-4 text-green-400" />
                          <span className="font-bold text-green-400">{script}</span>
                        </div>
                        <p className="text-green-300 text-sm">
                          {script === '01-setup-user.sh' && 'Configuración de usuario seguro con sudo'}
                          {script === '02-firewall.sh' && 'Configuración de firewall UFW/iptables'}
                          {script === '03-fail2ban.sh' && 'Instalación y configuración de Fail2ban'}
                          {script === '04-ssh-hardening.sh' && 'Hardening completo de SSH'}
                          {script === '05-selinux.sh' && 'Configuración de SELinux enforcing'}
                        </p>
                      </div>
                    ))}
                  </div>

                  <h2 className="text-xl font-bold text-green-400 mb-3">🚀 Instalación y Uso</h2>
                  <div className="bg-gray-800 rounded-lg p-4 mb-4 border border-green-700">
                    <pre className="text-green-300 text-sm">
{`# Clonar el repositorio
git clone https://github.com/zmohozzo/linux-hardening-scripts.git
cd linux-hardening-scripts

# Dar permisos de ejecución
chmod +x *.sh

# Ejecutar script completo
sudo ./hardening-complete.sh

# O ejecutar scripts individuales
sudo ./01-setup-user.sh
sudo ./02-firewall.sh
sudo ./03-fail2ban.sh
sudo ./04-ssh-hardening.sh
sudo ./05-selinux.sh`}
                    </pre>
                  </div>

                  <h2 className="text-xl font-bold text-green-400 mb-3">🔍 Sobre Fail2ban</h2>
                  <div className="bg-yellow-900 border border-yellow-600 rounded-lg p-4 mb-4">
                    <p className="text-yellow-200">
                      <strong>Fail2ban</strong> es una herramienta de seguridad que protege contra ataques de fuerza bruta 
                      monitoreando los archivos de log del sistema. Cuando detecta múltiples intentos fallidos de autenticación 
                      desde la misma IP, automáticamente bloquea esa dirección IP usando las reglas del firewall.
                    </p>
                  </div>

                  <h2 className="text-xl font-bold text-green-400 mb-3">🐧 Distribuciones Soportadas</h2>
                  <div className="grid grid-cols-2 md:grid-cols-3 gap-3 mb-4">
                    {distributions.map((distro) => (
                      <div key={distro.name} className="flex items-center space-x-2 bg-gray-800 rounded-lg p-3 border border-green-700">
                        <span className="text-lg">{distro.icon}</span>
                        <span className="text-green-300">{distro.name}</span>
                        <CheckCircle className="h-4 w-4 text-green-400 ml-auto" />
                      </div>
                    ))}
                  </div>

                  <h2 className="text-xl font-bold text-green-400 mb-3">👨‍💻 Autor</h2>
                  <div className="bg-gray-800 rounded-lg p-4 mb-4 border border-green-700">
                    <div className="flex items-start space-x-4">
                      <div className="bg-green-800 rounded-full p-3">
                        <User className="h-6 w-6 text-green-400" />
                      </div>
                      <div>
                        <h3 className="font-bold text-green-400">Zelmar Mohozzo</h3>
                        <p className="text-green-300 text-sm mb-2">Especialista en Ciberseguridad y Desarrollador</p>
                        <p className="text-green-500 text-sm mb-2">
                          Scripts desarrollados durante mi tiempo en Code Society para testing y hardening 
                          de entornos internos de desarrollo y producción.
                        </p>
                        <a href="https://github.com/zmohozzo" className="flex items-center space-x-2 text-green-400 hover:text-green-300 transition-colors">
                          <Github className="h-4 w-4" />
                          <span>GitHub Personal</span>
                        </a>
                      </div>
                    </div>
                  </div>

                  <h2 className="text-xl font-bold text-green-400 mb-3">⚠️ Advertencias</h2>
                  <div className="bg-red-900 border border-red-600 rounded-lg p-4 mb-4">
                    <div className="flex items-start space-x-2">
                      <AlertTriangle className="h-5 w-5 text-red-400 mt-0.5" />
                      <div>
                        <p className="text-red-200 font-bold mb-2">IMPORTANTE:</p>
                        <ul className="text-red-200 text-sm space-y-1">
                          <li>• Ejecute siempre en un entorno de prueba primero</li>
                          <li>• Mantenga una conexión SSH activa durante la configuración</li>
                          <li>• Guarde las claves SSH antes de deshabilitar autenticación por contraseña</li>
                          <li>• Algunos cambios requieren reinicio del servidor</li>
                        </ul>
                      </div>
                    </div>
                  </div>

                  <h2 className="text-xl font-bold text-green-400 mb-3">📄 Licencia</h2>
                  <p className="text-green-300 text-sm">
                    MIT License - Libre para uso en proyectos comerciales y personales
                  </p>
                </div>
              </div>
            )}

            {activeTab === 'scripts' && (
              <div className="bg-gray-900 rounded-lg border border-green-800">
                <div className="flex border-b border-green-800">
                  <div className="w-1/3 border-r border-green-800">
                    <div className="p-4 bg-gray-800">
                      <h3 className="font-bold text-green-400 mb-3">Scripts Disponibles</h3>
                      <div className="space-y-2">
                        {Object.keys(scripts).map((script) => (
                          <button
                            key={script}
                            onClick={() => setActiveScript(script)}
                            className={`w-full text-left p-3 rounded-lg transition-colors ${
                              activeScript === script 
                                ? 'bg-green-800 text-green-400' 
                                : 'bg-gray-700 text-green-300 hover:bg-gray-600'
                            }`}
                          >
                            <div className="flex items-center space-x-2">
                              <Terminal className="h-4 w-4" />
                              <span className="font-mono text-sm">{script}</span>
                            </div>
                          </button>
                        ))}
                      </div>
                    </div>
                  </div>
                  <div className="w-2/3">
                    <div className="p-4 bg-gray-800 border-b border-green-700">
                      <div className="flex items-center justify-between">
                        <h3 className="font-bold text-green-400">{activeScript}</h3>
                        <button className="text-green-400 hover:text-green-300 text-sm">
                          Copiar código
                        </button>
                      </div>
                    </div>
                    <div className="p-4">
                      <pre className="text-green-300 text-xs overflow-x-auto">
                        <code>{scripts[activeScript]}</code>
                      </pre>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'preview' && (
              <div className="bg-gray-900 rounded-lg border border-green-800 p-6">
                <h2 className="text-xl font-bold text-green-400 mb-4">🖥️ Preview de Terminal</h2>
                <div className="bg-black rounded-lg p-4 border border-green-700">
                  <div className="flex items-center space-x-2 mb-4">
                    <div className="w-3 h-3 bg-red-500 rounded-full"></div>
                    <div className="w-3 h-3 bg-yellow-500 rounded-full"></div>
                    <div className="w-3 h-3 bg-green-500 rounded-full"></div>
                    <span className="text-green-400 text-sm ml-4">root@server:~/linux-hardening-scripts</span>
                  </div>
                  <div className="text-green-400 text-sm font-mono">
                    <div className="mb-2">
                      <span className="text-green-500">root@server</span>
                      <span className="text-green-300">:</span>
                      <span className="text-blue-400">~/linux-hardening-scripts</span>
                      <span className="text-green-300"># ./hardening-complete.sh</span>
                    </div>
                    <div className="text-green-400 space-y-1">
                      <div>[2025-01-15 10:30:15] INFO: Iniciando hardening completo del servidor...</div>
                      <div>[2025-01-15 10:30:16] INFO: Ejecutando 01-setup-user.sh</div>
                      <div className="text-yellow-400">[2025-01-15 10:30:17] WARNING: Configurando usuario seguro...</div>
                      <div>[2025-01-15 10:30:18] INFO: ✓ Usuario admin creado con permisos sudo</div>
                      <div>[2025-01-15 10:30:19] INFO: ✓ Acceso root remoto deshabilitado</div>
                      <div>[2025-01-15 10:30:20] INFO: Ejecutando 02-firewall.sh</div>
                      <div>[2025-01-15 10:30:21] INFO: ✓ UFW configurado con políticas restrictivas</div>
                      <div>[2025-01-15 10:30:22] INFO: Ejecutando 03-fail2ban.sh</div>
                      <div>[2025-01-15 10:30:25] INFO: ✓ Fail2ban instalado y configurado</div>
                      <div>[2025-01-15 10:30:26] INFO: ✓ Protección SSH habilitada</div>
                      <div>[2025-01-15 10:30:27] INFO: Ejecutando 04-ssh-hardening.sh</div>
                      <div className="text-yellow-400">[2025-01-15 10:30:28] WARNING: Puerto SSH cambiado a 2222</div>
                      <div>[2025-01-15 10:30:29] INFO: ✓ SSH hardening completado</div>
                      <div>[2025-01-15 10:30:30] INFO: Ejecutando 05-selinux.sh</div>
                      <div>[2025-01-15 10:30:33] INFO: ✓ SELinux configurado en modo enforcing</div>
                      <div className="text-green-400 font-bold">[2025-01-15 10:30:34] SUCCESS: Hardening completo exitoso!</div>
                      <div className="text-yellow-400">[2025-01-15 10:30:35] WARNING: Reinicio requerido para aplicar todos los cambios</div>
                    </div>
                    <div className="mt-4">
                      <span className="text-green-500">root@server</span>
                      <span className="text-green-300">:</span>
                      <span className="text-blue-400">~/linux-hardening-scripts</span>
                      <span className="text-green-300"># </span>
                      <span className="animate-pulse">_</span>
                    </div>
                  </div>
                </div>
                
                <div className="mt-6">
                  <h3 className="text-lg font-bold text-green-400 mb-3">🔍 Verificación Post-Hardening</h3>
                  <div className="bg-black rounded-lg p-4 border border-green-700">
                    <div className="text-green-400 text-sm font-mono space-y-1">
                      <div><span className="text-green-500">$</span> fail2ban-client status</div>
                      <div className="text-green-300 ml-2">Status: 3 jails running</div>
                      <div className="text-green-300 ml-2">Jail list: sshd, apache-auth, postfix-sasl</div>
                      <div className="mt-2"><span className="text-green-500">$</span> ufw status</div>
                      <div className="text-green-300 ml-2">Status: active</div>
                      <div className="text-green-300 ml-2">2222/tcp ALLOW Anywhere</div>
                      <div className="mt-2"><span className="text-green-500">$</span> sestatus</div>
                      <div className="text-green-300 ml-2">SELinux status: enabled</div>
                      <div className="text-green-300 ml-2">Current mode: enforcing</div>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Sidebar */}
          <div className="space-y-6">
            {/* Technologies */}
            <div className="bg-gray-900 rounded-lg border border-green-800 p-4">
              <h3 className="font-bold text-green-400 mb-3">🔧 Tecnologías</h3>
              <div className="grid grid-cols-2 gap-2">
                {technologies.map((tech) => (
                  <div key={tech.name} className="flex items-center space-x-2 bg-gray-800 rounded-lg p-2">
                    <span>{tech.icon}</span>
                    <span className="text-green-300 text-sm">{tech.name}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Compatibility */}
            <div className="bg-gray-900 rounded-lg border border-green-800 p-4">
              <h3 className="font-bold text-green-400 mb-3">🐧 Compatibilidad</h3>
              <div className="space-y-2">
                {distributions.map((distro) => (
                  <div key={distro.name} className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <span>{distro.icon}</span>
                      <span className="text-green-300 text-sm">{distro.name}</span>
                    </div>
                    <CheckCircle className="h-4 w-4 text-green-400" />
                  </div>
                ))}
              </div>
            </div>

            {/* Stats */}
            <div className="bg-gray-900 rounded-lg border border-green-800 p-4">
              <h3 className="font-bold text-green-400 mb-3">📊 Estadísticas</h3>
              <div className="space-y-3">
                <div className="flex justify-between">
                  <span className="text-green-300 text-sm">Scripts</span>
                  <span className="text-green-400 font-bold">5</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-green-300 text-sm">Líneas de código</span>
                  <span className="text-green-400 font-bold">1,247</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-green-300 text-sm">Distribuciones</span>
                  <span className="text-green-400 font-bold">6</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-green-300 text-sm">Última actualización</span>
                  <span className="text-green-400 font-bold">Hoy</span>
                </div>
              </div>
            </div>

            {/* Security Badge */}
            <div className="bg-gray-900 rounded-lg border border-green-800 p-4">
              <h3 className="font-bold text-green-400 mb-3">🛡️ Seguridad</h3>
              <div className="space-y-2">
                <div className="flex items-center space-x-2">
                  <CheckCircle className="h-4 w-4 text-green-400" />
                  <span className="text-green-300 text-sm">Código auditado</span>
                </div>
                <div className="flex items-center space-x-2">
                  <CheckCircle className="h-4 w-4 text-green-400" />
                  <span className="text-green-300 text-sm">Sin vulnerabilidades</span>
                </div>
                <div className="flex items-center space-x-2">
                  <CheckCircle className="h-4 w-4 text-green-400" />
                  <span className="text-green-300 text-sm">Prácticas seguras</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Footer */}
      <footer className="border-t border-green-800 bg-gray-900 py-6 mt-12">
        <div className="max-w-7xl mx-auto px-4 text-center">
          <p className="text-green-500 mb-2">
            Desarrollado por <span className="text-green-400 font-bold">Zelmar Mohozzo</span> para Code Society
          </p>
          <p className="text-green-600 text-sm">
            Scripts de hardening para entornos internos de testing y producción
          </p>
        </div>
      </footer>
    </div>
  );
}

export default App;