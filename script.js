// JavaScript para efectos interactivos y animaciones

// Scripts data
const scriptsData = {
    '01-setup-user': {
        icon: '👤',
        name: '01-setup-user.sh',
        content: `#!/bin/bash
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

# Deshabilitar login root directo
log "Deshabilitando login root directo..."
passwd -l root

log "✓ Configuración de usuario seguro completada"
log "✓ Usuario \$NEW_USER creado con permisos sudo"
log "✓ Acceso root remoto deshabilitado"

exit 0`
    },
    '02-firewall': {
        icon: '🔥',
        name: '02-firewall.sh',
        content: `#!/bin/bash
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
else
    error "UFW no encontrado"
    exit 1
fi

log "✓ Firewall configurado con políticas restrictivas"
log "✓ Tráfico entrante bloqueado por defecto"
log "✓ Puertos esenciales habilitados"

exit 0`
    },
    '03-fail2ban': {
        icon: '🚫',
        name: '03-fail2ban.sh',
        content: `#!/bin/bash
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

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 1800
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

exit 0`
    },
    '04-ssh-hardening': {
        icon: '🔐',
        name: '04-ssh-hardening.sh',
        content: `#!/bin/bash
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

# Configuración de autenticación
LoginGraceTime 30
PermitRootLogin no
MaxAuthTries 3
MaxSessions 2

# Autenticación por clave pública
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys

# Deshabilitar autenticación por contraseña
PasswordAuthentication no
PermitEmptyPasswords no

# Configuración de usuarios
AllowUsers \$SSH_USER
DenyUsers root

# Configuración de sesión
ClientAliveInterval 300
ClientAliveCountMax 2

# Configuración de logging
SyslogFacility AUTHPRIV
LogLevel INFO
EOF

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

log "✓ SSH hardening completado"
log "✓ Puerto SSH cambiado a: \$SSH_PORT"
log "✓ Autenticación por contraseña deshabilitada"
log "✓ Solo usuario \$SSH_USER permitido"

warning "IMPORTANTE: Pruebe la conexión SSH en una nueva terminal"

exit 0`
    },
    '05-selinux': {
        icon: '🛡️',
        name: '05-selinux.sh',
        content: `#!/bin/bash
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
        exit 0
    else
        error "Sistema no compatible con SELinux"
        exit 1
    fi
fi

# Instalar herramientas SELinux si no están presentes
log "Instalando herramientas SELinux..."
if command -v yum &> /dev/null; then
    yum install -y policycoreutils-python-utils setroubleshoot-server
elif command -v dnf &> /dev/null; then
    dnf install -y policycoreutils-python-utils setroubleshoot-server
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

# Backup de configuración actual
cp /etc/selinux/config /etc/selinux/config.backup-$(date +%Y%m%d-%H%M%S)

# Configurar SELinux
cat > /etc/selinux/config << 'EOF'
# Configuración SELinux - Code Society Hardening
# Autor: Zelmar Mohozzo

# Este archivo controla el estado de SELinux en el sistema
SELINUX=enforcing
SELINUXTYPE=targeted
EOF

# Establecer contextos SELinux para directorios comunes
log "Configurando contextos SELinux..."
restorecon -R /etc
restorecon -R /var
restorecon -R /home

# Configurar auditd para monitoreo SELinux
log "Configurando auditd para monitoreo SELinux..."
systemctl enable auditd
systemctl start auditd

# Verificar configuración
log "Verificando configuración SELinux..."
sestatus

# Verificar si se requiere reinicio
if [[ "\$CURRENT_STATE" != "Enforcing" ]]; then
    warning "Se requiere reinicio para activar SELinux en modo enforcing"
    touch /.autorelabel
    log "Configurado relabel automático de archivos en próximo reinicio"
fi

log "✓ SELinux configurado en modo enforcing"
log "✓ Política targeted aplicada"
log "✓ Contextos de seguridad configurados"
log "✓ Auditd habilitado para monitoreo"

if [[ "\$CURRENT_STATE" != "Enforcing" ]]; then
    warning "IMPORTANTE: Reinicie el sistema para activar SELinux"
fi

exit 0`
    }
};

document.addEventListener('DOMContentLoaded', function() {
    // Typewriter effect para el comando
    const command = document.querySelector('.typewriter');
    if (command) {
        const text = command.textContent;
        command.textContent = '';
        let i = 0;
        
        function typeWriter() {
            if (i < text.length) {
                command.textContent += text.charAt(i);
                i++;
                setTimeout(typeWriter, 100);
            }
        }
        
        setTimeout(typeWriter, 1000);
    }

    // Efecto de glitch aleatorio en el título
    const glitchText = document.querySelector('.glitch-text');
    if (glitchText) {
        setInterval(() => {
            if (Math.random() > 0.95) {
                glitchText.style.animation = 'none';
                setTimeout(() => {
                    glitchText.style.animation = '';
                }, 100);
            }
        }, 2000);
    }

    // Script viewer functionality
    const scriptButtons = document.querySelectorAll('.script-btn');
    const scriptDisplay = document.getElementById('script-display');
    const scriptCurrentIcon = document.querySelector('.script-current-icon');
    const scriptCurrentName = document.querySelector('.script-current-name');

    scriptButtons.forEach(button => {
        button.addEventListener('click', function() {
            // Remove active class from all buttons
            scriptButtons.forEach(btn => btn.classList.remove('active'));
            
            // Add active class to clicked button
            this.classList.add('active');
            
            // Get script data
            const scriptKey = this.dataset.script;
            const scriptData = scriptsData[scriptKey];
            
            if (scriptData) {
                // Update script display
                scriptDisplay.innerHTML = `<code>${scriptData.content}</code>`;
                scriptCurrentIcon.textContent = scriptData.icon;
                scriptCurrentName.textContent = scriptData.name;
            }
        });
    });

    // Animación de aparición de elementos al hacer scroll
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.opacity = '1';
                entry.target.style.transform = 'translateY(0)';
            }
        });
    }, observerOptions);

    // Aplicar animación a las tarjetas
    const cards = document.querySelectorAll('.distro-card, .feature-item, .author-card, .repo-card');
    cards.forEach(card => {
        card.style.opacity = '0';
        card.style.transform = 'translateY(30px)';
        card.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
        observer.observe(card);
    });

    // Efecto de hover en las badges
    const badges = document.querySelectorAll('.badge');
    badges.forEach(badge => {
        badge.addEventListener('mouseenter', function() {
            this.style.background = 'linear-gradient(45deg, var(--accent-green), var(--accent-blue))';
            this.style.color = 'var(--primary-bg)';
        });
        
        badge.addEventListener('mouseleave', function() {
            this.style.background = 'var(--card-bg)';
            this.style.color = 'var(--text-primary)';
        });
    });

    // Efecto de partículas en el fondo
    function createParticle() {
        const particle = document.createElement('div');
        particle.style.position = 'fixed';
        particle.style.width = '2px';
        particle.style.height = '2px';
        particle.style.background = 'var(--accent-green)';
        particle.style.borderRadius = '50%';
        particle.style.pointerEvents = 'none';
        particle.style.zIndex = '-1';
        particle.style.left = Math.random() * window.innerWidth + 'px';
        particle.style.top = '-5px';
        particle.style.opacity = '0.5';
        
        document.body.appendChild(particle);
        
        const animation = particle.animate([
            { transform: 'translateY(0px)', opacity: 0.5 },
            { transform: `translateY(${window.innerHeight + 10}px)`, opacity: 0 }
        ], {
            duration: Math.random() * 3000 + 2000,
            easing: 'linear'
        });
        
        animation.onfinish = () => particle.remove();
    }

    // Crear partículas ocasionalmente
    setInterval(createParticle, 3000);

    // Animación de los logs en el terminal preview
    const logLines = document.querySelectorAll('.log-line');
    logLines.forEach((line, index) => {
        line.style.opacity = '0';
        setTimeout(() => {
            line.style.opacity = '1';
            line.style.transition = 'opacity 0.5s ease';
        }, index * 150);
    });

    // Smooth scroll para enlaces internos
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });

    // Efecto de parallax sutil en el header
    window.addEventListener('scroll', () => {
        const scrolled = window.pageYOffset;
        const header = document.querySelector('.terminal-header');
        if (header) {
            header.style.transform = `translateY(${scrolled * 0.3}px)`;
        }
    });

    // Detectar si el usuario prefiere movimiento reducido
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
    
    if (prefersReducedMotion.matches) {
        // Deshabilitar animaciones para usuarios que prefieren movimiento reducido
        document.querySelectorAll('*').forEach(el => {
            el.style.animation = 'none';
            el.style.transition = 'none';
        });
    }

    // Lazy loading para imágenes
    const images = document.querySelectorAll('img[data-src]');
    const imageObserver = new IntersectionObserver((entries, observer) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const img = entry.target;
                img.src = img.dataset.src;
                img.classList.remove('lazy');
                imageObserver.unobserve(img);
            }
        });
    });

    images.forEach(img => imageObserver.observe(img));

    // Animación del cursor en el terminal demo
    const cursorDemo = document.querySelector('.cursor-demo');
    if (cursorDemo) {
        setInterval(() => {
            cursorDemo.style.opacity = cursorDemo.style.opacity === '0' ? '1' : '0';
        }, 500);
    }

    // Efecto de escritura en el footer
    const footerOutput = document.querySelector('.footer-output');
    if (footerOutput) {
        const lines = footerOutput.querySelectorAll('p');
        lines.forEach((line, index) => {
            line.style.opacity = '0';
            setTimeout(() => {
                line.style.opacity = '1';
                line.style.transition = 'opacity 0.5s ease';
            }, index * 200);
        });
    }
});

// Función para copiar script al portapapeles
function copyScript() {
    const activeButton = document.querySelector('.script-btn.active');
    if (activeButton) {
        const scriptKey = activeButton.dataset.script;
        const scriptData = scriptsData[scriptKey];
        
        if (scriptData) {
            navigator.clipboard.writeText(scriptData.content).then(() => {
                // Mostrar notificación de éxito
                showNotification('✓ Script copiado al portapapeles');
            }).catch(() => {
                showNotification('❌ Error al copiar script');
            });
        }
    }
}

// Función para mostrar notificaciones
function showNotification(message) {
    const notification = document.createElement('div');
    notification.textContent = message;
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: var(--accent-green);
        color: var(--primary-bg);
        padding: 1rem 1.5rem;
        border-radius: 8px;
        z-index: 1000;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.9rem;
        font-weight: 500;
        box-shadow: 0 4px 20px rgba(0, 255, 65, 0.3);
        animation: slideInNotification 0.3s ease;
    `;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.style.animation = 'slideOutNotification 0.3s ease';
        setTimeout(() => {
            notification.remove();
        }, 300);
    }, 3000);
}

// Agregar estilos para las animaciones de notificación
const style = document.createElement('style');
style.textContent = `
    @keyframes slideInNotification {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes slideOutNotification {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(100%);
            opacity: 0;
        }
    }
`;
document.head.appendChild(style);