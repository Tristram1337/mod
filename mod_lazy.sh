#!/bin/bash

#set -e  # Při chybě končíme

# --- Globální proměnné ---
APACHE_CONF_DIR="/etc/apache2/sites-enabled"
MOD_MD_CONF="/etc/apache2/conf-available/md-zcu.conf"
HOOK_SCRIPT="/etc/apache2/md-message"
SUDOERS_FILE="/etc/sudoers.d/mod_md_iptables"
CONTACT_EMAIL="operator@service.zcu.cz"
PRODUCTION_URL="https://acme-v02.api.letsencrypt.org/directory"
LOG_FILE="/var/log/mod_md_setup.log"
RECOMMENDED_ACTION=""

# Kontrola, zda je skript spuštěn jako root
if [[ $EUID -ne 0 ]]; then
    echo "Tento skript musí být spuštěn jako root (přidejte sudo)." 1>&2
    exit 1
fi

log() {
    #echo "$(date '+%Y-%m-%d %H:%M:%S') $1"
    echo "$(date '+%H:%M:%S') $1"
}

sep() {
    echo "----------------------------------------"
}

parse_apache_enable_output() {
    local out="$1"
    if echo "$out" | grep -qi "systemctl restart apache2"; then
        RECOMMENDED_ACTION="restart"
    elif echo "$out" | grep -qi "systemctl reload apache2" && [[ "$RECOMMENDED_ACTION" != "restart" ]]; then
        RECOMMENDED_ACTION="reload"
    fi
}

install_apache() {
    sep
    if ! dpkg -l | grep -qw apache2; then
        read -p "Apache není nainstalován. Chcete ho nyní nainstalovat? (y/n): " ans
        if [[ "$ans" == "y" ]]; then
            echo "Spusťte ručně:"
            echo "sudo apt-get update && sudo apt-get install -y apache2 apache2-utils"
        else
            log "Apache není nainstalován, skript končí."
            exit 1
        fi
    else
        log "Apache je již nainstalován."
    fi
}

detect_apachectl() {
    sep
    if command -v apache2ctl &>/dev/null; then
        APACHECTL=apache2ctl
    elif command -v apachectl &>/dev/null; then
        APACHECTL=apachectl
    elif command -v httpd &>/dev/null; then
        APACHECTL=httpd
    else
        log "Chyba: nelze nalézt apache2ctl, apachectl ani httpd."
        exit 1
    fi
    log "Používám příkaz: $APACHECTL"
}

enable_modules() {
    sep
    log "Načítám seznam aktivních modulů..."
    MODULES=$($APACHECTL -M 2>&1)
    log "Seznam modulů načten."

    for module in md ssl; do
        if echo "$MODULES" | grep -q "${module}_module"; then
            log "Modul '$module' je již aktivní."
        else
            echo "Spusťte ručně:"
            echo "sudo a2enmod $module"
        fi
    done
}

find_domains() {
    sep
    log "Hledám domény v $APACHE_CONF_DIR/*.conf..."
    DOMAINS=$(grep -hEo "ServerName [^ ]+" "$APACHE_CONF_DIR"/*.conf 2>/dev/null | awk '{print $2}' | sort -u)
    if [[ -z "$DOMAINS" ]]; then
        log "Nebyl nalezen žádný ServerName. Skript končí."
        exit 0
    fi
    log "Nalezeny domény: $DOMAINS"
}

generate_md_config() {
    sep
    log "Vytvořte soubor '$MOD_MD_CONF' tímto obsahem:"
    DOMAINS_LINE=$(echo "$DOMAINS" | tr '\n' ' ')

    cat <<EOF
sudo tee $MOD_MD_CONF <<EOT
MDContactEmail $CONTACT_EMAIL
MDCertificateAgreement accepted
MDCertificateAuthority $PRODUCTION_URL
MDomain $DOMAINS_LINE
EOT
EOF
}

create_hook_script() {
    sep
    log "Vytvářím hook skript '$HOOK_SCRIPT'..."
    tee "$HOOK_SCRIPT" >/dev/null <<'EOF'
#!/bin/bash
LOG_FILE="/var/log/md-message.log"

log_event() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') $1" >> "$LOG_FILE"
}

log_event "Event: $1, Domain: $2"

case "$1" in
    "renewing")
        log_event "[INFO] Obnovuji certifikát pro: $2"

        if ! iptables -C INPUT -p tcp --dport 80 -m comment --comment "ACME renewal" -j ACCEPT 2>/dev/null; then
            iptables -A INPUT -p tcp --dport 80 -m comment --comment "ACME renewal" -j ACCEPT
        fi
        ;;
    "renewed")
        log_event "[INFO] Obnova certifikátu byla úspěšná: $2"

        iptables -D INPUT -p tcp --dport 80 -m comment --comment "ACME renewal" -j ACCEPT 2>/dev/null || true
        ;;
    "errored")
        log_event "[ERROR] Chyba při obnově certifikátu pro: $2"
        ;;
    "expiring")
        log_event "[WARNING] Certifikát brzy vyprší: $2"
        ;;
    "installed")
        log_event "[INFO] Certifikát nainstalován: $2"
        ;;
    *)
        log_event "[WARNING] Neznámá událost: $1 pro doménu $2"
        ;;
esac
EOF
    chmod +x "$HOOK_SCRIPT"
    log "Hook skript '$HOOK_SCRIPT' byl vytvořen."
}

setup_sudoers() {
    log "Je potřeba vytvořit sudoers pravidla pro iptables."

    cat <<EOF
Vytvořte soubor '$SUDOERS_FILE' s tímto obsahem:
---------------------------------------------------
www-data ALL=(ALL) NOPASSWD: /usr/sbin/iptables -I INPUT -p tcp --dport 80 -j ACCEPT
www-data ALL=(ALL) NOPASSWD: /usr/sbin/iptables -D INPUT -p tcp --dport 80 -j ACCEPT
www-data ALL=(ALL) NOPASSWD: /usr/sbin/iptables -C INPUT -p tcp --dport 80 -j ACCEPT
---------------------------------------------------

Poté nastavte správná oprávnění a vlastníka:
---------------------------------------------------
sudo chown root:root $SUDOERS_FILE
sudo chmod 440 $SUDOERS_FILE
---------------------------------------------------
EOF
}

enable_md_config() {
    echo "Spusťte ručně:"
    echo "sudo a2enconf $(basename "$MOD_MD_CONF")"
}

install_apache
detect_apachectl
enable_modules
find_domains
generate_md_config
create_hook_script
setup_sudoers
enable_md_config
