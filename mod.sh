#!/bin/bash

#set -e  # Při chybě končíme

APACHE_CONF_DIR="/etc/apache2/sites-enabled"
MOD_MD_CONF="/etc/apache2/conf-available/md-zcu.conf"
HOOK_SCRIPT="/etc/apache2/md-message"
CONTACT_EMAIL="operator@service.zcu.cz"
PRODUCTION_URL="https://acme-v02.api.letsencrypt.org/directory"
LOG_FILE="/var/log/mod_md_setup.log"
RECOMMENDED_ACTION=""

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') $1" | tee -a "$LOG_FILE"
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
            log "Instaluji Apache..."
            sudo apt-get update && sudo apt-get install -y apache2 apache2-utils
            log "Apache byl nainstalován."
        else
            log "Apache není nainstalován, skript končí."
            exit 1
        fi
    else
        log "Apache je již nainstalován."
    fi
}

cleanup_old_config() {
    sudo rm -f "$MOD_MD_CONF" "/etc/apache2/conf-enabled/$(basename "$MOD_MD_CONF")"
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
            log "Povoluji modul '$module'..."
            A2ENMOD_OUT=$(sudo a2enmod "$module")
            echo "$A2ENMOD_OUT"
            parse_apache_enable_output "$A2ENMOD_OUT"
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
    log "Generuji konfigurační soubor '$MOD_MD_CONF'..."

    # Převod seznamu domén do jednoho řádku odděleného mezerami
    DOMAINS_LINE=$(echo "$DOMAINS" | tr '\n' ' ')

    sudo tee "$MOD_MD_CONF" >/dev/null <<EOF
MDContactEmail $CONTACT_EMAIL
MDCertificateAgreement accepted
MDCertificateAuthority $PRODUCTION_URL
MDomain $DOMAINS_LINE
EOF
    log "Soubor '$MOD_MD_CONF' byl vytvořen s doménami: $DOMAINS_LINE"
}

create_hook_script() {
    sep
    log "Vytvářím hook skript '$HOOK_SCRIPT'..."
    sudo tee "$HOOK_SCRIPT" >/dev/null <<'EOF'
#!/bin/bash
LOG_FILE="/var/log/md-message.log"
echo "$(date '+%Y-%m-%d %H:%M:%S') Event: $1, Domain: $2" >> "$LOG_FILE"
EOF
    sudo chmod +x "$HOOK_SCRIPT"
    log "Hook skript '$HOOK_SCRIPT' byl vytvořen."
}

enable_md_config() {
    sep
    log "Povoluji konfiguraci 'md-zcu.conf'..."
    A2ENCONF_OUT=$(sudo a2enconf "$(basename "$MOD_MD_CONF")")
    echo "$A2ENCONF_OUT"
    parse_apache_enable_output "$A2ENCONF_OUT"
}

check_ssl_directives() {
    sep
    SSL_LINES=$(grep -HnE "^[^#]*\bSSLCertificate(File|Key|Chain)File\b" "$APACHE_CONF_DIR"/*.conf 2>/dev/null || true)
    if [[ -n "$SSL_LINES" ]]; then
        log "Byly nalezeny nekomenované SSL direktivy. Bez zakomentování to nebude fungovat!"
        read -p "Chcete je zakomentovat? (y/n): " ans
        if [[ "$ans" == "y" ]]; then
            for f in "$APACHE_CONF_DIR"/*.conf; do
                sudo sed -i 's/^\([^#].*\bSSLCertificate\(File\|KeyFile\|ChainFile\).*\)/# \1/' "$f"
            done
            log "SSL direktivy byly zakomentovány."
        else
            log "Staré SSL direktivy ponechány, může dojít ke konfliktu s mod_md."
        fi
    else
        log "Žádné nekomenované SSL direktivy nenalezeny."
    fi
}

check_ssl_engine() {
    sep
    log "Kontrola a přidání 'SSLEngine on' tam, kde je potřeba..."
    for f in "$APACHE_CONF_DIR"/*.conf; do
        if ! grep -qE '^[[:space:]]*SSLEngine\s+on\b' "$f"; then
            sudo sed -i '/^[^#]*<VirtualHost [^>]*:443>/ a \    SSLEngine on' "$f"
            log "Přidán 'SSLEngine on' do '$f'."
        fi
    done
}

test_and_reload_apache() {
    sep
    log "Testuji syntaxi Apache..."
    if ! $APACHECTL -t; then
        log "Chyba: Syntaxe Apache není v pořádku."
        exit 1
    fi
    log "Syntax OK."

    if [[ "$RECOMMENDED_ACTION" == "restart" ]]; then
        log "Provádím restart Apache..."
        sudo systemctl restart apache2
    else
        log "Provádím reload Apache..."
        sudo systemctl reload apache2
    fi
    log "Apache úspěšně restartován/reloadován."
}

install_apache
cleanup_old_config
detect_apachectl
enable_modules
find_domains
generate_md_config
create_hook_script
enable_md_config
check_ssl_directives
check_ssl_engine
test_and_reload_apache
