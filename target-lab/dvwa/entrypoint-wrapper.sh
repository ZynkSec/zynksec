#!/bin/sh
# Wrapper around cytopia/dvwa's stock /entrypoint.sh.
#
# Appends ``$_DVWA[ 'disable_authentication' ] = true`` to DVWA's
# config.inc.php BEFORE cytopia's entrypoint rewrites the rest of
# the config block.  Cytopia uses ``>>`` (append) on
# /var/www/html/config/config.inc.php, so the resulting file looks
# like:
#
#   <?php (image-baked baseline: $DBMS, $_DVWA = array(), db_port) ?>
#   <?php $_DVWA['disable_authentication'] = true; ?>     <- our line
#   <?php (cytopia's runtime config: db creds, security_level, ...) ?>
#
# PHP parses every ``<?php ... ?>`` block; after all three execute,
# $_DVWA carries every key.  Our key doesn't conflict with any of
# cytopia's so both sticks.  Setting it ``true`` makes
# /vulnerabilities/* reachable without first POSTing /login.php —
# which lets ZAP scan the intentionally-vulnerable code paths
# (the load-bearing reason DVWA is in the lab in the first place).
#
# Bind-mounted read-only at /target-lab/dvwa-entrypoint-wrapper.sh
# from target-lab/dvwa/entrypoint-wrapper.sh in compose-targets.yml.
# The wrapper is the container's entrypoint; it then exec's
# cytopia's stock entrypoint with the original arguments.

set -eu

CONFIG_FILE="/var/www/html/config/config.inc.php"

if [ ! -f "${CONFIG_FILE}" ]; then
    echo "[dvwa-wrapper] config.inc.php missing at ${CONFIG_FILE}" >&2
    exit 1
fi

echo "<?php \$_DVWA[ 'disable_authentication' ] = true; ?>" >> "${CONFIG_FILE}"
echo "[dvwa-wrapper] appended disable_authentication=true to ${CONFIG_FILE}" >&2

exec /entrypoint.sh "$@"
