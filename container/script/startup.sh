#!/usr/bin/env bash
set -e

AUTHOIDC_DIR="${AUTHOIDC_DIR:-/authOidc}"
XML_FILE="${AUTHOIDC_DIR}/openIdWebSecurity.xml"
PROPS_FILE="${AUTHOIDC_DIR}/openIdParameters.properties"

# Only proceed if the directory exists and contains at least one of the two files
if [ -d "${AUTHOIDC_DIR}" ] && { [ -f "${XML_FILE}" ] || [ -f "${PROPS_FILE}" ]; }; then

    # Maps: ENV_VAR_NAME -> xml_attribute_name -> properties_key
    # A properties_key of "" means the variable cannot be extracted from that file.
    declare -A XML_ATTR=(
        [CLIENT_ID]="clientId"
        [CLIENT_SECRET]="clientSecret"
        [TOKEN_URL]="tokenEndpointUrl"
        [SCOPE]="scope"
        [ISSUER_URL]="issuerIdentifier"
    )
    declare -A PROPS_KEY=(
        [CLIENT_ID]="OPENID_CLIENT_ID"
        [CLIENT_SECRET]="OPENID_CLIENT_SECRET"
        [TOKEN_URL]="OPENID_TOKEN_URL"
        [SCOPE]="OPENID_SCOPE"
        [ISSUER_URL]=""
        [INTROSPECTION_URL]="OPENID_INTROSPECTION_URL"
    )

    # Build list of files being parsed for the startup message
    PARSING_FILES=""
    [ -f "${XML_FILE}" ]   && PARSING_FILES="${XML_FILE}"
    [ -f "${PROPS_FILE}" ] && PARSING_FILES="${PARSING_FILES:+${PARSING_FILES} and }${PROPS_FILE}"
    echo "[startup] Parsing ${PARSING_FILES}"

    # Extract any variables defined in the XML file
    declare -A XML_VARS=()
    if [ -f "${XML_FILE}" ]; then
        VAR_COUNT=$(xmllint --xpath "count(//*[local-name()='variable'])" "${XML_FILE}" 2>/dev/null || echo 0)
        if [[ "${VAR_COUNT}" =~ ^[0-9]+$ ]]; then
            for ((i=1; i<=VAR_COUNT; i++)); do
                V_NAME=$(xmllint --xpath "string((//*[local-name()='variable'])[${i}]/@name)" "${XML_FILE}" 2>/dev/null)
                V_VAL=$(xmllint --xpath "string((//*[local-name()='variable'])[${i}]/@value)" "${XML_FILE}" 2>/dev/null)
                if [ -n "${V_NAME}" ]; then
                    for EXISTING_VAR in "${!XML_VARS[@]}"; do
                        V_VAL="${V_VAL//\$\{$EXISTING_VAR\}/${XML_VARS[$EXISTING_VAR]}}"
                    done
                    XML_VARS["${V_NAME}"]="${V_VAL}"
                fi
            done
        fi
    fi

    for VAR in CLIENT_ID CLIENT_SECRET TOKEN_URL SCOPE ISSUER_URL INTROSPECTION_URL; do
        # Skip if already set
        if [ -n "${!VAR}" ]; then
            echo "[startup] ${VAR} already set, skipping."
            continue
        fi

        VALUE=""
        SOURCE=""

        # Try XML file first
        if [ -f "${XML_FILE}" ]; then
            if [ "${VAR}" = "INTROSPECTION_URL" ]; then
                # Extract validationEndpointUrl only from openidConnectClient elements where
                # validationMethod is absent (defaults to introspect) or is explicitly "introspect"
                VALUE=$(xmllint --xpath "string((//*[local-name()='openidConnectClient'][not(@validationMethod) or @validationMethod='introspect'])[1]/@validationEndpointUrl)" "${XML_FILE}" 2>/dev/null)
            elif [ -n "${XML_ATTR[$VAR]:-}" ]; then
                VALUE=$(xmllint --xpath "string((//*[local-name()='openidConnectClient'])[1]/@${XML_ATTR[$VAR]})" "${XML_FILE}" 2>/dev/null)
            fi
            if [ -n "${VALUE}" ]; then
                # Replace any variable references in the value
                for V_NAME in "${!XML_VARS[@]}"; do
                    VALUE="${VALUE//\$\{$V_NAME\}/${XML_VARS[$V_NAME]}}"
                done
                SOURCE="${XML_FILE}"
            fi
        fi

        # Fallback to properties file (only if a key is defined for this variable)
        if [ -z "${VALUE}" ] && [ -f "${PROPS_FILE}" ] && [ -n "${PROPS_KEY[$VAR]:-}" ]; then
            VALUE=$(grep -oP "^${PROPS_KEY[$VAR]}=\K[^# ]+" "${PROPS_FILE}" | head -1)
            [ -n "${VALUE}" ] && SOURCE="${PROPS_FILE}"
        fi

        if [ -n "${VALUE}" ]; then
            export "${VAR}=${VALUE}"
            if [ "${VAR}" = "CLIENT_SECRET" ]; then
                SAFE_VALUE="${VALUE:0:1}*****${VALUE: -1}"
            else
                SAFE_VALUE="${VALUE}"
            fi
            echo "[startup] ${VAR}=${SAFE_VALUE} (set from ${SOURCE})."
        else
            echo "[startup] ${VAR} not found in config files, leaving unset."
        fi
    done

fi

exec ibm-odm-management-mcp-server "$@"
