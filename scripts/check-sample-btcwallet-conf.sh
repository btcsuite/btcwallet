#!/bin/bash

# This script performs different checks on the sample-btcwallet.conf file:
# 1. Checks that all relevant options of btcwallet are included.
# 2. Verifies that defaults are labeled if there are also further examples.
# 3. Checks that all default values of btcwallet are mentioned correctly,
#    including empty defaults and booleans which are set to false by default.

set -e

CONF_FILE=${1:-sample-btcwallet.conf}

# Get the directory containing this script.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
SAMPLE_CONF="$REPO_DIR/$CONF_FILE"

# Check if sample config file exists.
if [ ! -f "$SAMPLE_CONF" ]; then
    echo "ERROR: $CONF_FILE not found at $SAMPLE_CONF"
    exit 1
fi

BTCWALLET_BIN="btcwallet"

# Check if btcwallet binary exists and is executable.
if [ ! -x "$(which "$BTCWALLET_BIN" 2>/dev/null)" ]; then
    echo "ERROR: $BTCWALLET_BIN binary not found in PATH or not executable"
    exit 1
fi

# Get btcwallet help output.
FILE_TMP=$(mktemp)
"$BTCWALLET_BIN" --help > "$FILE_TMP" 2>&1 || true
BTCWALLET_HELP="$(cat $FILE_TMP) --end"

# BTCWALLET_OPTIONS is a list of all options of btcwallet including the equal
# sign, which is needed to distinguish between booleans and other variables. It
# is created by reading the first two columns of btcwallet --help.
BTCWALLET_OPTIONS="$(cat $FILE_TMP | \
    awk '{
        option="";
        if ($1 ~ /^--/){option=$1};
        if ($2 ~ /^--/){option=$2};
        if (match(option,  /--[^=]+[=]*/))
            {printf "%s ", substr(option, RSTART, RLENGTH)}
        }
        END { printf "%s", "--end"}')"
rm $FILE_TMP

# OPTIONS_NO_CONF is a list of all options without any expected entries in
# sample-btcwallet.conf. There's no validation needed for these options.
OPTIONS_NO_CONF="help version configfile end"

# OPTIONS_NO_BTCWALLET_DEFAULT_VALUE_CHECK is a list of options with default
# values set, but there aren't any returned defaults by btcwallet --help.
# Defaults have to be included in sample-btcwallet.conf but no further checks
# are performed.
OPTIONS_NO_BTCWALLET_DEFAULT_VALUE_CHECK="rpclisten legacyrpclisten experimentalrpclisten profile rpcconnect cafile proxy"

# EXITCODE is returned at the end after all checks are performed and set to 1 if
# a validation error occurs. COUNTER counts the checked options.
EXITCODE=0
COUNTER=0

echo "Checking $CONF_FILE..."

for OPTION in $BTCWALLET_OPTIONS; do
    # Determination of the clean name of the option without leading -- and
    # possible = at the end.
    OPTION_NAME=${OPTION##--}
    OPTION_NAME=${OPTION_NAME%=}

    # Skip if there is no expected entry in sample-btcwallet.conf.
    echo "$OPTIONS_NO_CONF" | grep -qw $OPTION_NAME && continue
    COUNTER=$((COUNTER+1))

    # Determine the default value of btcwallet. If the option has no equal sign,
    # it is boolean and set to false.
    # For other options we grep the text between the current option and the next
    # option from BTCWALLET_HELP. The default value is given in brackets
    # (default: xx) In the case of durations expressed in hours or minutes, the
    # indications of '0m0s' and '0s' are removed, as they provide redundant
    # information. HOME is replaced with general values.
    if [[ "$OPTION" == *"="* ]]; then
        OPTION_NEXT="$(echo "$BTCWALLET_OPTIONS" | sed -E -e "s/.*$OPTION //" \
            -e "s/([^ ]*).*/\1/")"
        DEFAULT_VALUE_BTCWALLET="$(echo $BTCWALLET_HELP | \
            sed -E -e "s/.*--${OPTION##--}//" \
            -e "s/--${OPTION_NEXT##--}.*//" \
            -e '/(default:.*)/ {' \
                -e 's/.*\(default: ([^)]*)\).*/\1/' -e 't end' -e '}' \
            -e 's/.*//' -e ':end' \
            -e "s#m0s#m#g" \
            -e "s#h0m#h#g" \
            -e "s#$HOME#~#g")"
    else
        DEFAULT_VALUE_BTCWALLET="false"
    fi

    # An option is considered included in the sample-btcwallet.conf if there is
    # a match of the following regex.
    OPTION_REGEX="^;[ ]*$OPTION_NAME=[^ ]*$"

    # Perform the different checks now. If one fails we move to the next option.
    # 1. check if the option is included in the sample-btcwallet.conf.
    if [ $(grep -c "$OPTION_REGEX" $SAMPLE_CONF) -eq 0 ]; then
        echo "Option $OPTION_NAME: no default or example included in $CONF_FILE"
        EXITCODE=1
        continue
    fi
    
    # Skip if no default value check should be performed.
    echo "$OPTIONS_NO_BTCWALLET_DEFAULT_VALUE_CHECK" | grep -wq $OPTION_NAME && continue

    # 2. Check that the default value is labeled if it is included multiple
    # times.
    if [ $(grep -c "$OPTION_REGEX" $SAMPLE_CONF) -ge 2 ]; then
        # For one option there has to be a preceding line "; Default:"
        # If it matches we grep the default value from the file.
        if grep -A 1 "^; Default:" $SAMPLE_CONF | grep -q "$OPTION_REGEX"; then
            DEFAULT_VALUE_CONF="$(grep -A 1 "^; Default:" $SAMPLE_CONF | \
               grep "$OPTION_REGEX" | cut -d= -f2)"

        else
            echo "Option $OPTION_NAME: mentioned multiple times in $CONF_FILE but without a default value"
            EXITCODE=1
            continue
        fi
    else
        # If there is only one entry in sample-btcwallet.conf we grep the
        # default value.
        DEFAULT_VALUE_CONF=$(grep "$OPTION_REGEX" $SAMPLE_CONF | cut -d= -f2)
    fi
    
    # 3. Compare the default value of btcwallet --help with the value in the
    # sample-btcwallet.conf file. If btcwallet doesn't provide a default value,
    # it is allowed for the value in the file to be '0' or '0s'. For boolean
    # options, allow both 'false' and '0' representations.
    if [ ! "$DEFAULT_VALUE_BTCWALLET" == "$DEFAULT_VALUE_CONF" ]; then

        if [ -z "$DEFAULT_VALUE_BTCWALLET" ] && [ "$DEFAULT_VALUE_CONF" == "0" ]; then
            true

        elif [ -z "$DEFAULT_VALUE_BTCWALLET" ] && [ "$DEFAULT_VALUE_CONF" == "0s" ]; then
            true

        elif [ "$DEFAULT_VALUE_BTCWALLET" == "false" ] && [ "$DEFAULT_VALUE_CONF" == "0" ]; then
            true

        else
            echo "Option $OPTION_NAME: defaults don't match - $CONF_FILE: '$DEFAULT_VALUE_CONF', btcwallet: '$DEFAULT_VALUE_BTCWALLET'"
            EXITCODE=1
            continue
        fi
    fi

done

echo "$COUNTER options were checked"

if [ $EXITCODE -eq 0 ]; then
    echo "SUCCESS: All btcwallet configuration options are present and correctly configured in $CONF_FILE"
    echo "$CONF_FILE validation completed successfully!"
else
    echo "ERROR: Configuration validation failed"
fi

exit $EXITCODE