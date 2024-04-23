#!/bin/bash

set -o nounset
set -o errexit

#### Description: Lists alias from jks keystore
#### Written by: Guillermo de Ignacio - gdeignacio@fundaciobit.org on 04-2021

###################################
###   KEYTOOL LIST              ###
###################################

echo ""
PROJECT_PATH="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && cd .. && pwd )"
echo "Project path at $PROJECT_PATH"
echo ""
echo "[$(date +"%Y-%m-%d %T")] Installing JDK..."
echo ""

source $PROJECT_PATH/bin/lib_string_utils.sh 
source $PROJECT_PATH/bin/lib_env_utils.sh

lib_env_utils.loadenv ${PROJECT_PATH}
echo ""
lib_env_utils.check_os
echo ""

KEYSTORE_FOLDER=$APP_FILES_BASE_FOLDER/firma

if [ -d "$KEYSTORE_FOLDER" ]; then
    ### Take action if $DIR exists ###
    echo ""
    echo "Keystore folder at" $KEYSTORE_FOLDER 
    echo ""
else
    ###  Control will jump here if dir does NOT exists ###
    echo "Keystore folder ${KEYSTORE_FOLDER} not found. Creating ..."
    mkdir -p ${KEYSTORE_FOLDER}
fi

COMMAND=keytool

KEYTOOL=$(command -v $COMMAND)
echo "$COMMAND at $KEYTOOL"

remaining=1

for i in "$@"
do
    case $i in
        -keystore=*)
        KEYSTORE="${i#*=}"
        let "remaining--"
        shift # past argument=value
        ;;
        *)
            # unknown option
        ;;
    esac
done


if [[ remaining -eq 0 ]]; then
    KEYSTORE=${KEYSTORE_FOLDER}/${KEYSTORE}
    echo Loading parameter
    echo keystore set to $KEYSTORE
else
    if [[ remaining -eq 1 ]]; then
        KEYSTORE=${KEYSTORE_FOLDER}/${APP_PROJECT_NAME}.jks
        echo Loading default values
        echo keystore set to $KEYSTORE
    else
        echo Wrong number of parameters $remaining more expected
        exit 1
    fi
fi

$KEYTOOL -list -v -keystore $KEYSTORE