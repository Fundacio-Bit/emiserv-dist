#!/bin/bash

#set -o nounset
#set -o errexit

#### Description: Installs SSH.
#### Written by: Guillermo de Ignacio - gdeignacio@fundaciobit.org on 04-2021
#### WARNING: Check if DOCKER_CUSTOM_USERNAME is set. See settings/110_nginx file

###################################
###      SSH INSTALL UTILS      ###
###################################

echo ""
PROJECT_PATH="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && cd .. && pwd )"
echo "Project path at $PROJECT_PATH"
echo ""
echo "[$(date +"%Y-%m-%d %T")] Installing ssh..."
echo ""

# Taking values from .env file

source $PROJECT_PATH/bin/lib_string_utils.sh 
source $PROJECT_PATH/bin/lib_env_utils.sh

lib_env_utils.loadenv ${PROJECT_PATH}
echo ""
lib_env_utils.check_os
echo ""

if [[ isLinux -eq 1 ]]; then

    sudo apt-get update
    sudo apt-get upgrade

    sudo apt-get install openssl openssh-server openssh-client
    sudo service ssh start
    sudo service ssh enable
    sudo apt-get install net-tools

else
    echo ""
    echo "ssh should be installed manually"
    echo ""
fi

