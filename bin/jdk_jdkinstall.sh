#!/bin/bash

set -o nounset
set -o errexit

#### Description: Downloads and installs jdk binaries
#### Written by: Guillermo de Ignacio - gdeignacio@fundaciobit.org on 04-2021

###################################
###   JDK INSTALL UTILS         ###
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

echo "Downloading" $JDK_URL "to" $JDK_TARGET
wget $JDK_URL -P $JDK_TARGET
tar -zxvf $JDK_TARGET/$JDK_TARFILE --directory $JDK_TARGET
rm $JDK_TARGET/$JDK_TARFILE