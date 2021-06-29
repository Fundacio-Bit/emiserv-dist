#!/bin/bash

set -o nounset
set -o errexit

#### Description: Generate properties file from template
#### Written by: Guillermo de Ignacio - gdeignacio@fundaciobit.org on 04-2021

###################################
###   GENERATE PROPERTIES UTILS ###
###################################

echo ""
PROJECT_PATH="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && cd ../.. && pwd )"
echo "Project path at $PROJECT_PATH"
echo ""
echo "[$(date +"%Y-%m-%d %T")] Build and deploy project..."
echo ""

#source $PROJECT_PATH/bin/_app__loadenv.sh

echo off
if [[ -f help.txt ]]
then
  cat help.txt
else
  echo "help.txt no existe"
fi

TEMPLATE=$PROJECT_PATH/bbdd/core_parametro_configuracion.sql.template
PROPERTIES=$PROJECT_PATH/bbdd/core_parametro_configuracion.sql

echo "Copying $TEMPLATE to $PROPERTIES"
cp $TEMPLATE $PROPERTIES
