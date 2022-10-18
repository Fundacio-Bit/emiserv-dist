#!/bin/bash

set -o nounset
set -o errexit

#### Description: Run version patch database scripts from APP_PROJECT_DB_PATCH_FOLDER
####              by executing psql from docker container
#### Written by: Guillermo de Ignacio - gdeignacio@fundaciobit.org on 04-2021

###################################
###   PATCH DATABASE UTILS      ###
###################################

echo ""
PROJECT_PATH="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && cd .. && pwd )"
echo "Project path at $PROJECT_PATH"
echo ""
echo "[$(date +"%Y-%m-%d %T")] Loading database..."
echo ""

# Taking values from .env file

source $PROJECT_PATH/bin/lib_string_utils.sh 
source $PROJECT_PATH/bin/lib_env_utils.sh

lib_env_utils.loadenv ${PROJECT_PATH}
echo ""
lib_env_utils.check_os
echo ""
lib_env_utils.check_docker
echo ""

if [[ "${DOCKER}" == "/dev/null" ]]; then
  echo "Docker not installed. Exiting"
  exit 1
fi

IFS=' '
#Read the split words into an array based on space delimiter
read -a VERSIONS_ARRAY <<< ${APP_PROJECT_DB_PATCH_ARRAY}

IFS=' '
#Read the split words into an array based on space delimiter
read -a EXCLUSIONS_ARRAY <<< ${APP_PROJECT_SGBD_EXCLUDE_ARRAY}


# VERSIONS_ARRAY=${APP_PROJECT_DB_PATCH_ARRAY}

VERSIONS_PATH=${APP_PROJECT_DB_PATCH_FOLDER}

for VERSION in ${VERSIONS_ARRAY[*]}; do
  
  # Begin version section

  VERSION_FOLDER=${VERSIONS_PATH}/${VERSION}
  echo ""
  echo "Executing "$VERSION "version patch"
  echo "Processing "${VERSION_FOLDER} "folder"
  echo ""
 
  if [ -d "$VERSION_FOLDER" ]; then
    
    # Copy section
    for FILE in $VERSION_FOLDER/* $VERSION_FOLDER/**/* ; do
      echo ""
      echo "Processing "${FILE}
      SKIP_FILE=0

      for EXCLUSION in ${EXCLUSIONS_ARRAY[*]}; do
        echo "Processing "$EXCLUSION "pattern on "${FILE}
        if [[ "$FILE" =~ .*"$EXCLUSION".* ]]; then
          SKIP_FILE=1
          echo $FILE will be skipped
        fi
      done

      if [[ -f "$FILE" ]] && [[ $SKIP_FILE -eq 0 ]]; then
        echo ""
        echo Loading $FILE
        echo ""
        ${DOCKER} exec -i ${APP_PROJECT_DOCKER_SERVER_NAME}-pg psql -v ON_ERROR_STOP=1 --username ${APP_PROJECT_DB_NAME} --dbname ${APP_PROJECT_DB_NAME} < $FILE
      else
        echo ""
        echo Skipping $FILE
        echo ""
      fi

    done  

  else
    echo "${VERSION_FOLDER} not found"
  fi

  # End version section 

done
