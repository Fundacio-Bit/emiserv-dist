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

export NAMECA=${NGINX_SSL_NAMECA}
export NAMECLIENT=${NGINX_SSL_NAMECLIENT}
export NAMESERVER=${NGINX_SSL_NAMESERVER}
export ALIAS=${NGINX_SSL_DST_ALIAS}
export PASS=${NGINX_KEYSTORE_PASS}
export SSL_PASS=${NGINX_SSL_PASS}

PWD=$(cat ${SSL_PASS})

export OPENSSL_CONF=${NGINX_CONF_PATH}/${NGINX_OPENSSL_CONF_FILE}
export OPENSSL_CERTS_PATH=${APP_FILES_BASE_FOLDER}/assets/ssl

# Extraer DNAME de openssl.conf
DNAME=$(grep -E '^(CN|C|ST|L|O|OU|serialNumber|emailAddress)=' ${OPENSSL_CONF} | tr '\n' ',' | sed 's/,$//')

mkdir -p ${OPENSSL_CERTS_PATH}

COMMAND=${JAVA_HOME}/bin/keytool

KEYTOOL=$(command -v $COMMAND)
echo "$COMMAND at $KEYTOOL"

echo dname is ${DNAME}

touch ${OPENSSL_CERTS_PATH}/${NAMECA}.txt
touch ${OPENSSL_CERTS_PATH}/${NAMESERVER}.txt

rm ${OPENSSL_CERTS_PATH}/${NAMECA}*.*
rm ${OPENSSL_CERTS_PATH}/${NAMESERVER}*.*

echo "generating server key"
openssl genrsa -out ${OPENSSL_CERTS_PATH}/${NAMESERVER}.key 4096

echo "generating server csr"
openssl req -new -config ${OPENSSL_CONF} -key ${OPENSSL_CERTS_PATH}/${NAMESERVER}.key -out ${OPENSSL_CERTS_PATH}/${NAMESERVER}.csr

echo "extracting pem and key from NGINX_SSL_KEYSTORE.p12"



openssl pkcs12 -in ${NGINX_SSL_KEYSTORE} -nodes -out ${OPENSSL_CERTS_PATH}/${NAMECA}ca.pem -passin pass:${PWD}
openssl pkcs12 -in ${NGINX_SSL_KEYSTORE} -nocerts -nodes -out ${OPENSSL_CERTS_PATH}/${NAMECA}ca.key -passin pass:${PWD}

echo "generating server crt"
openssl x509 -req -CA ${OPENSSL_CERTS_PATH}/${NAMECA}ca.pem -CAkey ${OPENSSL_CERTS_PATH}/${NAMECA}ca.key -in ${OPENSSL_CERTS_PATH}/${NAMESERVER}.csr  -out ${OPENSSL_CERTS_PATH}/${NAMESERVER}.crt -days 1000 -CAcreateserial

echo "generating server pem"
openssl x509 -in ${OPENSSL_CERTS_PATH}/${NAMESERVER}.crt -inform PEM -out ${OPENSSL_CERTS_PATH}/${NAMESERVER}.pem -outform PEM
cat ${OPENSSL_CERTS_PATH}/${NAMESERVER}.key >> ${OPENSSL_CERTS_PATH}/${NAMESERVER}.pem


echo "generating jks"
$KEYTOOL -genkeypair -alias ${ALIAS} -keyalg RSA -keysize 4096 -dname "${DNAME}" -validity 1000 -keypass ${PASS} -keystore ${OPENSSL_CERTS_PATH}/${NAMESERVER}.jks -storepass ${PASS} -storetype JKS -noprompt

# echo "generating server store csr"
# $KEYTOOL -certreq -v -alias ${NAMESERVER} -keystore ${OPENSSL_CERTS_PATH}/${NAMESERVER}.jks -storepass ${PASS} -file ${OPENSSL_CERTS_PATH}/${NAMESERVER}keystore.csr

# echo "generating server cer"
# openssl x509 -req -CA ${OPENSSL_CERTS_PATH}/${NAMECA}ca.pem -CAkey ${OPENSSL_CERTS_PATH}/${NAMECA}ca.key -in ${OPENSSL_CERTS_PATH}/${NAMESERVER}keystore.csr -out ${OPENSSL_CERTS_PATH}/${NAMESERVER}keystore.cer -days 1000 -CAcreateserial -passin pass:${PASS}


chmod 755 ${OPENSSL_CERTS_PATH}/*



#$KEYTOOL -import -trustcacerts -keystore ${OPENSSL_CERTS_PATH}/${NAMESERVER}.jks -storepass ${PASS} -file ${OPENSSL_CERTS_PATH}/${NAMESERVER}keystore.cer -alias ${NAMESERVER}

#echo "import server cer"
#$KEYTOOL -import -keystore ${OPENSSL_CERTS_PATH}/${NAMESERVER}.jks -storepass ${PASS} -file ${OPENSSL_CERTS_PATH}/${NAMESERVER}keystore.cer -alias ${NAMESERVER}


#echo "importing crt and authority to emiserv.jks"
#$KEYTOOL -import -alias ${NAMECA} -file ${OPENSSL_CERTS_PATH}/${NAMECA}ca.pem -keystore ${OPENSSL_CERTS_PATH}/${NAMESERVER}.jks -storepass ${PASS} -noprompt
#$KEYTOOL -import -alias ${NAMESERVER} -file ${OPENSSL_CERTS_PATH}/${NAMESERVER}.crt -keystore ${OPENSSL_CERTS_PATH}/${NAMESERVER}.jks -storepass ${PASS} -noprompt

echo "import trustcacerts"
#$KEYTOOL -import -trustcacerts -alias ${NAMECA} -file ${OPENSSL_CERTS_PATH}/${NAMECA}ca.pem -keystore ${OPENSSL_CERTS_PATH}/${NAMESERVER}trust.jks -storepass ${PASS} -noprompt
$KEYTOOL -import -trustcacerts -alias ${NAMESERVER} -file ${OPENSSL_CERTS_PATH}/${NAMESERVER}.crt -keystore ${OPENSSL_CERTS_PATH}/${NAMESERVER}trust.jks -storepass ${PASS} -noprompt



chmod 755 ${OPENSSL_CERTS_PATH}/*
