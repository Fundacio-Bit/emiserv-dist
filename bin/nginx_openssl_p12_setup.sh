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
export SSL_PASS=${NGINX_SSL_PASS}
export OPENSSL_CONF=${NGINX_CONF_PATH}/${NGINX_OPENSSL_CONF_FILE}
export OPENSSL_CERTS_PATH=${APP_FILES_BASE_FOLDER}/assets/ssl

PASS=$(cat ${SSL_PASS})

# Extraer DNAME de openssl.conf
DNAME=$(grep -E '^(CN|C|ST|L|O|OU|serialNumber|emailAddress)=' ${OPENSSL_CONF} | tr '\n' ',' | sed 's/,$//')

mkdir -p ${OPENSSL_CERTS_PATH}

COMMAND=${JAVA_HOME}/bin/keytool

KEYTOOL=$(command -v $COMMAND)
echo "$COMMAND at $KEYTOOL"

echo dname is ${DNAME}

# echo "import keystore server"
$KEYTOOL -importkeystore -srckeystore ${NGINX_SSL_KEYSTORE} -destkeystore ${NAMESERVER}.jks -srcstoretype pkcs12 -deststoretype JKS -srcstorepass ${PASS} -deststorepass ${NGINX_KEYSTORE_PASS} -srcalias ${NGINX_SSL_SRC_ALIAS} -destalias ${NGINX_SSL_DST_ALIAS} -srckeypass ${PASS} -destkeypass ${PASS} -noprompt

# Extraer el certificado del keystore
$KEYTOOL -exportcert -keystore ${NAMESERVER}.jks -storepass ${NGINX_KEYSTORE_PASS} -alias ${NGINX_SSL_DST_ALIAS} -rfc -file ${NAMESERVER}.crt

# Extraer la clave privada del keystore
openssl pkcs12 -in ${NGINX_SSL_KEYSTORE} -nocerts -nodes -out ${NAMESERVER}.key -passin pass:${PASS}

# # Cambiar el cifrado a AES256
#openssl pkcs12 -in ${NGINX_SSL_KEYSTORE} -out ${NAMESERVER}.p12 -nodes -passin pass:${PASS} -passout pass:${PASS}

# Extraer el certificado
#echo comprobando
#openssl pkcs12 -info -in ${NAMESERVER}.p12 -noout

# Extraer el certificado
#openssl pkcs12 -in ${NAMESERVER}.p12 -nokeys -out ${NAMESERVER}.crt -passin pass:${PASS}


# echo "generating genrsa"
# openssl genrsa -out ${NAMECA}ca.key -aes256 -passout pass:${PASS} 4096
# echo "generating req new using config ${OPENSSL_CONF}"
# openssl req -new -config ${OPENSSL_CONF} -x509 -key ${NAMECA}ca.key -days 3560 -sha256 -out ${NAMECA}ca.pem -passin pass:${PASS}
# echo "generating rsa"
# openssl rsa -in ${NAMECA}ca.key -out ${NAMECA}ca.key -passin pass:${PASS}

# echo "generating server key"
# openssl genrsa -out ${NAMESERVER}.key 4096 # -aes256 -passout pass:${PASS} 

# echo "generating server crt"
# openssl req -new -config ${OPENSSL_CONF} -key ${NAMESERVER}.key -out ${NAMESERVER}.csr -passin pass:${PASS}
# openssl x509 -req -CA ${NAMECA}ca.pem -CAkey ${NAMECA}ca.key -in ${NAMESERVER}.csr  -out ${NAMESERVER}.crt -days 1000 -CAcreateserial -passin pass:${PASS}

# openssl pkcs12 -export -in ${NAMESERVER}.pem -inkey ${NAMESERVER}.key -out ${NAMESERVER}.p12 -name "${NAMESERVER}" -passin pass:${PASS} -passout pass:${PASS}

# echo "generating jks"
# $KEYTOOL -genkeypair -keyalg RSA -alias ${NAMESERVER} -keystore ${NAMESERVER}.jks -storepass ${PASS} -keypass ${PASS} -validity 1000 -dname "${DNAME}"

# echo "generating server csr"
# $KEYTOOL -certreq -v -alias ${NAMESERVER} -keystore ${NAMESERVER}.jks -storepass ${PASS} -file ${NAMESERVER}.csr

# echo "generating server cer"
# openssl x509 -req -CA ${NAMECA}ca.pem -CAkey ${NAMECA}ca.key -in ${NAMESERVER}.csr -out ${NAMESERVER}.cer -days 1000 -CAcreateserial -passin pass:${PASS}

# echo "import server pem"
# $KEYTOOL -import -keystore ${NAMESERVER}.jks -storepass ${PASS} -file ${NAMECA}ca.pem -alias ${NAMECA}rootca -noprompt

# echo "import server cer"
# $KEYTOOL -import -keystore ${NAMESERVER}.jks -storepass ${PASS} -file ${NAMESERVER}.cer -alias ${NAMESERVER}

# echo "import keystore server"
# $KEYTOOL -importkeystore -srckeystore ${NAMESERVER}.jks -destkeystore ${NAMESERVER}_RC2-40-CBC.p12 -srcstoretype JKS -deststoretype PKCS12 -srcstorepass ${PASS} -deststorepass ${PASS} -srcalias ${NAMESERVER} -destalias ${NAMESERVER} -srckeypass ${PASS} -destkeypass ${PASS} -noprompt

# # Cambiar el cifrado a AES256
# openssl pkcs12 -in ${NAMESERVER}_RC2-40-CBC.p12 -out ${NAMESERVER}.p12 -nodes -aes256 -passin pass:${PASS} -passout pass:${PASS}

# # Extraer el certificado
# openssl pkcs12 -in ${NAMESERVER}.p12 -nokeys -out ${NAMESERVER}.crt -passin pass:${PASS}

# # Extraer la clave privada
# openssl pkcs12 -in ${NAMESERVER}.p12 -nocerts -nodes -out ${NAMESERVER}.key -passin pass:${PASS}

# echo "import trustcacerts"
# $KEYTOOL -import -trustcacerts -alias ${NAMECA} -file ${NAMECA}ca.pem -keystore ${NAMESERVER}trust.jks -storepass ${PASS} -noprompt

# mv *.key ${OPENSSL_CERTS_PATH}/
# mv *.pem ${OPENSSL_CERTS_PATH}/
# mv *.csr ${OPENSSL_CERTS_PATH}/
# mv *.crt ${OPENSSL_CERTS_PATH}/
# mv *.p12 ${OPENSSL_CERTS_PATH}/
# mv *.cer ${OPENSSL_CERTS_PATH}/
mv *.jks ${OPENSSL_CERTS_PATH}/
# mv *.p12 ${OPENSSL_CERTS_PATH}/
mv *.crt ${OPENSSL_CERTS_PATH}/
mv *.key ${OPENSSL_CERTS_PATH}/