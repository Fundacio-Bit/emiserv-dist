#!/bin/bash

set -o nounset
set -o errexit

#### Description: Lists alias from jks keystore
#### Written by: Guillermo de Ignacio - gdeignacio@fundaciobit.org on 04-2021

# See https://docs.oracle.com/javase/8/docs/technotes/tools/unix/keytool.html#keytool_option_genkeypair

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
export PASS=${NGINX_KEYSTORE_PASS}
export SSL_PASS=${NGINX_SSL_PASS}

PWD=$(cat ${SSL_PASS})
echo Pass $PASS

export OPENSSL_CONF=${NGINX_CONF_PATH}/${NGINX_OPENSSL_CONF_FILE}
export OPENSSL_CERTS_PATH=${APP_FILES_BASE_FOLDER}/assets/ssl

# Extraer DNAME de openssl.conf
DNAME=$(grep -E '^(CN|C|ST|L|O|OU|serialNumber|emailAddress)=' ${OPENSSL_CONF} | tr '\n' ',' | sed 's/,$//')

mkdir -p ${OPENSSL_CERTS_PATH}

COMMAND=${JAVA_HOME}/bin/keytool

KEYTOOL=$(command -v $COMMAND)
echo "$COMMAND at $KEYTOOL"

echo dname is ${DNAME}

#rm ${OPENSSL_CERTS_PATH}/${NAMESERVER}*.*
#rm ${OPENSSL_CERTS_PATH}/${NAMECA}*.*

echo "generating keypair"
$KEYTOOL -genkeypair -keystore ${OPENSSL_CERTS_PATH}/${NAMESERVER}root.jks -alias ${NAMESERVER}root -ext bc:c -dname "${DNAME}" -validity 1000  -keypass ${PASS} -storepass ${PASS} -storetype JKS -noprompt
$KEYTOOL -genkeypair -keystore ${OPENSSL_CERTS_PATH}/${NAMESERVER}ca.jks -alias ${NAMESERVER}ca -ext bc:c -dname "${DNAME}" -validity 1000  -keypass ${PASS} -storepass ${PASS} -storetype JKS -noprompt
$KEYTOOL -genkeypair -keystore ${OPENSSL_CERTS_PATH}/${NAMESERVER}.jks -alias ${NAMESERVER} -dname "${DNAME}" -validity 1000  -keypass ${PASS} -storepass ${PASS} -storetype JKS -noprompt
 
echo "generating root pem"
$KEYTOOL -exportcert -keystore ${OPENSSL_CERTS_PATH}/${NAMESERVER}root.jks -alias ${NAMESERVER}root  -rfc -keypass ${PASS} -storepass ${PASS} -noprompt > ${OPENSSL_CERTS_PATH}/${NAMESERVER}root.pem 

echo "generating ca pem"
$KEYTOOL -certreq -storepass ${PASS} -keystore ${OPENSSL_CERTS_PATH}/${NAMESERVER}ca.jks  -alias ${NAMESERVER}ca | $KEYTOOL -gencert -storepass ${PASS}  -keypass ${PASS}  -noprompt -keystore ${OPENSSL_CERTS_PATH}/${NAMESERVER}root.jks  -alias ${NAMESERVER}root -ext BC=0 -rfc > ${OPENSSL_CERTS_PATH}/${NAMESERVER}ca.pem 
echo "importing ca pem"
#$KEYTOOL -importcert -keystore ${OPENSSL_CERTS_PATH}/${NAMESERVER}ca.jks -keypass ${PASS} -storepass ${PASS} -noprompt  -alias ${NAMESERVER}ca -file ${OPENSSL_CERTS_PATH}/${NAMESERVER}ca.pem 
 
echo "generating server pem"
$KEYTOOL -storepass ${PASS} -keystore ${OPENSSL_CERTS_PATH}/${NAMESERVER}.jks -certreq -alias ${NAMESERVER} -keypass ${PASS} -noprompt | $KEYTOOL -gencert -keypass ${PASS} -storepass ${PASS} -noprompt -keystore ${OPENSSL_CERTS_PATH}/${NAMESERVER}ca.jks  -alias ${NAMESERVER}ca -ext ku:c=dig,kE -rfc > ${OPENSSL_CERTS_PATH}/${NAMESERVER}.pem 
echo "importing server pem"
cat ${OPENSSL_CERTS_PATH}/${NAMESERVER}root.pem ${OPENSSL_CERTS_PATH}/${NAMESERVER}ca.pem ${OPENSSL_CERTS_PATH}/${NAMESERVER}.pem | $KEYTOOL -importcert -keystore ${OPENSSL_CERTS_PATH}/${NAMESERVER}.jks  -alias ${NAMESERVER} -keypass ${PASS} -storepass ${PASS} -noprompt


echo "extracting crt and key from pem"
openssl x509 -in ${OPENSSL_CERTS_PATH}/${NAMESERVER}.pem -out ${OPENSSL_CERTS_PATH}/${NAMESERVER}.crt -outform PEM
openssl rsa -in ${OPENSSL_CERTS_PATH}/${NAMESERVER}.pem -out ${OPENSSL_CERTS_PATH}/${NAMESERVER}.key -outform PEM



echo "importing crt and authority to emiserv.jks"
$KEYTOOL -import -alias ${NAMECA} -file ${OPENSSL_CERTS_PATH}/${NAMECA}ca.pem -keystore ${OPENSSL_CERTS_PATH}/${NAMESERVER}.jks -storepass ${PASS} -noprompt
$KEYTOOL -import -alias ${NAMESERVER} -file ${OPENSSL_CERTS_PATH}/${NAMESERVER}.crt -keystore ${OPENSSL_CERTS_PATH}/${NAMESERVER}.jks -storepass ${PASS} -noprompt

echo "import trustcacerts"
$KEYTOOL -import -trustcacerts -alias ${NAMECA} -file ${OPENSSL_CERTS_PATH}/${NAMECA}ca.pem -keystore ${OPENSSL_CERTS_PATH}/${NAMESERVER}trust.jks -storepass ${PASS} -noprompt
$KEYTOOL -import -trustcacerts -alias ${NAMESERVER} -file ${OPENSSL_CERTS_PATH}/${NAMESERVER}.crt -keystore ${OPENSSL_CERTS_PATH}/${NAMECLIENT}trust.jks -storepass ${PASS} -noprompt



# # echo "generating jks"
# $KEYTOOL -genkey -alias ${NAMESERVER} -keyalg RSA -keysize 4096 -dname "${DNAME}" -validity 1000 -keypass ${PASS} -keystore ${OPENSSL_CERTS_PATH}/${NAMESERVER}.jks -storepass ${PASS} -storetype JKS -noprompt

# # Extract .crt from JKS keystore
# $KEYTOOL -exportcert -alias ${NAMESERVER} -keystore ${OPENSSL_CERTS_PATH}/${NAMESERVER}.jks -storepass ${PASS} -file ${OPENSSL_CERTS_PATH}/${NAMESERVER}.crt

# $KEYTOOL -import -trustcacerts -alias ${NAMESERVER} -file ${OPENSSL_CERTS_PATH}/${NAMESERVER}.crt -keystore ${OPENSSL_CERTS_PATH}/${NAMESERVER}trust.jks -storepass ${PASS} -noprompt

# # Extract .key from JKS keystore
# $KEYTOOL -importkeystore -srckeystore ${OPENSSL_CERTS_PATH}/${NAMESERVER}.jks -srcalias ${NAMESERVER} -srcstorepass ${PASS} -destkeystore ${OPENSSL_CERTS_PATH}/${NAMESERVER}.p12 -deststoretype PKCS12 -deststorepass ${PASS}

# openssl pkcs12 -in ${OPENSSL_CERTS_PATH}/${NAMESERVER}.p12 -out ${OPENSSL_CERTS_PATH}/${NAMESERVER}_aes256.p12 -nodes -aes256 -passin pass:${PASS} -passout pass:${PASS}

# openssl pkcs12 -in ${OPENSSL_CERTS_PATH}/${NAMESERVER}_aes256.p12 -nocerts -nodes -out ${OPENSSL_CERTS_PATH}/${NAMESERVER}.key -passin pass:${PASS}

chmod 755 ${OPENSSL_CERTS_PATH}/*


# echo "generating genrsa"
# openssl genrsa -out ${OPENSSL_CERTS_PATH}/${NAMECA}ca.key -passout pass:${PASS} 4096
# echo "generating req new using config ${OPENSSL_CONF}"
# openssl req -new -config ${OPENSSL_CONF} -x509 -key ${OPENSSL_CERTS_PATH}/${NAMECA}ca.key -days 3560 -sha256 -out ${OPENSSL_CERTS_PATH}/${NAMECA}ca.pem -passin pass:${PASS}
# echo "generating rsa"
# openssl rsa -in ${OPENSSL_CERTS_PATH}/${NAMECA}ca.key -out ${OPENSSL_CERTS_PATH}/${NAMECA}ca.key -passin pass:${PASS}

# echo "generating server key"
# openssl genrsa -out ${OPENSSL_CERTS_PATH}/${NAMESERVER}.key -passout pass:${PASS} 4096

# echo "generating server crt"
# openssl req -new -config ${OPENSSL_CONF} -key ${OPENSSL_CERTS_PATH}/${NAMESERVER}.key -out ${OPENSSL_CERTS_PATH}/${NAMESERVER}.csr -passin pass:${PASS}

# echo "extracting pem and key from NGINX_SSL_KEYSTORE.p12"
# openssl pkcs12 -in ${NGINX_SSL_KEYSTORE} -nodes -out ${OPENSSL_CERTS_PATH}/ca.pem -passin pass:${PWD}
# openssl pkcs12 -in ${NGINX_SSL_KEYSTORE} -nocerts -nodes -out ${OPENSSL_CERTS_PATH}/ca.key -passin pass:${PWD}

# openssl x509 -req -CA ${OPENSSL_CERTS_PATH}/${NAMECA}ca.pem -CAkey ${OPENSSL_CERTS_PATH}/${NAMECA}ca.key -in ${OPENSSL_CERTS_PATH}/${NAMESERVER}.csr  -out ${OPENSSL_CERTS_PATH}/${NAMESERVER}.crt -days 1000 -CAcreateserial -passin pass:${PASS}

# openssl pkcs12 -export -inkey ${OPENSSL_CERTS_PATH}/${NAMESERVER}.key -in ${OPENSSL_CERTS_PATH}/${NAMESERVER}.crt -out ${OPENSSL_CERTS_PATH}/${NAMESERVER}.p12 -name ${NAMESERVER} -CAfile ${OPENSSL_CERTS_PATH}/ca.pem -caname ${NAMECA}  -password pass:${PASS}

# $KEYTOOL -importkeystore -srckeystore ${OPENSSL_CERTS_PATH}/${NAMESERVER}.p12 -srcstoretype PKCS12 -destkeystore ${OPENSSL_CERTS_PATH}/${NAMESERVER}.jks -deststoretype JKS -deststorepass ${PASS} -noprompt

# openssl x509 -req -CA ${NAMECA}ca.pem -CAkey ${NAMECA}ca.key -in ${NAMESERVER}.csr  -out ${NAMESERVER}.crt -days 1000 -CAcreateserial -passin pass:${PWD}

# echo "generating server pem"
# openssl x509 -in ${NAMESERVER}.crt -out ${NAMESERVER}.pem -outform PEM

# echo "generating server pem"
# openssl x509 -in ${NAMESERVER}.pem -out ${NAMESERVER}.der -outform DER

# openssl pkcs12 -export -inkey ${NAMESERVER}.key -in ${NAMESERVER}.crt -out ${NAMESERVER}.p12 -name ${NAMESERVER} -CAfile ${NAMECA}ca.pem -caname ${NAMECA} -passin pass:${PASS} -passout pass:${PASS} 




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

# Combina la clave privada y el certificado en un archivo PKCS12


# # Importa el archivo PKCS12 en el almacén de claves
# $KEYTOOL -importkeystore -srckeystore ${NAMESERVER}.p12 -srcstoretype PKCS12 -destkeystore ${NAMESERVER}.jks -deststoretype JKS -srcstorepass ${PASS} -deststorepass ${PASS} -noprompt

# echo "import trustcacerts"
# $KEYTOOL -import -trustcacerts -alias ${NAMECA} -file ${NAMECA}ca.pem -keystore ${NAMESERVER}trust.jks -storepass ${PASS} -noprompt
# $KEYTOOL -import -trustcacerts -alias ${NAMESERVER} -file ${NAMESERVER}.crt -keystore ${NAMESERVER}trust.jks -storepass ${PASS} -noprompt

# mv *.key ${OPENSSL_CERTS_PATH}/
# mv *.pem ${OPENSSL_CERTS_PATH}/
# mv *.csr ${OPENSSL_CERTS_PATH}/
# mv *.crt ${OPENSSL_CERTS_PATH}/
# mv *.der ${OPENSSL_CERTS_PATH}/
# mv *.p12 ${OPENSSL_CERTS_PATH}/
# mv *.jks ${OPENSSL_CERTS_PATH}/
# chmod 755 ${OPENSSL_CERTS_PATH}/*

# mv *.cer ${OPENSSL_CERTS_PATH}/
# mv *.jks ${OPENSSL_CERTS_PATH}/