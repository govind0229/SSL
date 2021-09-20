#!/bin/bash
#############################################################################
#   Script  :   OpenSSL self-signed certificate            	            #
#   Use     :   Create Self-signed Server Certificate                       #
#   Author  :   Buzzworks <Govind.sharma@flexydial.com>                     #
#   Version :   Flexy 4.0						    #
#############################################################################
set -o nounset
DEBUG=false

# Colors
CO='\033[0m'
R='\033[0;31m'          
Gr='\033[0;32m'        
Ye='\033[0;33m'       
Cy='\033[0;36m'         

# Variables  
pass='flexydial'
Null=$(2> /dev/null);
SERIAL=`cat /dev/urandom | tr -dc '1-9' | fold -w 30 | head -n 1`
AP=$(ip route | grep '^default' | grep -oP '(?<=dev )[^ ]*');
HOST_IP=$(ip a s $AP ${Null}| grep -v "127.0.0.1" | awk '{ if ($1=="inet") { print $2 }}' | sed 's/\/.*//');

temclear(){
    rm -f buzzworks.config
    rm -rf buzzworks.db.*
    rm -f ${CONFIG}
}
fail (){
	rm -f ${HOST_IP}.*
}

clear
echo "--------------------------------------------";
echo -e "${R}\tOpenSSL self-signed certificate${CO}";
echo "--------------------------------------------";

    $DEBUG && echo "${SERIAL}"
    $DEBUG && echo -e "${Cy}Server IP${CO} ${HOST_IP}";

    if [ ! -f ${HOST_IP}.key ]; then
        openssl genrsa -out $HOST_IP.key 4096 &> /dev/null
    fi

# Fill the necessary certificate data
CONFIG="server-cert.conf"
cat >$CONFIG <<EOT
[ req ]
default_bits			= 4096
default_keyfile			= server.key
distinguished_name		= req_distinguished_name
string_mask			= nombstr
req_extensions			= v3_req
[ req_distinguished_name ]
countryName			= Country Name (2 letter code)
countryName_default		= MY
countryName_min			= 2
countryName_max			= 2
stateOrProvinceName		= State or Province Name (full name)
stateOrProvinceName_default	= Perak
localityName			= Locality Name (eg, city)
localityName_default		= Sitiawan
0.organizationName		= Organization Name (eg, company)
0.organizationName_default	= My Directory Sdn Bhd
organizationalUnitName		= Organizational Unit Name (eg, section)
organizationalUnitName_default	= Secure Web Server
commonName			= Common Name (eg, www.domain.com)
commonName_max			= 64
emailAddress			= Email Address
emailAddress_max		= 40
[ v3_req ]
nsCertType			= server
keyUsage 			= digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
basicConstraints		= CA:false
subjectKeyIdentifier		= hash
EOT

if [ ! -f ${HOST_IP}.csr ]; then

	CSR=$(openssl req -new  -subj "/C=IN/ST=Mumbai/L=Mumbai/O=Flexydial/OU=Solutions/CN=${HOST_IP}/emailAddress=help@flexydial.com" -config $CONFIG -key $HOST_IP.key -out $HOST_IP.csr &> /dev/null)

    if [ $? -ne 0 ]; then 
        $DEBUG && echo -e "${R} Error CSR ${CO}"
	    temclear; fail;
        exit 1
    fi

    if [ ! -f buzzworks.key -o ! -f buzzworks.crt ]; then
        $DEBUG && echo -e "${R} Error Root Certificate.${CO}"
        temclear; fail;
	    exit 1
    fi
fi
# Make sure environment exists

if [ ! -d buzzworks.db.certs ]; then
    mkdir buzzworks.db.certs
fi

if [ ! -f buzzworks.db.buzzworks.serial ]; then
    echo "$SERIAL" >buzzworks.db.buzzworks.serial
fi

if [ ! -f buzzworks.db.index ]; then
    cp /dev/null buzzworks.db.index
fi

# Create the CA requirement to sign the cert
cat >buzzworks.config <<EOT
[ ca ]
default_ca              = default_CA
[ default_CA ]
dir                     = .
certs                   = \$dir
new_certs_dir           = \$dir/buzzworks.db.certs
database                = \$dir/buzzworks.db.index
serial                  = \$dir/buzzworks.db.buzzworks.serial
certificate             = \$dir/buzzworks.crt
private_key             = \$dir/buzzworks.key
default_days            = 1825
default_crl_days        = 30
default_md              = sha256
preserve                = no
x509_extensions	    	= server_cert
policy                  = policy_anything
[ policy_anything ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional
[ server_cert ]
basicConstraints	    = CA:FALSE
subjectKeyIdentifier 	= hash
authorityKeyIdentifier	= keyid,issuer
keyUsage 		        = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName		    = @subject_alt_names

[ subject_alt_names ]
DNS.1 			= *.google.com
IP.1			= ${HOST_IP}
IP.2			= 127.0.0.1
IP.3			= ::1
EOT

Certi=$(openssl ca -config buzzworks.config -batch -passin pass:${pass} -out ${HOST_IP}.crt -infiles ${HOST_IP}.csr 2> /dev/null)

if [ $? -ne 0 ]; then
    $DEBUG && echo -e "${R} Error Server Cert ${CO}"
	temclear; fail;
    exit 1
fi

Verify=$(openssl verify -check_ss_sig -trusted_first -verify_ip ${HOST_IP} -CAfile buzzworks.crt ${HOST_IP}.crt | awk '{print $2}')

if [ $? -ne 0 ]; then
    $DEBUG && echo -e "${R} Error Cert Verify ${CO}"
	temclear; fail;
    exit 1
fi

cp -f ${HOST_IP}.crt /etc/pki/tls/certs/localhost.crt
cp -f ${HOST_IP}.key /etc/pki/tls/private/localhost.key
cp -f ${HOST_IP}.csr /etc/pki/tls/private/
install -d /etc/freeswitch/tls
cat ${HOST_IP}.crt ${HOST_IP}.key > /etc/freeswitch/tls/agent.pem
cat ${HOST_IP}.crt ${HOST_IP}.key > /etc/freeswitch/tls/wss.pem
cp -f buzzworks.crt /etc/freeswitch/tls/cafiles.pem


if [ $? -eq 0 ]; then
	    echo;echo -e "${Cy}Certificate${CO}\t\t[ ${Gr}${Verify}${CO} ]";echo;
	    temclear   
    else 
        echo;echo -e "${Cy}Certificate${CO}\t\t[ ${R}Failed${CO} ]";echo;
        temclear; fail;
        exit 1	    
fi

