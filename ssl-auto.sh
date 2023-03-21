#!/bin/bash
#############################################################################
#   Script  :   OpenSSL self-signed certificate            	                #
#   Use     :   Create Self-signed CA Server Certificate                    #
#   Author  :   SSL <Govind_sharma@live.com>                                #
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
pass='selfgen'
Null=$(2> /dev/null);
SERIAL=`cat /dev/urandom | tr -dc '1-9' | fold -w 30 | head -n 1`
HOST_IP=$(ip route get 1 | sed 's/^.*src \([^ ]*\).*$/\1/;q')
PUBIP=$(curl https://ifconfig.me/ 2> /dev/null)

function temclear(){
    rm -f SSL.config
    rm -rf SSL.db.*
    rm -f ${CONFIG}
}
function fail(){
	rm -f ${@}.*
}

# CA Certificate
function ca(){

    echo "------------------------------------------------";
    echo -e "${R}\tOpenSSL self-signed CA certificate${CO}";
    echo "------------------------------------------------";

    if [ ! -f ca.key ]; then
        echo "";echo -e "$Gr No Root CA key round. Generating CA.key file$CO"
        openssl genrsa -des3 -out ca.key -passout pass:${pass} 4096 
        echo ""
    fi

    # Self-sign it.
    CONFIG="root-ca.conf"
    cat >$CONFIG <<EOT
    [ req ]
    default_bits			    = 4096
    default_keyfile			    = ca.key
    distinguished_name		    = req_distinguished_name
    x509_extensions			    = v3_ca
    string_mask			        = nombstr
    req_extensions			    = v3_req
    [ req_distinguished_name ]
    countryName			        = Country Name (2 letter code)
    countryName_default		    = MY
    countryName_min			    = 2
    countryName_max			    = 2
    stateOrProvinceName		    = State or Province Name (full name)
    stateOrProvinceName_default	= Perak
    localityName			    = Locality Name (eg, city)
    localityName_default		= Sitiawan
    0.organizationName		    = Organization Name (eg, company)
    0.organizationName_default	= My Directory Sdn Bhd
    organizationalUnitName		= Organizational Unit Name (eg, section)
    organizationalUnitName_default	= Certification Services Division
    commonName			        = Common Name (eg, MD Root CA)
    commonName_max			= 64
    emailAddress			= Email Address
    emailAddress_max		= 40
    [ v3_ca ]
    basicConstraints		= critical,CA:true
    subjectKeyIdentifier	= hash
    [ v3_req ]
    nsCertType              = objsign,email,server
EOT
    
    echo -e "$Gr Generating Self-sign the root CA...$CO"
    echo ""
    openssl req -new -x509 -days 3650 -subj "/C=IN/ST=DELHI NCR/L=NOIDA/O=AUTOMATION/OU=Solutions/CN=CA-Authority/emailAddress=govind.kumar@infinitylabs.in" -config  $CONFIG -key ca.key -out ca.crt --passin pass:${pass}

    rm -f $CONFIG
    echo -e "$Gr You Have Successfully Generated CA Certificates$CO"
    echo ""
    echo -e "CA Key         = $Gr ca.key$CO"
    echo -e "CA Certificate = $Gr ca.crt$CO"
    echo ""
}

# server certificate 
function server(){

    clear
    echo "--------------------------------------------";
    echo -e "${R}\tOpenSSL self-signed certificate${CO}";
    echo "--------------------------------------------";

        $DEBUG && echo "${SERIAL}"
        $DEBUG && echo -e "${Cy}Server IP${CO} ${@}";

        if [[ -z "${@}" ]]; then
            echo -e "${R}Server IP Not found${CO}";
            exit 1;
        fi

        if [ ! -f ${@}.key ]; then
            openssl genrsa -out $@.key 4096 &> /dev/null
        fi

    # Fill the necessary certificate data
    CONFIG="server-cert.conf"
    cat >$CONFIG <<EOT
    [ req ]
    default_bits			= 4096
    default_keyfile			= server.key
    distinguished_name		= req_distinguished_name
    string_mask			    = nombstr
    req_extensions			= v3_req
    [ req_distinguished_name ]
    countryName			    = Country Name (2 letter code)
    countryName_default		= MY
    countryName_min			= 2
    countryName_max			= 2
    stateOrProvinceName		= State or Province Name (full name)
    stateOrProvinceName_default	= Perak
    localityName			= Locality Name (eg, city)
    localityName_default	= Sitiawan
    0.organizationName		= Organization Name (eg, company)
    0.organizationName_default	= My Directory Sdn Bhd
    organizationalUnitName	    = Organizational Unit Name (eg, section)
    organizationalUnitName_default	= Secure Web Server
    commonName			    = Common Name (eg, www.domain.com)
    commonName_max			= 64
    emailAddress			= Email Address
    emailAddress_max		= 40
    [ v3_req ]
    nsCertType			    = server
    keyUsage 			    = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
    basicConstraints		= CA:false
    subjectKeyIdentifier	= hash
EOT

    if [ ! -f ${@}.csr ]; then

        CSR=$(openssl req -new  -subj "/C=IN/ST=Mumbai/L=Mumbai/O=XYZ/OU=Solutions/CN=${@}/emailAddress=default@default.com" -config $CONFIG -key $@.key -out $@.csr &> /dev/null)

        if [ $? -ne 0 ]; then 
            $DEBUG && echo -e "${R} Error CSR ${CO}"
            temclear; fail;
            exit 1
        fi

        if [ ! -f ca.key -o ! -f ca.crt ]; then
            $DEBUG && echo -e "${R} Error Root Certificate.${CO}"
            temclear; fail;
            exit 1
        fi
    fi

    # Make sure environment exists
    if [ ! -d SSL.db.certs ]; then
        mkdir SSL.db.certs
    fi

    if [ ! -f SSL.db.SSL.serial ]; then
        echo "$SERIAL" >SSL.db.SSL.serial
    fi

    if [ ! -f SSL.db.index ]; then
        cp /dev/null SSL.db.index
    fi

    # Create the CA requirement to sign the cert
    cat >SSL.config <<EOT
    [ ca ]
    default_ca              = default_CA
    [ default_CA ]
    dir                     = .
    certs                   = \$dir
    new_certs_dir           = \$dir/SSL.db.certs
    database                = \$dir/SSL.db.index
    serial                  = \$dir/SSL.db.SSL.serial
    certificate             = \$dir/ca.crt
    private_key             = \$dir/ca.key
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
    basicConstraints        = CA:FALSE
    subjectKeyIdentifier    = hash
    authorityKeyIdentifier  = keyid,issuer
    keyUsage                = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
    subjectAltName          = @subject_alt_names

    [ subject_alt_names ]
    DNS.1                    = localhost
    IP.1                    = $@
    IP.2                    = 127.0.0.1
    IP.3                    = ::1
EOT

    Certi=$(openssl ca -config SSL.config -batch -passin pass:${pass} -out ${@}.crt -infiles ${@}.csr 2> /dev/null)

    if [ $? -ne 0 ]; then
        $DEBUG && echo -e "${R} Error Server Cert ${CO}"
        temclear; fail;
        exit 1
    fi

    Verify=$(openssl verify -check_ss_sig -trusted_first -verify_ip ${@} -CAfile ca.crt ${@}.crt | awk '{print $2}')

    if [ $? -ne 0 ]; then
        $DEBUG && echo -e "${R} Error Cert Verify ${CO}"
        temclear; fail;
        exit 1
    fi

    if [ $? -eq 0 ]; then
            echo;echo -e "${Cy}Certificate${CO}\t\t[ ${Gr}${Verify}${CO} ]";echo;
            temclear   
        else 
            echo;echo -e "${Cy}Certificate${CO}\t\t[ ${R}Failed${CO} ]";echo;
            temclear; fail;
            exit 1	    
    fi

    if [[ ! -e "dhparam.pem" ]]; then
        sudo openssl dhparam -out dhparam.pem 4096
        cat dhparam.pem |sudo tee -a ${@}.crt
    fi

    # Deployment certificates.
    if [ -h "/etc/pki/tls/certs/localhost-chain.crt" ]; then
        sudo unlink /etc/pki/tls/certs/localhost-chain.crt
        sudo ln -s ${@}.csr /etc/pki/tls/certs/localhost-chain.crt
    fi
    sudo cp -f ${@}.crt /etc/pki/tls/certs/localhost.crt
    sudo cp -f ${@}.key /etc/pki/tls/private/localhost.key
    sudo cp -f dhparam.pem /etc/pki/tls/certs/dhparam.pem   
}

if [ -f "ca.crt" ]; then
    echo "File \"ca.crt\" exists"
else
    ca
fi

# Case condition for CA and Server Certificate.
TYPE=$@
case $TYPE in
    cloud|Cloud) 
    server $PUBIP
    ;;
    premise|local)
    server $HOST_IP
    ;;
esac
