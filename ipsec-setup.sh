#!/bin/bash

#@(#) IPSec Setup
# by Lech Taczkowski
#------------------------------------------------------------------------------
# This script can be useful for setting up IPSec server with Strongswan + IKEv2 + key authentication (Roadwarrior).
# It allows users to get secure access to another network over an unsecure network (Internet).

# Script has been written for my own personal use for the following setup, where the VPN server is behind a router and is NATted.
# The ports should be redirected on the router.
# There are so many possible scenarios of setting up StrongSwan with IKEv2. This script focuses on one of them.

# I hope it's going to be useful.
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

clear

# Debug mode
# set -x

# Name of the screen displayed on screen
SCRIPT_DESC="IPSec - Strongswan - IKEv2 setup script"
# Backup target location
BP_TARGET="/root/backups-ipsec"
# Probably this will never have to be changed
SYSCTL_CONF="/etc/sysctl.conf"
# Current date and time
CUR_DATE=$(date +'%m-%d-%Y-%H-%M-%S')
# SSH server port
SSHD_PORT=$(sshd -T | grep "^port " | cut -d " " -f2)
TMP="tmp$$"

if [[ $EUID -ne 0 ]]; then
   echo "● This script must be run as root" 1>&2
   exit 1
fi

        dpkg -s dialog >/dev/null 2>&1

        if [ ! $? -eq 0 ]; then
                echo "● Package \"dialog\" is required but is not installed. Installing ..."
                apt-get -yqq install dialog >/dev/null 2>&1
fi

CONFIG="${0}.conf"

# Check if the configuration file exists
if [ ! -f ${CONFIG} ]; then

	# Since the configuration file doesn't exist few questions will be asked and the answers saved to the file
	dialog --title "Configuration file" --backtitle "${SCRIPT_DESC}" --pause "Configuration file was not found, so few questions will be asked and the answers saved for later use." 10 70 10
	# Server's domain name (primary). This has to be only one domain.
	SERVER_DOMAIN_DN=$(dialog --title "Information required" --backtitle "${SCRIPT_DESC}" --inputbox "Enter the domain name under which the server will be available (example: secure.taczkowski.net):" 10 40 3>&1 1>&2 2>&3 3>&-)
	GLOBAL_SERVER_IP=$(dialog --title "Information required" --backtitle "${SCRIPT_DESC}" --inputbox "Enter the server's global IP address (example: 83.142.142.247):" 10 40 3>&1 1>&2 2>&3 3>&-)
        IFACE=$(dialog --title "Information required" --backtitle "${SCRIPT_DESC}" --inputbox "Enter the network interface name to be used for IPSec traffic:" 10 40 3>&1 1>&2 2>&3 3>&-)
	VPN_NET=$(dialog --title "Information required" --backtitle "${SCRIPT_DESC}" --inputbox "Enter the VPN network/net (example: 10.42.42.0/24):" 10 40 3>&1 1>&2 2>&3 3>&-)
	COUNTRY=$(dialog --title "Information required" --backtitle "${SCRIPT_DESC}" --inputbox "Enter the two letter country code in capital letters (example: PL):" 10 40 3>&1 1>&2 2>&3 3>&-)
	ORGANIZATION=$(dialog --title "Information required" --backtitle "${SCRIPT_DESC}" --inputbox "Enter the organization name for certs (example: Taczkowski.net):" 10 40 3>&1 1>&2 2>&3 3>&-)

echo "SERVER_DOMAIN_DN=\"${SERVER_DOMAIN_DN}\"
GLOBAL_SERVER_IP=\"${GLOBAL_SERVER_IP}\"
VPN_NET=\"${VPN_NET}\"
IFACE=\"${IFACE}\"
COUNTRY=\"${COUNTRY}\"
ORGANIZATION=\"${ORGANIZATION}\"" > ${CONFIG}

else
. ./${CONFIG}
fi

# Store menu options selected by the user
INPUT="/tmp/menu.${TMP}"

# Get text editor or fall back to vi_editor
VI_EDITOR=${EDITOR-vi}

# trap and delete temp files
trap "rm $INPUT; exit" SIGHUP SIGINT SIGTERM

pkg_setup()
{
        echo "10" | dialog --title "Reinstallation of required packages" --backtitle "${SCRIPT_DESC}" --gauge "Refreshing package information ..." 10 70 0
	apt-get update >/dev/null 2>&1

	echo "20" | dialog --title "Reinstallation of required packages" --backtitle "${SCRIPT_DESC}" --gauge "Removing packages ..." 10 70 0
# Packages for Debian Stretch
	apt-get -yqq purge haveged strongswan strongswan-pki libstrongswan-extra-plugins libcharon-extra-plugins >/dev/null 2>&1


	echo "40" | dialog --title "Reinstallation of required packages" --backtitle "${SCRIPT_DESC}" --gauge "Installing packages ..." 10 70 0
# Packages for Debian Stretch
	apt-get -yqq install haveged strongswan strongswan-pki libstrongswan-extra-plugins libcharon-extra-plugins >/dev/null 2>&1

	echo "80" | dialog --title "Reinstallation of required packages" --backtitle "${SCRIPT_DESC}" --gauge "Preparing ..." 10 70 0
	systemctl enable haveged >/dev/null 2>&1
	systemctl start haveged >/dev/null 2>&1
	echo "100" | dialog --title "Reinstallation of required packages" --backtitle "${SCRIPT_DESC}" --gauge "Ready." 10 70 0
}

backup_everything()
{
	echo "90" | dialog --title "Backup existing configuration" --backtitle "${SCRIPT_DESC}" --gauge "Backing up existing configuration ..." 10 70 0
	mkdir -p ${BP_TARGET} ${BP_TARGET}/etc_ipsec.d/private-${CUR_DATE} ${BP_TARGET}/etc_ipsec.d/cacerts-${CUR_DATE} ${BP_TARGET}/etc_ipsec.d/certs-${CUR_DATE} ${BP_TARGET}/etc_ipsec.d/p12-${CUR_DATE} ${BP_TARGET}${SYSCTL_CONF}-${CUR_DATE}
	if [ ! -d "/etc/ipsec.d" ] 
	then
		dialog --title "Backup existing configuration" --backtitle "${SCRIPT_DESC}" --pause "There is nothing that can be backed up. It seems the server has not been setup yet. Please run step 1 or 3 to at least installed the required packages." 10 70 3
	else	
	cp -Pr /etc/ipsec.d/private ${BP_TARGET}/etc_ipsec.d/private-${CUR_DATE}
	cp -Pr /etc/ipsec.d/cacerts ${BP_TARGET}/etc_ipsec.d/cacerts-${CUR_DATE}
	cp -Pr /etc/ipsec.d/certs ${BP_TARGET}/etc_ipsec.d/certs-${CUR_DATE}
	cp -Pr /etc/ipsec.d/p12 ${BP_TARGET}/etc_ipsec.d/p12-${CUR_DATE}
	cp -Pr /etc/ipsec.secrets ${BP_TARGET}/etc_ipsec.secrets-${CUR_DATE}
	cp -P /etc/ipsec.conf ${BP_TARGET}/ipsec.conf-${CUR_DATE}
	cp -P ${SYSCTL_CONF} ${BP_TARGET}${SYSCTL_CONF}-${CUR_DATE} 
	iptables-save > ${BP_TARGET}/iptables-backup-${CUR_DATE} >/dev/null 2>&1
	echo "100" | dialog --title "Backup existing configuration" --backtitle "${SCRIPT_DESC}" --gauge "Done." 10 70 0
	dialog --title "Backup existing configuration" --backtitle "${SCRIPT_DESC}" --pause "Existing configuration has been backed up (if it existed)." 10 70 3
fi
}

cert_setup()
{
	rm -fR /etc/ipsec.d/{private,cacerts,certs,p12}
	cd /etc/ipsec.d/
	mkdir -p {private,cacerts,certs,p12}
	chmod 755 {cacerts,certs,p12}
	chmod 700 private

	echo "5" | dialog --title "Setup certificate structure" --backtitle "${SCRIPT_DESC}" --gauge "Removing current directory structure and creating a new one (current directories will be backed up) ..." 10 70 0

	echo "20" | dialog --title "Setup certificate structure" --backtitle "${SCRIPT_DESC}" --gauge "Creating a self singed root CA private key ..." 10 70 0
	ipsec pki --gen --type rsa --size 4096 --outform der > private/strongswanKey.der
	chmod 600 private/strongswanKey.der
	echo "40" | dialog --title "Setup certificate structure" --backtitle "${SCRIPT_DESC}" --gauge "Generating a self signed root CA certificate of the private key ..." 10 75 0
	ipsec pki --self --ca --lifetime 3650 --in private/strongswanKey.der --type rsa --dn "C=${COUNTRY}, O=${ORGANIZATION}, CN=strongSwan Root CA" --outform der > cacerts/strongswanCert.der

	echo "60" | dialog --title "Setup certificate structure" --backtitle "${SCRIPT_DESC}" --gauge "Generating the VPN Host key. This is the keypair the VPN server host will use to authenticate itself to clients. First the private key ..." 10 80 0
	ipsec pki --gen --type rsa --size 4096 --outform der > private/vpnHostKey.der
	chmod 600 private/vpnHostKey.der

	echo "80" | dialog --title "Setup certificate structure" --backtitle "${SCRIPT_DESC}" --gauge "Generating the public key and use our earlier created root CA to sign the public key ..." 10 70 0
	ipsec pki --pub --in private/vpnHostKey.der --type rsa | ipsec pki --issue --lifetime 730 --cacert cacerts/strongswanCert.der --cakey private/strongswanKey.der --dn "C=${COUNTRY}, O=${ORGANIZATION}, CN=${SERVER_DOMAIN_DN}" --san ${SERVER_DOMAIN_DN} --san ${GLOBAL_SERVER_IP}  --san @${GLOBAL_SERVER_IP} --flag serverAuth --flag ikeIntermediate --outform der > certs/vpnHostCert.der

	echo "100" | dialog --title "Setup certificate structure" --backtitle "${SCRIPT_DESC}" --gauge "Done." 10 70 0
	dialog --title "Setup certificate structure" --backtitle "${SCRIPT_DESC}" --pause "Certificate structure has been setup successfully." 10 70 3
# ipsec listcerts can tell much about possible errors.
}

user_key()
{
	cd /etc/ipsec.d/
	KEY_NAME=$(dialog --title "Information required" --backtitle "${SCRIPT_DESC}" --inputbox "Enter the name of the user:" 8 40 3>&1 1>&2 2>&3 3>&-)	
	echo "20" | dialog --title "Generate new user's key" --backtitle "${SCRIPT_DESC}" --gauge "Generating private key ..." 10 70 0

	ipsec pki --gen --type rsa --size 2048 --outform der > private/${KEY_NAME}Key.der
	chmod 600 private/${KEY_NAME}Key.der

	echo "40" | dialog --title "Generate new user's key" --backtitle "${SCRIPT_DESC}" --gauge "Public key, signed by our root CA we generated ..." 10 70 0
	ipsec pki --pub --in private/${KEY_NAME}Key.der --type rsa | ipsec pki --issue --lifetime 730 --cacert cacerts/strongswanCert.der --cakey private/strongswanKey.der --dn "C=PL, O=${ORGANIZATION}, CN=${KEY_NAME}@${SERVER_DOMAIN_DN}" --san "${KEY_NAME}@${SERVER_DOMAIN_DN}" --san "${KEY_NAME}@${GLOBAL_SERVER_IP}" --outform der > certs/${KEY_NAME}Cert.der

	echo "60" | dialog --title "Generate new user's key" --backtitle "${SCRIPT_DESC}" --gauge "Preparing to generate P12 file ..." 10 70 0
	openssl rsa -inform DER -in private/${KEY_NAME}Key.der -out private/${KEY_NAME}Key.pem -outform PEM
	openssl x509 -inform DER -in certs/${KEY_NAME}Cert.der -out certs/${KEY_NAME}Cert.pem -outform PEM
	openssl x509 -inform DER -in cacerts/strongswanCert.der -out cacerts/strongswanCert.pem -outform PEM

	echo "80" | dialog --title "Generate new user's key" --backtitle "${SCRIPT_DESC}" --gauge "Generating P12 file ..." 10 70 0
	openssl pkcs12 -export -inkey private/${KEY_NAME}Key.pem -in certs/${KEY_NAME}Cert.pem -name "${KEY_NAME} - user certificate" -certfile cacerts/strongswanCert.pem -caname "strongSwan Root CA" -out p12/${KEY_NAME}.p12
	dialog --title "Generate new user's key" --backtitle "${SCRIPT_DESC}" --pause "All keys have been generated successfully.\nIt's important to copy them in a safe way to the client machine." 10 70 3
}


ipsec_config()
{
	echo "90" | dialog --title "Setup configuration file" --backtitle "${SCRIPT_DESC}" --gauge "Writing new IPSec configuration files ..." 10 70 0
	echo "# IPSec configuration file - generated on ${CUR_DATE} by ${SCRIPT_DESC}
config setup
        charondebug="ike 2, knl 2, cfg 2, net 2, esp 2, dmn 2, mgr 2"
        uniqueids=never

conn %default
        keyexchange=ikev2
        ike=aes128-sha256-modp3072
        # ike=chacha20poly1305-sha512-curve25519-prfsha512,aes256gcm16-sha384-prfsha384-ecp384,aes256-sha1-modp1024,aes128-sha1-modp1024,3des-sha1-modp1024!
        esp=aes128-sha256-modp3072
        # esp=chacha20poly1305-sha512,aes256gcm16-ecp384,aes256-sha256,aes256-sha1,3des-sha1!
        eap_identity=%identity
        forceencaps=yes
        fragmentation=yes
        reauth=yes
        forceencaps=no
        rekey=yes
        dpdaction=clear
        dpddelay=300s
        authby=pubkey
        left=%any
        leftid=${SERVER_DOMAIN_DN}
        leftsubnet=0.0.0.0/0
        leftcert=vpnHostCert.der
        leftsendcert=always
        right=%any
        rightid=%any
        rightsendcert=never
        rightsourceip=${VPN_NET}
        rightdns=8.8.8.8
        type=tunnel

conn IPSec-IKEv2
        keyexchange=ikev2
	auto=add" > /etc/ipsec.conf

	echo ": RSA vpnHostKey.der" > /var/lib/strongswan/ipsec.secrets.inc
	chown root:root /etc/ipsec.conf
	chmod 644 /etc/ipsec.conf
	echo "100" | dialog --title "Setup configuration file" --backtitle "${SCRIPT_DESC}" --gauge "Done." 10 70 0
        dialog --title "Setup configuration file" --backtitle "${SCRIPT_DESC}" --pause "Configuration file has been written." 10 70 3
	systemctl restart ipsec >/dev/null 2>&1
}

tunables_setup()
{
        echo "15" | dialog --title "Setting system tunables" --backtitle "${SCRIPT_DESC}" --gauge "Setting tunable parameters ..." 10 70 0

	# Removing lines that might exist
	grep -vE 'net.ipv4.ip_forward|net.ipv4.conf.all.accept_redirects|net.ipv4.conf.all.send_redirects|net.ipv4.conf.default.accept_redirects|net.ipv4.conf.default.send_redirects|net.ipv4.conf.default.rp_filter|net.ipv4.conf.default.accept_source_route|net.ipv4.icmp_ignore_bogus_error_responses' ${SYSCTL_CONF} > ${SYSCTL_CONF}-${TMP}

	# Setting new values
        echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
        echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
        echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
        echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
        echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf
        echo "net.ipv4.conf.default.rp_filter = 0" >> /etc/sysctl.conf
        echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
        echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf

	# Probably the line below is not necessary
	for vpn in /proc/sys/net/ipv4/conf/*; do echo 0 > $vpn/accept_redirects; echo 0 > $vpn/send_redirects; done >/dev/null 2>&1
	# Making new settings persistent
	sysctl -p >/dev/null 2>&1
        echo "100" | dialog --title "Setting system tunables" --backtitle "${SCRIPT_DESC}" --gauge "Done." 10 70 0
        dialog --title "Setting system tunables" --backtitle "${SCRIPT_DESC}" --pause "Tunable parameters have been set." 10 70 3
}

iptables_setup()
{
        echo "15" | dialog --title "Setting firewall rules" --backtitle "${SCRIPT_DESC}" --gauge "Setting iptables rules ..." 10 70 0

	# Installing required package
	apt-get -yqq install iptables-persistent

	# Flush firewall rules and counters
	iptables -F
	iptables -F -t nat
	iptables -Z
	rm -f /etc/iptables/rules.v?

        # Set permissive policy
        iptables -P INPUT ACCEPT
        iptables -P FORWARD ACCEPT

	# Don't interrupt existing connections and the ones initiated by the server
	iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

	if [ ! -z "${SSHD_PORT}" ]
	then
	        # Open SSH port for remote administration only if there is an SSH server running and configured
	        iptables -A INPUT -p tcp --dport ${SSHD_PORT} -j ACCEPT 
	fi

#	iptables -A INPUT -p tcp --dport 80 -j ACCEPT
#	iptables -A INPUT -p tcp --dport 19999 -j ACCEPT

	# Accept connections on the local loopback interface
	iptables -I INPUT 1 -i lo -p all -j ACCEPT

	# IPSec part - start

	iptables -A INPUT -p udp --dport  500 -j ACCEPT
	iptables -A INPUT -p udp --dport 4500 -j ACCEPT

	# forward ESP (Encapsulating Security Payload) traffic so the VPN clients will be able to connect. ESP provides additional security for our VPN packets as they're traversing untrusted networks
	iptables -A FORWARD --match policy --pol ipsec --dir in  --proto esp -s ${VPN_NET} -j ACCEPT
	iptables -A FORWARD --match policy --pol ipsec --dir out --proto esp -d ${VPN_NET} -j ACCEPT

	# VPN server will act as a gateway between the VPN clients and the internet. Since the VPN server will only have a single public IP address,
	# we will need to configure masquerading to allow the server to request data from the internet on behalf of the clients.
	# This will allow traffic to flow from the VPN clients to the internet, and vice-versa
	iptables -t nat -A POSTROUTING -s ${VPN_NET} -o ${IFACE} -m policy --pol ipsec --dir out -j ACCEPT
	iptables -t nat -A POSTROUTING -s ${VPN_NET} -o ${IFACE} -j MASQUERADE

	# To prevent IP packet fragmentation on some clients, we'll tell IPTables to reduce the size of packets by adjusting the packet's maximum segment size. This prevents issues with some VPN clients.
	iptables -t mangle -A FORWARD --match policy --pol ipsec --dir in -s ${VPN_NET} -o ${IFACE} -p tcp -m tcp --tcp-flags SYN,RST SYN -m tcpmss --mss 1361:1536 -j TCPMSS --set-mss 1360

	# IPSec part - end

	# Drop everything else
	iptables -A INPUT -j DROP
	iptables -A FORWARD -j DROP

	# Saving the changes
	iptables-save > /etc/iptables/rules.v4
}

service_autostart()
{
        echo "10" | dialog --title "Making services start automatically" --backtitle "${SCRIPT_DESC}" --gauge "Enabling autostart and starting services ..." 10 70 0
	systemctl enable strongswan >/dev/null 2>&1
	# Strongswan will be stopped in case it was already running
	systemctl stop strongswan >/dev/null 2>&1
	systemctl start strongswan >/dev/null 2>&1
        echo "100" | dialog --title "Making services start automatically" --backtitle "${SCRIPT_DESC}" --gauge "Service has been started and will start automatically during boot." 10 70 0
	sleep 1
        dialog --title "Making services start automatically" --backtitle "${SCRIPT_DESC}" --pause "Service has been started and will start automatically during boot." 10 70 3
        dialog --title "Services status" --backtitle "${SCRIPT_DESC}" --pause "`ipsec statusall`" 35 70 10
}

help_text()
{
TEXT="This script has been written to automate the setup of a secure IPSec server using Strongswan using IKEv2 and public key authentication.

If the configuration file doesn't exist, the script will ask a series of questions before it can start working and write the answers to the config. file. It will not ask again.

Menu items are described below:

● Full server setup from scratch - executes all steps required to setup a production-ready IPSec server (options: 2,3,4,6,8,9 and 10).
● Backup current configuration - backs up files and directories that are being altered in either of the steps and saves them to \"${BP_TARGET}\".
● Install/reinstall packages - purges and reinstalls packages required to setup the IPSec server
● Generate CA and server certificates - sets up all certificate related stuff without generating any client keys. This needs to be done by choosing
● option 7 from the menu.
● Generate new user key - generates set of files for the user (it adds a user to the system).
● Generate IPSec/Strongswan config - generates ipsec.conf file based on a predefined template.
● Edit ipsec.conf - this allows making manual changes to /etc/ipsec.conf. Changes will be overwritten after choosing option
\"Generate IPSec/Strongswan config\". After that ipsec reload is executed.
● Configure system tunables - there are system-wide options in /etc/sysctl.conf that must be modified for
the whole setup to work. The changes are applied immediately.
● Configure IPTables - sets up the firewall by applying rules required for IPSec to work as well
● IPTables monitor - monitors packets on the firewall
as some other, like opening SSH port. It will not disconnect existing
connections.
● Enable services - enables IPSec services to start on system boot and immediately.

"
	dialog --title "HELP" --backtitle "${SCRIPT_DESC}" --msgbox "${TEXT}" 40 75 
}

outro()
{
	dialog --title "Outro" --backtitle "${SCRIPT_DESC}" --infobox "Your server has been set up." 3 60
}

# Menu in infinite loop
while true
do

dialog --clear --backtitle "IPSec - Strongswan - IKEv2 setup script" \
--title "[ M E N U ]" \
--menu "Use the UP/DOWN keys to choose an option:\n\
" 12 60 4 \
1 "Full server setup from scratch" \
2 "Backup current configuration" \
3 "Install/reinstall packages" \
4 "Generate CA and server certificates" \
5 "Generate new user key" \
6 "Generate IPSec/Strongswan config" \
7 "Edit ipsec.conf" \
8 "Configure system tunables" \
9 "Configure IPTables" \
10 "IPTables monitor" \
11 "Enable services" \
12 "Help" \
Exit "Exit to the shell" 2>"${INPUT}"

menuitem=$(<"${INPUT}")
 
case $menuitem in
	1) backup_everything
	pkg_setup
	cert_setup
	ipsec_config
	tunables_setup
	iptables_setup
	service_autostart
	outro
	;;
	2) backup_everything;;
	3) pkg_setup;;
	4) cert_setup;;
	5) user_key;;
	6) ipsec_config;;
	7) ${VI_EDITOR} /etc/ipsec.conf;ipsec reload >/dev/null 2>&1;;
	8) tunables_setup;;
	9) iptables_setup;;
	10) watch -d -n 0.1 'iptables -L INPUT -v -n';;
        11) service_autostart;;
	12) help_text;;
	Exit) echo "Bye"; break;;
esac

done

# Cleanup 
[ -f $INPUT ] && rm $INPUT
