#!/bin/bash
#
# OpenVPN Road Warrior Installer
# Version:	1.1.0
# 
# Source:	https://github.com/Nyr/openvpn-install
# License:	MIT
# Author:	Nyr
# Date:		December 8, 2013
# 
# Source:	https://github.com/Lulech23/openvpn-setup
# Author:	Lucas Chasteen
# Date:		December 14, 2023
# 

##
# INITIALIZATION
##

# Ensure script is run with `bash` instead of `sh` (Debian)
if readlink /proc/$$/exe | grep -q "dash"; then
    echo 'This installer needs to be run with "bash", not "sh".'
    exit
fi

# Discard stdin (needed when running from a one-liner which includes newline)
read -N 999999 -t 0.001

# Ensure compatible system kernel (OpenVZ 6)
if [[ $(uname -r | cut -d "." -f 1) -eq 2 ]]; then
    echo "The system is running an old kernel which is incompatible with this installer."
    exit
fi

# Ensure OS is compatible/supported
if grep -qs "ubuntu" /etc/os-release; then
    os="ubuntu"
    os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
    group_name="nogroup"
elif [[ -e /etc/debian_version ]]; then
    os="debian"
    os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
    group_name="nogroup"
elif [[ -e /etc/almalinux-release || -e /etc/rocky-release || -e /etc/centos-release ]]; then
    os="centos"
    os_version=$(grep -shoE '[0-9]+' /etc/almalinux-release /etc/rocky-release /etc/centos-release | head -1)
    group_name="nobody"
elif [[ -e /etc/fedora-release ]]; then
    os="fedora"
    os_version=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)
    group_name="nobody"
else
    cat <<-EOF
		This installer seems to be running on an unsupported distribution.

		Supported distros include:
			* Ubuntu
			* Debian
			* AlmaLinux
			* Rocky Linux
			* CentOS
			* Fedora
	EOF
    exit
fi

if [[ "$os" == "ubuntu" && "$os_version" -lt 1804 ]]; then
    echo "Ubuntu 18.04 or higher is required to use this installer."
    exit
fi

if [[ "$os" == "debian" ]]; then
    if grep -q '/sid' /etc/debian_version; then
        echo "Debian Testing and Debian Unstable are unsupported by this installer."
        exit
    fi
    if [[ "$os_version" -lt 9 ]]; then
        echo "Debian 9 or higher is required to use this installer."
        exit
    fi
fi

if [[ "$os" == "centos" && "$os_version" -lt 7 ]]; then
    echo "CentOS 7 or higher is required to use this installer."
    exit
fi

# Ensure $PATH includes sbin directory
if ! grep -q sbin <<< "$PATH"; then
	echo '$PATH does not include sbin. Try using "su -" instead of "su".'
	exit
fi

# Ensure script is run with sufficient permissions
if [[ "$EUID" -ne 0 ]]; then
	echo "This installer needs to be run with superuser privileges."
	exit
fi

# Ensure TUN is available and enabled
if [[ ! -e /dev/net/tun ]] || ! ( exec 7<>/dev/net/tun ) 2>/dev/null; then
	echo "The system does not have the TUN device available. TUN needs to be"
	echo "enabled before running this installer."
	exit
fi

# Ensure client profile directory exists
client_dir="/etc/openvpn/client"
if [ ! -d "$client_dir" ]; then
	mkdir -p "$client_dir"
fi



##
# INSTALLATION
##

if [[ ! -e /etc/openvpn/server/server.conf ]]; then
	# Ensure wget or curl is installed
	if ! hash wget 2>/dev/null && ! hash curl 2>/dev/null; then
		echo "Wget is required to use this installer."
		read -n1 -r -p "Press any key to install Wget and continue..."
		apt-get update
		apt-get install -y wget
	fi

	clear
	echo "OpenVPN Server - Setup"

	# Get host IPv4 address
	if [[ $(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}') -eq 1 ]]; then
		# If system has a single IPv4, select it automatically
		ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
	else
		# Otherwise, prompt user for IPv4 selection
		echo
		echo "Which IPv4 address should be used?"

		ip4_count=$(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}')
		ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | nl -s ') '
		read -p "IPv4 address [1]: " ip4_number
		until [[ -z "$ip4_number" || "$ip4_number" =~ ^[0-9]+$ && "$ip4_number" -le "$ip4_count" ]]; do
			echo "$ip4_number: Invalid selection."
			read -p "IPv4 address [1]: " ip4_number
		done
		[[ -z "$ip4_number" ]] && ip4_number="1"
		ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n "$ip4_number"p)
	fi

	# If host IPv4 address is private, prompt user for public IPv4 selection (NAT)
	if echo "$ip" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
		echo
		echo "This server is behind NAT. What is the public IPv4 address or hostname?"

		# Get public IP and sanitize with grep
		get_public_ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<< "$(wget -T 10 -t 1 -4qO- "http://ip1.dynupdate.no-ip.com/" || curl -m 10 -4Ls "http://ip1.dynupdate.no-ip.com/")")
		read -p "Public IPv4 address / hostname [$get_public_ip]: " public_ip
		until [[ -n "$get_public_ip" || -n "$public_ip" ]]; do
			# If the checkip service is unavailable and user didn't provide input, ask again
			echo "Invalid input."
			read -p "Public IPv4 address / hostname: " public_ip
		done
		[[ -z "$public_ip" ]] && public_ip="$get_public_ip"
	fi

	# Get host IPv6 address, if any
	if [[ $(ip -6 addr | grep -c 'inet6 [23]') -eq 1 ]]; then
		# If system has a single IPv6, select it automatically
		ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}')
	elif [[ $(ip -6 addr | grep -c 'inet6 [23]') -gt 1 ]]; then
		# Otherwise, prompt user for IPv6 selection
		ip6_count=$(ip -6 addr | grep -c 'inet6 [23]')
		echo
		echo "Which IPv6 address should be used?"
		ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | nl -s ') '
		read -p "IPv6 address [1]: " ip6_number
		until [[ -z "$ip6_number" || "$ip6_number" =~ ^[0-9]+$ && "$ip6_number" -le "$ip6_count" ]]; do
			echo "$ip6_number: Invalid selection."
			read -p "IPv6 address [1]: " ip6_number
		done
		[[ -z "$ip6_number" ]] && ip6_number="1"
		ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | sed -n "$ip6_number"p)
	fi

	# Get VPN protocol
	echo
	echo "Which protocol should OpenVPN use?"
	echo "    1) UDP (recommended)"
	echo "    2) TCP"
	read -p "Protocol [1]: " protocol
	until [[ -z "$protocol" || "$protocol" =~ ^[12]$ ]]; do
		echo "$protocol: Invalid selection."
		read -p "Protocol [1]: " protocol
	done
	case "$protocol" in
		1|"")
			protocol=udp
		;;
		2)
			protocol=tcp
		;;
	esac

	# Get VPN port
	echo
	echo "What port should OpenVPN listen to?"
	read -p "Port [1194]: " port
	until [[ -z "$port" || ("$port" =~ ^[0-9]+$ && "$port" -le 65535 && "$port" -ne 5555) ]]; do
		echo "$port: Invalid or reserved port."
		read -p "Port [1194]: " port
	done
	[[ -z "$port" ]] && port="1194"

	# Get VPN DNS server
	echo
	echo "Which DNS server should OpenVPN clients use?"
	echo "    1) Current system resolvers"
	echo "    2) Google"
	echo "    3) CloudFlare"
	echo "    4) OpenDNS"
	echo "    5) Quad9"
	echo "    6) AdGuard"
	read -p "DNS server [1]: " dns
	until [[ -z "$dns" || "$dns" =~ ^[1-6]$ ]]; do
		echo "$dns: Invalid selection."
		read -p "DNS server [1]: " dns
	done


	##
	# DEPENDENCIES
	##

	echo
	echo "OpenVPN installation is ready to begin."

	# Also install a firewall, if not already available
	if ! systemctl is-active --quiet firewalld.service && ! hash iptables 2>/dev/null; then
		if [[ "$os" == "centos" || "$os" == "fedora" ]]; then
			firewall="firewalld"
		elif [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
			firewall="iptables"
		fi

		echo
		echo "Notice: $firewall, which is required to manage routing tables, will also be installed."
	fi
	echo
	read -n1 -r -p "Press any key to continue..."
	
	# If running inside a container, disable LimitNPROC to prevent conflicts
	if systemd-detect-virt -cq; then
		mkdir /etc/systemd/system/openvpn-server@server.service.d/ 2>/dev/null
		echo "[Service]" > /etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf
		echo "LimitNPROC=infinity" >> /etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf
	fi

	# Install OpenVPN and dependencies
	if [[ "$os" = "debian" || "$os" = "ubuntu" ]]; then
		apt-get update
		apt-get install -y --no-install-recommends openvpn openssl ca-certificates $firewall
	elif [[ "$os" = "centos" ]]; then
		yum install -y epel-release
		yum install -y openvpn openssl ca-certificates tar $firewall
	else # Fedora
		dnf install -y openvpn openssl ca-certificates tar $firewall
	fi

	# If firewalld was installed, enable it
	if [[ "$firewall" == "firewalld" ]]; then
		systemctl enable --now firewalld.service
	fi

	# Install local Easy-RSA
	easy_rsa_url='https://github.com/OpenVPN/easy-rsa/releases/download/v3.1.7/EasyRSA-3.1.7.tgz'
	mkdir -p /etc/openvpn/server/easy-rsa/
	{ wget -qO- "$easy_rsa_url" 2>/dev/null || curl -sL "$easy_rsa_url" ; } | tar xz -C /etc/openvpn/server/easy-rsa/ --strip-components 1
	chown -R root:root /etc/openvpn/server/easy-rsa/
	
	# Create the PKI, set up the CA and the server and client certificates
	cd /etc/openvpn/server/easy-rsa/ || exit
	./easyrsa --batch init-pki
	./easyrsa --batch build-ca nopass
	./easyrsa --batch --days=3650 build-server-full server nopass
	./easyrsa --batch --days=3650 build-client-full "$client" nopass
	./easyrsa --batch --days=3650 gen-crl

	# Move the stuff we need
	cp pki/ca.crt pki/private/ca.key pki/issued/server.crt pki/private/server.key pki/crl.pem /etc/openvpn/server

	# CRL is read with each client connection, while OpenVPN is dropped to nobody
	chown nobody:"$group_name" /etc/openvpn/server/crl.pem

	# Without +x in the directory, OpenVPN can't run a stat() on the CRL file
	chmod o+x /etc/openvpn/server/

	# Generate key for tls-crypt
	openvpn --genkey secret /etc/openvpn/server/tc.key

	# Create the DH parameters file using the predefined ffdhe2048 group
	cat <<-EOF > /etc/openvpn/server/dh.pem
		-----BEGIN DH PARAMETERS-----
		MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
		+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
		87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
		YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
		7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
		ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
		-----END DH PARAMETERS-----
	EOF


	##
	# SERVER.CONF
	##

	# Generate server.conf
	cat <<-EOF > /etc/openvpn/server/server.conf
		management localhost 5555
		local $ip
		port $port
		proto $protocol
		dev tun
		ca ca.crt
		cert server.crt
		key server.key
		dh dh.pem
		auth SHA512
		tls-crypt tc.key
		topology subnet
		keepalive 10 120
		user nobody
		group $group_name
		persist-key
		persist-tun
		verb 3
		crl-verify crl.pem
		server 10.8.0.0 255.255.255.0
	EOF

	# IPv6
	if [[ -z "$ip6" ]]; then
		echo 'push "redirect-gateway def1 bypass-dhcp"' >> /etc/openvpn/server/server.conf
	else
		echo 'server-ipv6 fddd:1194:1194:1194::/64' >> /etc/openvpn/server/server.conf
		echo 'push "redirect-gateway def1 ipv6 bypass-dhcp"' >> /etc/openvpn/server/server.conf
	fi
	echo 'ifconfig-pool-persist ipp.txt' >> /etc/openvpn/server/server.conf

	# DNS
	case "$dns" in
		1|"")
			# Locate the proper resolv.conf (needed for systems running systemd-resolved)
			if grep '^nameserver' "/etc/resolv.conf" | grep -qv '127.0.0.53' ; then
				resolv_conf="/etc/resolv.conf"
			else
				resolv_conf="/run/systemd/resolve/resolv.conf"
			fi

			# Obtain the resolvers from resolv.conf and use them for OpenVPN
			grep -v '^#\|^;' "$resolv_conf" | grep '^nameserver' | grep -v '127.0.0.53' | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | while read line; do
				echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server/server.conf
			done
		;;
		2)
			echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/server/server.conf
		;;
		3)
			echo 'push "dhcp-option DNS 1.1.1.1"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 1.0.0.1"' >> /etc/openvpn/server/server.conf
		;;
		4)
			echo 'push "dhcp-option DNS 208.67.222.222"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 208.67.220.220"' >> /etc/openvpn/server/server.conf
		;;
		5)
			echo 'push "dhcp-option DNS 9.9.9.9"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 149.112.112.112"' >> /etc/openvpn/server/server.conf
		;;
		6)
			echo 'push "dhcp-option DNS 94.140.14.14"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 94.140.15.15"' >> /etc/openvpn/server/server.conf
		;;
	esac
	echo 'push "block-outside-dns"' >> /etc/openvpn/server/server.conf
	if [[ "$protocol" = "udp" ]]; then
		echo "explicit-exit-notify" >> /etc/openvpn/server/server.conf
	fi


	##
	# FIREWALL
	##

	# Enable accessing local network devices for connected clients
	echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-openvpn-forward.conf
	echo 1 > /proc/sys/net/ipv4/ip_forward # (Don't wait for rebooot)
	if [[ -n "$ip6" ]]; then
		echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/99-openvpn-forward.conf
		echo 1 > /proc/sys/net/ipv6/conf/all/forwarding # (Don't wait for rebooot)
	fi

	# Configure firewalld (uses both temporary and permanent rules to avoid reload)
	if systemctl is-active --quiet firewalld.service; then

		##
		# FIREWALLD
		##

		# Set NAT for the VPN subnet
		firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
		firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"

		# IPv4
		firewall-cmd --add-port="$port"/"$protocol"
		firewall-cmd --zone=trusted --add-source=10.8.0.0/24
		firewall-cmd --permanent --add-port="$port"/"$protocol"
		firewall-cmd --permanent --zone=trusted --add-source=10.8.0.0/24

		# IPv6
		if [[ -n "$ip6" ]]; then
			firewall-cmd --zone=trusted --add-source=fddd:1194:1194:1194::/64
			firewall-cmd --permanent --zone=trusted --add-source=fddd:1194:1194:1194::/64
			firewall-cmd --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
			firewall-cmd --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
		fi
	else

		##
		# IPTABLES
		##

		# Get iptables paths
		iptables_path=$(command -v iptables)
		ip6tables_path=$(command -v ip6tables)

		# If running on OpenVZ, use iptables-legacy
		if [[ $(systemd-detect-virt) == "openvz" ]] && readlink -f "$(command -v iptables)" | grep -q "nft" && hash iptables-legacy 2>/dev/null; then
			iptables_path=$(command -v iptables-legacy)
			ip6tables_path=$(command -v ip6tables-legacy)
		fi

		# Create a service to set up persistent iptables rules
		cat <<-EOF  > /etc/systemd/system/openvpn-iptables.service
			[Unit]
			Before=network.target

			[Service]
			Type=oneshot
			ExecStart=$iptables_path -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $ip
			ExecStart=$iptables_path -I INPUT -p $protocol --dport $port -j ACCEPT
			ExecStart=$iptables_path -I FORWARD -s 10.8.0.0/24 -j ACCEPT
			ExecStart=$iptables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
			ExecStop=$iptables_path -t nat -D POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $ip
			ExecStop=$iptables_path -D INPUT -p $protocol --dport $port -j ACCEPT
			ExecStop=$iptables_path -D FORWARD -s 10.8.0.0/24 -j ACCEPT
			ExecStop=$iptables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
		EOF
		if [[ -n "$ip6" ]]; then
			cat <<-EOF >> /etc/systemd/system/openvpn-iptables.service
				ExecStart=$ip6tables_path -t nat -A POSTROUTING -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to $ip6
				ExecStart=$ip6tables_path -I FORWARD -s fddd:1194:1194:1194::/64 -j ACCEPT
				ExecStart=$ip6tables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
				ExecStop=$ip6tables_path -t nat -D POSTROUTING -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to $ip6
				ExecStop=$ip6tables_path -D FORWARD -s fddd:1194:1194:1194::/64 -j ACCEPT
				ExecStop=$ip6tables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT"
			EOF
		fi
		cat <<-EOF >> /etc/systemd/system/openvpn-iptables.service
			RemainAfterExit=yes

			[Install]
			WantedBy=multi-user.target
		EOF
		systemctl enable --now openvpn-iptables.service
	fi


	##
	# SELINUX
	##

	# Allow port in SELinux, if enabled
	if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 1194 ]]; then
		# Install semanage if not already present
		if ! hash semanage 2>/dev/null; then
			if [[ "$os_version" -eq 7 ]]; then
				# Centos 7
				yum install -y policycoreutils-python
			else
				# CentOS 8 or Fedora
				dnf install -y policycoreutils-python-utils
			fi
		fi
		semanage port -a -t openvpn_port_t -p "$protocol" "$port"
	fi


	##
	# CLIENT-COMMON.TXT
	##

	# Create client profile template
	cat <<-EOF > /etc/openvpn/server/client-common.txt
		client
		dev tun
		resolv-retry infinite
		nobind
		persist-key
		persist-tun
		remote-cert-tls server
		auth SHA512
		ignore-unknown-option block-outside-dns
		verb 3
		proto $protocol
		remote $ip $port
	EOF
	if [[ -n "$public_ip" ]]; then # (If NAT, support local or remote connection)
		echo "remote $public_ip $port" >> /etc/openvpn/server/client-common.txt
	fi


	##
	# FINALIZATION
	##
	
	# Enable and start the OpenVPN service
	systemctl enable --now openvpn-server@server.service

	# Show success message
	echo
	echo "Finished!"
	echo
	echo "Clients can now be added by running this script again."



##
# SERVER MANAGEMENT
##

else
	clear
	echo "OpenVPN Server - Setup"
	echo
	echo "Select an option:"
	echo "    1) Add a new client"
	echo "    2) Revoke an existing client"
	echo "    3) View connected clients"
	echo "    4) Uninstall OpenVPN"
	echo "    5) Exit"
	read -p "Option: " option
	until [[ "$option" =~ ^[1-5]$ ]]; do
		echo "$option: Invalid selection."
		read -p "Option: " option
	done
	case "$option" in
		1)
			##
			# ADD NEW CLIENT
			##

			# Get client name
			echo
			echo "Provide a name for the client:"
			read -p "Name: " client_unsanitized
			client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$client_unsanitized")
			while [[ -z "$client" || -e /etc/openvpn/server/easy-rsa/pki/issued/"$client".crt ]]; do
				echo "$client: Invalid name."
				read -p "Name: " client_unsanitized
				client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$client_unsanitized")
			done

			# Generate client key
			cd /etc/openvpn/server/easy-rsa/ || exit
			./easyrsa --batch --days=3650 build-client-full "$client" nopass

			# Generate client.ovpn, including defaults from client-common.txt
			{
				cat /etc/openvpn/server/client-common.txt
				echo "<ca>"
				cat /etc/openvpn/server/easy-rsa/pki/ca.crt
				echo "</ca>"
				echo "<cert>"
				sed -ne '/BEGIN CERTIFICATE/,$ p' /etc/openvpn/server/easy-rsa/pki/issued/"$client".crt
				echo "</cert>"
				echo "<key>"
				cat /etc/openvpn/server/easy-rsa/pki/private/"$client".key
				echo "</key>"
				echo "<tls-crypt>"
				sed -ne '/BEGIN OpenVPN Static key/,$ p' /etc/openvpn/server/tc.key
				echo "</tls-crypt>"
			} > "$client_dir/$client.ovpn"

			# Change ownership to default user to allow export
			chown 1000:1000 "$client_dir/$client.ovpn"
			echo
			echo -e "Added client $client. Client profile is available at: $client_dir/$client.ovpn"
			exit
		;;
		2)
			##
			# REVOKE EXISTING CLIENT
			##

			# Get available clients
			number_of_clients=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep -c "^V")
			if [[ "$number_of_clients" = 0 ]]; then
				echo
				echo "There are no existing clients!"
				exit
			fi

			# Get client to revoke
			echo
			echo "Select the client to revoke:"
			tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
			read -p "Client: " client_number
			until [[ "$client_number" =~ ^[0-9]+$ && "$client_number" -le "$number_of_clients" ]]; do
				echo "$client_number: Invalid selection."
				read -p "Client: " client_number
			done
			client=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$client_number"p)
			echo
			read -p "Confirm $client revocation? [y/N]: " revoke
			until [[ "$revoke" =~ ^[yYnN]*$ ]]; do
				echo "$revoke: Invalid selection."
				read -p "Confirm $client revocation? [y/N]: " revoke
			done

			# Revoke client
			if [[ "$revoke" =~ ^[yY]$ ]]; then
				# Remove associated keys
				cd /etc/openvpn/server/easy-rsa/ || exit
				./easyrsa --batch revoke "$client"
				./easyrsa --batch --days=3650 gen-crl
				rm -f /etc/openvpn/server/crl.pem
				cp /etc/openvpn/server/easy-rsa/pki/crl.pem /etc/openvpn/server/crl.pem
				chown nobody:$group_name /etc/openvpn/server/crl.pem # (CRL is read with each client connection, when OpenVPN is dropped to nobody)

				# Remove client profile
				rm -f "$client_dir/$client.ovpn"

				echo
				echo "$client revoked!"
			else
				# Otherwise cancel
				echo
				echo "$client revocation aborted!"
			fi
			exit
		;;
		3)
			##
			# VIEW CONNECTED CLIENTS
			##

			clear
			while true; do
				output=$(echo "status 3" | nc -w 1 localhost 5555 | awk -F'\t' 'BEGIN { print "Common Name,Real Address,Virtual Address,Bytes Received,Bytes Sent,Connected Since,Username,Data Channel Cipher" } $1 == "CLIENT_LIST" { gsub(/^[ \t]+|[ \t]+$/, "", $2); gsub(/^[ \t]+|[ \t]+$/, "", $3); gsub(/^[ \t]+|[ \t]+$/, "", $4); gsub(/^[ \t]+|[ \t]+$/, "", $6); gsub(/^[ \t]+|[ \t]+$/, "", $7); gsub(/^[ \t]+|[ \t]+$/, "", $8); gsub(/^[ \t]+|[ \t]+$/, "", $9); gsub(/^[ \t]+|[ \t]+$/, "", $13); print $2 "," $3 "," $4 "," $6 "," $7 "," $8 "," $9 "," $13 }' | column -t -s,)
				clear
				echo "OpenVPN Server - Setup"
				echo
				echo "Refreshing status every 3 seconds. Press Ctrl + C to exit"
				echo
				echo "$output"
				sleep 3
			done


			echo
			echo "status 3" | nc -w 1 localhost 5555 | awk -F'\t' 'BEGIN { print "Common Name,Real Address,Virtual Address,Bytes Received,Bytes Sent,Connected Since,Username,Data Channel Cipher" } $1 == "CLIENT_LIST" { gsub(/^[ \t]+|[ \t]+$/, "", $2); gsub(/^[ \t]+|[ \t]+$/, "", $3); gsub(/^[ \t]+|[ \t]+$/, "", $4); gsub(/^[ \t]+|[ \t]+$/, "", $6); gsub(/^[ \t]+|[ \t]+$/, "", $7); gsub(/^[ \t]+|[ \t]+$/, "", $8); gsub(/^[ \t]+|[ \t]+$/, "", $9); gsub(/^[ \t]+|[ \t]+$/, "", $13); print $2 "," $3 "," $4 "," $6 "," $7 "," $8 "," $9 "," $13 }' | column -t -s,
			echo
			exit
		;;
		4)
			##
			# UNINSTALL OPENVPN
			##

			echo
			read -p "Confirm OpenVPN removal? [y/N]: " remove
			until [[ "$remove" =~ ^[yYnN]*$ ]]; do
				echo "$remove: Invalid selection."
				read -p "Confirm OpenVPN removal? [y/N]: " remove
			done
			if [[ "$remove" =~ ^[yY]$ ]]; then
				port=$(grep '^port ' /etc/openvpn/server/server.conf | cut -d " " -f 2)
				protocol=$(grep '^proto ' /etc/openvpn/server/server.conf | cut -d " " -f 2)
				if systemctl is-active --quiet firewalld.service; then
					ip=$(firewall-cmd --direct --get-rules ipv4 nat POSTROUTING | grep '\-s 10.8.0.0/24 '"'"'!'"'"' -d 10.8.0.0/24' | grep -oE '[^ ]+$')
					# Using both permanent and not permanent rules to avoid a firewalld reload.
					firewall-cmd --remove-port="$port"/"$protocol"
					firewall-cmd --zone=trusted --remove-source=10.8.0.0/24
					firewall-cmd --permanent --remove-port="$port"/"$protocol"
					firewall-cmd --permanent --zone=trusted --remove-source=10.8.0.0/24
					firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
					firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
					if grep -qs "server-ipv6" /etc/openvpn/server/server.conf; then
						ip6=$(firewall-cmd --direct --get-rules ipv6 nat POSTROUTING | grep '\-s fddd:1194:1194:1194::/64 '"'"'!'"'"' -d fddd:1194:1194:1194::/64' | grep -oE '[^ ]+$')
						firewall-cmd --zone=trusted --remove-source=fddd:1194:1194:1194::/64
						firewall-cmd --permanent --zone=trusted --remove-source=fddd:1194:1194:1194::/64
						firewall-cmd --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
						firewall-cmd --permanent --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
					fi
				else
					systemctl disable --now openvpn-iptables.service
					rm -f /etc/systemd/system/openvpn-iptables.service
				fi
				if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 1194 ]]; then
					semanage port -d -t openvpn_port_t -p "$protocol" "$port"
				fi
				systemctl disable --now openvpn-server@server.service
				rm -f /etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf
				rm -f /etc/sysctl.d/99-openvpn-forward.conf
				if [[ "$os" = "debian" || "$os" = "ubuntu" ]]; then
					rm -rf /etc/openvpn/server
					apt-get remove --purge -y openvpn
				else
					# Else, OS must be CentOS or Fedora
					yum remove -y openvpn
					rm -rf /etc/openvpn/server
				fi
				echo
				echo "OpenVPN removed!"
			else
				echo
				echo "OpenVPN removal aborted!"
			fi
			exit
		;;
		5)
			##
			# EXIT
			##

			exit
		;;
	esac
fi
