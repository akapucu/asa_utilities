#!/bin/bash
ip=$1
date=$(date --date 'now + 5 minutes' | awk '{split($4, a, ":"); printf "%s %s %s:%02d:00", $2, $3, a[1],int(a[2]/5)*5}')
if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
	ssh user@xxxxx << EOF
	echo $ip >> /opt/scripts/DynamicBlockList/whitelistip.txt
	echo $ip >> /opt/scripts/DynamicBlockList/unblock.txt
	chmod 750 /opt/scripts/DynamicBlockList/unblock.txt
	chmod 750 /opt/scripts/DynamicBlockList/whitelistip.txt
EOF

echo "List Updated"
echo "IP address will be removed at $date"
fi
