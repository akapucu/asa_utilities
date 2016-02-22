# asa_utilities
A collection of utility scripts for managing an ASA

Tools contained in this repository:
* ACL_check
* asa_dump
* asa_put
* asa_ban
* asa_unban

Python libraries needed to run the scripts in this project:
* ciscoconfparse
* requests
* paramiko
* paramiko-expect - https://github.com/fgimian/paramiko-expect


### ACL_check
This script takes in a plaintext ASA config file (-f asa_config.txt), and outputs a list of object-groups, network objects, and access-list lines that will be applied to a packet matching the specified source and destination addresses (--source 192.168.0.0/24 --dest 8.8.8.8). It can also be used to match a specific acl name (--acl OUTSIDE-IN), and supports processing multiple source and destination addresses, either by CIDR notation (192.168.0.0/16) subnet (192.168.0.0 255.255.0.0) or by a simple single IP address (192.168.1.1). Multiple addresses or ranges can be specified by seperating them with a comma (--source 192.168.1.0/24,192.168.2.50)

### asa_dump
Dumps the running configuration of an ASA to a file.

### asa_put
Takes in the lines of a file and executes them on an ASA.

### asa_ban
Adds an IP address to an object-group on an ASA. By default, this is a group named "blacklisted_IPs" which should be in a deny rule.

### asa_unban
The opposite of the above command.
