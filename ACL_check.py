#!/usr/bin/python3

# ./ACL_check.py <config file> <subnet>
# This script inputs a cisco config file and a subnet or IP address, and outputs any relevant
# objects pertaining to access lists.

from ciscoconfparse import CiscoConfParse, IOSCfgLine
from ciscoconfparse.ccp_util import IPv4Obj
import re
import sys
import pickle

debug=False
use_pickle = True
pickle_file = "pickle"

subnet = IPv4Obj(sys.argv[2])
# subnet = IPv4Obj("143.104.88.0/24")



def is_substring_of_obj_list(obj_name, matched_objects):
	# helper function for checking substrings in an object list
	for obj in matched_objects:
		if obj_name in obj.text:
			return True
	return False

# regular expressions used throughout
RE_OBJECT_NETWORK = re.compile('^object network (\S+)$')
RE_OBJECT_GROUP = re.compile('^object-group network (\S+)$')
RE_HOST = re.compile('^ host\s(\S+)$')
RE_SUBNET = re.compile('^ subnet ([\S ]+)$')
RE_NETWORK_OBJECT_HOST = re.compile('^ network-object host (\S+)$')
RE_NETWORK_OBJECT_OBJECT = re.compile('^ network-object object (\S+)$')
RE_BARE_ACL_HOST = re.compile('host ((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))')
RE_BARE_SUBNET = re.compile('(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?) (?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')

# parse config file
if debug: print('parsing')
#config = CiscoConfParse(sys.argv[1])
if use_pickle:
	if debug: print('loading pickle')
	config = pickle.load(open(pickle_file, 'rb'))
else:
	config = CiscoConfParse(sys.argv[1])

# get network objects
if debug: print('finding network objects')
net_objs = config.find_objects(RE_OBJECT_NETWORK)

# match subnet(s) against network objects
if debug: print('matching network objects with specified subnet')
matched_objects = []
for obj in net_objs:
	#print(obj)
	#print(obj.children)
	for child in obj.children:
		# match any statically defined hosts
		ip_str = child.re_match(RE_HOST, default=None)
		if not ip_str:
			# try to match subnet definitions
			ip_str = child.re_match(RE_SUBNET, default=None)

		if ip_str:
			# if we found an IP address, convert to IPv4Obj and check if it belongs 
			# to the subnet we want, and vice-versa
			addr = IPv4Obj(ip_str)
			if addr in subnet:
				matched_objects.append(obj)
				break
			elif subnet in addr:
				matched_objects.append(obj)
				break
		# match any statically defined subnets

# get object groups
if debug: print('finding object groups')
obj_groups = config.find_objects(RE_OBJECT_GROUP)
matched_groups = []
for group in obj_groups:
	# accumulate children
	children = []
	for child in group.children:
		# match any previously discovered network objects
		network_object = child.re_match(RE_NETWORK_OBJECT_OBJECT, default=None)
		# match any statically defined hosts
		if not network_object:
			ip_str = child.re_match(RE_NETWORK_OBJECT_HOST, default=None)

		if network_object:
			if is_substring_of_obj_list(network_object, matched_objects):
				children.append(child)
				# break
		elif ip_str:
			addr = IPv4Obj(ip_str)
			if addr in subnet:
				children.append(child)
				# break

	# if there were children for this group, make a copy of all of them and
	# append them to matched_groups. this is to limit the noise that is output by
	# the group portion of the output section below; we only care why a given
	# object group was selected, not about all of its contents. 
	if children:
		# create new parent that is the same as the one we have but without children
		parent = IOSCfgLine(group.text)
		# and give it children that are pertinent to our query
		for child in children:
			parent.add_child(child)
		# then append it to our matched groups
		matched_groups.append(parent)

			
# get access list items
if debug: print("extracting access-list")
ACL = config.find_objects("^access-list ")
ACL_matches = []
for line in ACL:
	# check network objects
	for obj in matched_objects:
		obj_name = obj.re_match(RE_OBJECT_NETWORK)
		if obj_name in line.text:
			ACL_matches.append(line)
			break
	# check object groups
	for obj_group in matched_groups:
		obj_name = obj_group.re_match(RE_OBJECT_GROUP)
		if obj_name in line.text:
			ACL_matches.append(line)
			break
	# check bare IP addresses
	IPs = RE_BARE_ACL_HOST.findall(line.text)
	for IP in IPs:
		if IPv4Obj(IP) in subnet:
			ACL_matches.append(line)
			break
	# check bare subnets
	IPs = RE_BARE_SUBNET.findall(line.text)
	# if IPs:
	# 	print(line.text)
	for IP in IPs:
		try:
			if IPv4Obj(IP) in subnet:
				ACL_matches.append(line)
				break
		except:
			pass

print("Matched network objects")
for obj in matched_objects:
	print(obj.text)
	for child in obj.children:
		print(child.text)

print("\n\nMatched object groups")
for obj in matched_groups:
	print(obj.text)
	for child in obj.children:
		print(child.text)

print("\n\nMatched ACLs")
for line in ACL_matches:
	print(line.text)