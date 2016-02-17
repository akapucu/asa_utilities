#!/usr/bin/python3

# ./ACL_check.py -f <input_file> -s <subnet>
# This script inputs a cisco config file and a subnet or IP address, and outputs any relevant
# objects pertaining to access lists.
# brf2010@med.cornell.edu

from ciscoconfparse import CiscoConfParse, IOSCfgLine
from ciscoconfparse.ccp_util import IPv4Obj
import re
import sys
import pickle
import argparse


# regular expressions used throughout
RE_OBJECT_NETWORK = re.compile('^object network (\S+)$')
RE_OBJECT_GROUP = re.compile('^object-group network (\S+)$')
RE_HOST = re.compile('^ host\s(\S+)$')
RE_SUBNET = re.compile('^ subnet ([\S ]+)$')
RE_NETWORK_OBJECT_HOST = re.compile('^ network-object host (\S+)$')
RE_NETWORK_OBJECT_OBJECT = re.compile('^ network-object object (\S+)$')
RE_BARE_ACL_HOST = re.compile('host ((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))')
RE_BARE_SUBNET = re.compile('(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?) (?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')


# parse arguments and determine a course of action
parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter,
	description="Check for relevant ACLs in a cisco config",
	epilog=
"""Examples:\n\
	Check an IP against a cisco config file: ACL_check.py -f config -s 1.2.3.4\n\
	Generate a pickle file for faster lookups: ACL_check.py -f config -o pickle\n\
	Check IP against pickle file: ACL_check.py -p pickle -s 1.2.3.4
It is strongly advised to generate and use a pickle file to speed things up.""")
parser.add_argument('-s', help="subnet/IP to check", dest="subnet")
parser.add_argument('-f', help="input config file", dest="in_file")
parser.add_argument('-p', help="input pickle file", dest="pickle_file")
parser.add_argument('-o', help="output pickle file", dest="out_file")
parser.add_argument('-d', help="debug", dest="debug", action="store_true")
args = parser.parse_args()

debug=args.debug

if args.out_file and args.in_file:
	print("Generating pickle file. This can take some time with very large files. Try getting some coffee.")
	fh = open(args.out_file, 'wb')
	config = CiscoConfParse(args.in_file)
	pickle.dump(config, fh)
	print("Done.")
	sys.exit()

elif args.subnet:
	try:
		subnet = IPv4Obj(args.subnet)
	except:
		print("Invalid subnet/IP")
		if debug: print(args.subnet)
		sys.exit()
	if debug: print(subnet)
	if args.pickle_file:
		if debug: print("loading %s as pickle file" %(args.pickle_file))
		config = pickle.load(open(args.pickle_file, 'rb'))
	elif args.in_file:
		if debug: print("loading %s as plaintext file" %(args.in_file))
		config = CiscoConfParse(args.in_file)
	else:
		parser.error("One of -f or -p must be given with -s")
		sys.exit()

else:
	parser.error("One of -s or -o must be given.")


def is_substring_of_obj_list(obj_name, matched_objects):
	# helper function for checking substrings in an object list
	for obj in matched_objects:
		if obj_name in obj.text:
			return True
	return False


class ASA_ACL():
	""" This class is used for deciphering a Cisco Access
	Control List line. It takes in a string. Properties can
	be looked up with related functions"""

	acl_name = None
	acl_type = None
	acl_permission = None
	acl_line = None
	acl_protocol = None
	acl_service_object = None
	acl_source = None
	acl_source_type = None
	acl_dest = None

	acl_string = None

	# this is the current index that we're using to process the ACL.
	# needs to be kept track of because of the way that different ACL
	# parameters can change the number of words in the ACL line
	index = 0


	def init(ACL_string):
		self.acl_string = ACL_string

		# simple parsing methodology
		acl = ACL_string.split()
		# check for an actual acl
		if not acl[self.index] == "access-list":
			assert('Not a cisco Access-list. First word does not match "access-list"')
		self.index += 1

		# acl_name
		self.acl_name = acl[self.index]
		self.index += 1

		# acl_type
		self.acl_type = acl[self.index]
		self.index += 1

		# pass to the correct acl type processing function
		if self.acl_type == "extended":
			self.process_extended_acl(acl)
		elif not self.acl_type == "extended":
			assert("Only extended access-list types are supported at this time")

	def process_extended_acl(acl):
		# logic branch for extended ACLs

		# should be either permit or deny
		self.acl_permission = acl[self.index]
		self.index += 1

		# protocol processing
		if acl[self.index] == "object":
			self.acl_protocol = "defined by object"
			self.acl_service_object = acl[self.index + 1]
			self.index += 2
		elif acl[self.index] == "object-group":
			self.acl_protocol = "defined by object-group"
			self.acl_service_object = acl[self.index + 1]
			self.index += 2
		elif acl[self.index] == "tcp":
			self.acl_protocol == "tcp"
			self.index += 1
		elif acl[self.index] == "udp":
			self.acl_protocol == "udp"
			self.index += 1
		elif acl[self.index] == "ip":
			self.acl_protocol == "ip"
			self.index += 1
		elif acl[self.index] == "icmp":
			self.acl_protocol == "icmp":
			self.index += 1


		# process the source
		if acl[self.index] == "any":
			self.acl_source = "any"
			self.acl_source_type = "any"
			self.index += 1
		elif acl[self.index] == "object":
			self.acl_source == acl[self.index + 1]
			self.acl_source_type = "object"
			self.index += 2
		elif acl[self.index] == "object-group":
			self.acl_source == acl[self.index + 1]
			self.acl_source_type = "object-group"
			self.index += 2
		elif acl[self.index] == "host":
			self.acl_source == acl[self.index + 1]
			self.acl_source_type = "ip"
			self.index += 2
		elif RE_BARE_SUBNET.match(' '.join(acl[self.index : self.index + 1]):
			self.acl_source = "test"
			self.acl_source_type = "IPv4Obj"
			self.index += 2

		# process the destination

	def process_object(obj):



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

print("\nMatched object groups")
for obj in matched_groups:
	print(obj.text)
	for child in obj.children:
		print(child.text)

print("\nMatched ACLs")
for line in ACL_matches:
	print(line.text)
