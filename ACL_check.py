#!/usr/bin/python3

# ./ACL_check.py -f <input_file> -s <subnet>
# This script inputs a cisco config file and a subnet or IP address, and outputs any relevant
# objects pertaining to access lists.
# brf2010@med.cornell.edu

from ciscoconfparse import CiscoConfParse, IOSCfgLine
from ciscoconfparse.ccp_util import IPv4Obj
from ASA_ACL import ASA_ACL
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
	Check an IP against a cisco config file: ACL_check.py -f config -i 1.2.3.4\n\
	Generate a pickle file for faster lookups: ACL_check.py -f config -o pickle\n\
	Check IP against pickle file: ACL_check.py -p pickle -i 1.2.3.4\n\
	Check source IP only, from the Outside-IN access-list, against a config file: ACL_check.py -s 8.8.8.8 -a Outside-IN -p pickle
It is strongly advised to generate and use a pickle file to speed things up.""")


# group IP arguments together
ip_groups = parser.add_argument_group("IP address specification")
ip_groups.add_argument('-i', '--ip', help="subnet/IP to check", dest="ip")
ip_groups.add_argument('-s', '--source', help="source subnet/IP to check", dest="source")
ip_groups.add_argument('-d', '--dest', help="destination subnet/IP to check", dest="dest")
parser.add_argument('-a', '--acl', help="access-list name to check. if omitted, assumes all lists", dest="acl_name")
# pickle and plaintext inputs are mutually exclusive
input_group = parser.add_mutually_exclusive_group()
input_group.add_argument('-f', help="input config file", dest="in_file")
input_group.add_argument('-p', help="input pickle file", dest="pickle_file")
parser.add_argument('-o', help="output pickle file. used in conjunction with -f", dest="out_file")

parser.add_argument('--debug', help="debug", dest="debug", action="store_true")
args = parser.parse_args()

debug=args.debug


# check for conflicting arguments and raise errors as necessary
if args.out_file and (args.ip or args.source or args.dest):
	parser.error("out_file conflicts with -i, -s, and -d")
	sys.exit()
if args.pickle_file and args.out_file:
	parser.error("-p is only compatible with -f")
	sys.exit()
if args.ip and (args.source or args.dest):
	parser.error("-s and -d cannot be used in conjunction with -i")
	sys.exit()
if not (args.ip or args.source or args.dest or args.out_file):
	parser.error("One of [-i | -s | -d] or -o must be given.")
	sys.exit()
if not (args.in_file or args.pickle_file):
	parser.error("One of -f or -p is necessary")
	sys.exit()


# are we generating a pickle file from an input?
if args.out_file and args.in_file:
	print("Generating pickle file. This can take some time with very large files. Try getting some coffee.")
	fh = open(args.out_file, 'wb')
	config = CiscoConfParse(args.in_file)
	pickle.dump(config, fh)
	print("Done.")
	sys.exit()


# if we made it this far, we have an input! try to cast our inputs to things and see if shit explodes!
subnet = None
source = None
dest = None

if args.ip:
	# try to cast to IPv4Obj for syntax checking
	subnet = args.ip.split(',')
	for i,ip in enumerate(subnet):
		try:
			subnet[i] = IPv4Obj(ip)
		except:
			print('Invalid subnet/IP "%s"' %(ip))
			sys.exit()
if args.source:
	source = args.source.split(',')
	for i,ip in enumerate(source):
		try:
			source[i] = IPv4Obj(ip)
		except:
			print('Invalid subnet/IP "%s"' %(ip))
			sys.exit()
if args.dest:
	dest = args.dest.split(',')
	for i,ip in enumerate(dest):
		try:
			dest[i] = IPv4Obj(ip)
		except:
			print('Invalid subnet/IP "%s"' %(ip))
			sys.exit()

acl_name = args.acl_name

if debug: print(subnet)
if debug: print(source)
if debug: print(dest)
if debug: print(acl_name)

# are we loading from a pickle?
if args.pickle_file:
	if debug: print("loading %s as pickle file" %(args.pickle_file))
	config = pickle.load(open(args.pickle_file, 'rb'))
# if not, load in a file
elif args.in_file:
	if debug: print("loading %s as plaintext file" %(args.in_file))
	config = CiscoConfParse(args.in_file)




# functions and stuff

def is_substring_of_obj_list(obj_name, matched_objects):
	# helper function for checking substrings in an object list
	for obj in matched_objects:
		if obj_name in obj.text:
			return True
	return False

def match_network_objects(subnet, network_objects):
	# takes in an IPv4Obj and a list of network_objects. returns a list of network_objects
	# that match based on if the network_object address(es) are in the subnet or if the subnet
	# is in the network_object
	if debug: print('matching network objects with specified subnet')
	matched_objects = []
	for obj in network_objects:
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
			# TODO: match any statically defined subnets
	return matched_objects

def match_network_object_groups(subnet, object_groups, matched_objects):
	# takes in an IPv4Obj, a list of object_groups, and a list of network_objects that were previously matched.
	# iterates through the object_groups and returns a list of all object groups that matched either the subnet
	# or one of the objects in matched_objects
	matched_groups = []
	for group in object_groups:
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
	return matched_groups

def match_access_lists(ACL, acl_name, ips_to_match, src_or_dest, matched_objects, matched_groups):
	# takes in a list of ACL lines and matches them against the other provided arguments.
	# returns a list of matching lines.
	# ips_to_match must be a list of IPv4Obj
	# src_or_dest should be a string containing either "source", "dest", or "both"
	# src_or_dest specifies what ip_to_match should be tested against
	# matched_objects is a list of network objects
	# matched_groups is a list of object groups
	# TODO: support for specifying a known network-object or object-group to match against

	ACL_matches = []

	# match on both source and dest
	for line in ACL:
		# parse the ACL line so we can read the source and destination attributes
		parsed_acl = ASA_ACL(line.text)
		# check access-list name
		if (parsed_acl.name == acl_name) or not acl_name:
			# flag to figure out if we should skip to
			# the next line because we found something
			found = False
			# iterate thorugh the ips_to_match
			for ip_to_match in ips_to_match:

				# figure out if we're matching source, dest, or both
				if src_or_dest == "source" or src_or_dest == "both":
					# check network objects as source
					if parsed_acl.source_type == "object":
						for obj in matched_objects:
							obj_name = obj.re_match(RE_OBJECT_NETWORK)
							if obj_name == parsed_acl.source:
								ACL_matches.append(line)
								found = True
								break
					# check object-groups as source
					elif parsed_acl.source_type == "object-group":
						for obj_group in matched_groups:
							obj_name = obj_group.re_match(RE_OBJECT_GROUP)
							if obj_name == parsed_acl.source:
								ACL_matches.append(line)
								found = True
								break
					# any matches any
					elif parsed_acl.source_type == "any":
						ACL_matches.append(line)
						found = True
					# check for any IPv4Obj types as source
					elif parsed_acl.source_type == "ip":
						if (parsed_acl.source in ip_to_match) or (ip_to_match in parsed_acl.source):
							ACL_matches.append(line)
							found = True
				# check our flag here so we don't accidentally do a redundant operation when checking "both"
				if found:
					break

				# now do the whole thing again for destinations
				if src_or_dest == "dest" or src_or_dest == "both":
					# check network objects as dest
					if parsed_acl.dest_type == "object":
						for obj in matched_objects:
							obj_name = obj.re_match(RE_OBJECT_NETWORK)
							if obj_name == parsed_acl.dest:
								ACL_matches.append(line)
								found = True
								break
					# check object-groups as dest
					elif parsed_acl.dest_type == "object-group":
						for obj_group in matched_groups:
							obj_name = obj_group.re_match(RE_OBJECT_GROUP)
							if obj_name == parsed_acl.dest:
								ACL_matches.append(line)
								found = True
								break
					# any matches any
					elif parsed_acl.dest_type == "any":
						ACL_matches.append(line)
						found = True
					# check for any IPv4Obj types as dest
					elif parsed_acl.dest_type == "ip":
						if (parsed_acl.dest in ip_to_match) or (ip_to_match in parsed_acl.dest):
							ACL_matches.append(line)
							found = True

				# check our flag again, force a skip to next line in ACL if needed
				if found:
					break

	return ACL_matches

def union_list_of_lists(in_list):
	# some black magic to condense and deduplicate a list of lists down to one list.
	# returns a set
	out_list = set(in_list[0]).union(*in_list[1:])
	return out_list


# get all network objects
if debug: print('finding network objects')
net_objs = config.find_objects(RE_OBJECT_NETWORK)

# match ips, sources, and destinations against network objects
if subnet:
	matched_objects = []
	for ip in subnet:
		matched_objects.append(match_network_objects(ip, net_objs))
	matched_objects = union_list_of_lists(matched_objects)
if source:
	source_matched_objects = []
	for ip in source:
	 	source_matched_objects.append(match_network_objects(ip, net_objs))
	source_matched_objects = union_list_of_lists(source_matched_objects)
if dest:
	dest_matched_objects = []
	for ip in dest:
		dest_matched_objects.append(match_network_objects(ip, net_objs))
	dest_matched_objects = union_list_of_lists(dest_matched_objects)



# get all object groups
if debug: print('finding object groups')
object_groups = config.find_objects(RE_OBJECT_GROUP)

# match ips, sources, and destinations against object groups
# TODO: this can be made more efficient when parsing multiple ip addresses that were passed in through one parameter
# by not searching through the matched_objects lists every time
if subnet:
	matched_groups = []
	for ip in subnet:
		matched_groups.append(match_network_object_groups(subnet, object_groups, matched_objects))
	matched_groups = union_list_of_lists(matched_groups)
if source:
	source_matched_groups = []
	for ip in source:
		source_matched_groups.append(match_network_object_groups(source, object_groups, source_matched_objects))
	source_matched_groups = union_list_of_lists(source_matched_groups)
if dest:
	dest_matched_groups = []
	for ip in dest:
		dest_matched_groups.append(match_network_object_groups(dest, object_groups, dest_matched_objects))
	dest_matched_groups = union_list_of_lists(dest_matched_groups)



# get access list items
if debug: print("extracting access-list")
ACL = config.find_objects("^access-list ")


# match against access-list items
if subnet:
	ACL_matches = match_access_lists(ACL, acl_name, subnet, "both", matched_objects, matched_groups)
if source:
	source_ACL_matches = match_access_lists(ACL, acl_name, source, "source", source_matched_objects, source_matched_groups)
if dest:
	dest_ACL_matches = match_access_lists(ACL, acl_name, dest, "dest", dest_matched_objects, dest_matched_groups)


# merge source and dest results if we are checking for both, otherwise pick one
if source and dest:
	# set intersection between ACL lines that matched source and dest parameters
	ACL_matches = [line for line in source_ACL_matches if line in dest_ACL_matches]
	matched_objects = source_matched_objects.union(dest_matched_objects)
	matched_groups = source_matched_groups.union(dest_matched_groups)
elif source:
	ACL_matches = source_ACL_matches
	matched_objects = source_matched_objects
	matched_groups = source_matched_groups
elif dest:
	ACL_matches = dest_ACL_matches
	matched_objects = dest_matched_objects
	matched_groups = dest_matched_groups



# print results
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
