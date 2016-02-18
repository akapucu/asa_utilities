import re
from ciscoconfparse.ccp_util import IPv4Obj

RE_BARE_SUBNET = re.compile('(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?) (?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')

class ASA_ACL:
	""" This class is used for deciphering a Cisco Access
	Control List line. It takes in a string. Properties can
	be looked up with related attributes and functions"""

	name = None
	acl_type = None
	permission = None
	line = None
	protocol = None
	service_object = None
	source = None
	source_type = None
	dest = None
	dest_type = None
	remark = None

	text = None

	# this is the current index that we're using to process the ACL.
	# needs to be kept track of because of the way that different ACL
	# parameters can change the number of words in the ACL line
	index = 0


	def __init__(self, ACL_string):
		self.text = ACL_string

		# simple parsing methodology
		acl = ACL_string.split()
		# check for an actual acl
		if not acl[self.index] == "access-list":
			raise Exception('Not a cisco Access-list. First word does not match "access-list"')

		self.index += 1

		# acl_name
		self.name = acl[self.index]
		self.index += 1

		# determine if we have a specific line number
		if acl[self.index] == "line":
			self.line = acl[self.index + 1]
			self.index += 2
		else:
			self.line = None

		# acl_type
		self.acl_type = acl[self.index]
		self.index += 1

		# pass to the correct acl type processing function
		if self.acl_type == "extended":
			self.process_extended_acl(acl)
		elif self.acl_type == "remark":
			self.remark = ' '.join(acl[self.index:])
		else:
			raise Exception("Only extended access-list types are supported at this time")

	def process_extended_acl(self, acl):
		# logic branch for extended ACLs

		# should be either permit or deny
		self.permission = acl[self.index]
		self.index += 1

		# protocol processing
		if acl[self.index] == "object":
			self.protocol = "defined by object"
			self.service_object = acl[self.index + 1]
			self.index += 2
		elif acl[self.index] == "object-group":
			self.protocol = "defined by object-group"
			self.service_object = acl[self.index + 1]
			self.index += 2
		elif acl[self.index] == "tcp":
			self.protocol == "tcp"
			self.index += 1
		elif acl[self.index] == "udp":
			self.protocol == "udp"
			self.index += 1
		elif acl[self.index] == "ip":
			self.protocol == "ip"
			self.index += 1
		elif acl[self.index] == "icmp":
			self.protocol = "icmp"
			self.index += 1
		elif acl[self.index] == "eigrp":
			self.protocol = "eigrp"
			self.index += 1
		elif acl[self.index] == "esp":
			self.protocol = "esp"
			self.index += 1
		else:
			raise Exception("Unsupported protocol: " + str(acl[self.index]))


		# process the source
		new_index, self.source, self.source_type = self.extract_src_dest(acl, self.index)
		self.index = new_index + 1

		# process the destination
		new_index, self.dest, self.dest_type = self.extract_src_dest(acl, self.index)
		self.index = new_index + 1


	def extract_src_dest(self, acl, index):
		# this function extracts the source or destination. It expects a list that represents all the words in an access-list line,
		# and the index of the first word of the source or destination in that line. it will return a tuple of the index of the
		# last word in the source or destination, the IP, and the type of entry the IP is


		if acl[index] == "any":
			ip_address = "any"
			ip_type = "any"
		elif acl[index] == "object":
			ip_address = acl[index + 1]
			ip_type = "object"
			index += 1
		elif acl[index] == "object-group":
			ip_address = acl[index + 1]
			ip_type = "object-group"
			index += 1
		elif acl[index] == "host":
			ip_address = IPv4Obj(acl[index + 1])
			ip_type = "ip"
			index += 1
		elif RE_BARE_SUBNET.match(' '.join(acl[index : index + 2])):
			ip_address_string = ' '.join(acl[index: index + 2])
			ip_address = IPv4Obj(ip_address_string)
			ip_type = "ip"
			index += 1
		else:
			raise Exception("could not determine source/destination type:" + str(acl[index:]))

		return (index, ip_address, ip_type)

	#def process_object(obj):
