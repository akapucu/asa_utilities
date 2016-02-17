import re
import ipaddress

RE_BARE_SUBNET = re.compile('(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?) (?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')

class ASA_ACL:
	""" This class is used for deciphering a Cisco Access
	Control List line. It takes in a string. Properties can
	be looked up with related attributes and functions"""

	acl_name = None
	acl_type = None
	acl_permission = None
	acl_line = None
	acl_protocol = None
	acl_service_object = None
	acl_source = None
	acl_source_type = None
	acl_dest = None
	acl_remark = None

	acl_string = None

	# this is the current index that we're using to process the ACL.
	# needs to be kept track of because of the way that different ACL
	# parameters can change the number of words in the ACL line
	index = 0


	def __init__(self, ACL_string):
		self.acl_string = ACL_string

		# simple parsing methodology
		acl = ACL_string.split()
		# check for an actual acl
		if not acl[self.index] == "access-list":
			raise Exception('Not a cisco Access-list. First word does not match "access-list"')

		self.index += 1

		# acl_name
		self.acl_name = acl[self.index]
		self.index += 1

		# determine if we have a specific line number
		if acl[self.index] == "line":
			self.acl_line = acl[self.index + 1]
			self.index += 2
		else:
			self.acl_line = None

		# acl_type
		self.acl_type = acl[self.index]
		self.index += 1

		# pass to the correct acl type processing function
		if self.acl_type == "extended":
			self.process_extended_acl(acl)
		elif self.acl_type == "remark":
			self.acl_remark = ' '.join(acl[self.index:])
		else:
			raise Exception("Only extended access-list types are supported at this time")

	def process_extended_acl(self, acl):
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
			self.acl_protocol = "icmp"
			self.index += 1


		# process the source
		new_index = self.extract_src_dest(acl, self.index)
		self.index = new_index

		# process the destination
		new_index = self.extract_src_dest(acl, self.index)
		self.index = new_index

	def extract_src_dest(self, acl, index):
		# this function extracts the source or destination. It expects a list that represents all the words in an access-list line,
		# and the index of the first word of the source or destination in that line. it will return the index of the
		# last word in the source or destination
		if acl[index] == "any":
			self.acl_source = "any"
			self.acl_source_type = "any"
		elif acl[index] == "object":
			self.acl_source = acl[index + 1]
			self.acl_source_type = "object"
		elif acl[index] == "object-group":
			self.acl_source = acl[index + 1]
			self.acl_source_type = "object-group"
			index += 1
		elif acl[index] == "host":
			ip_address = ipaddress.ip_network(acl[index + 1])
			self.acl_source = ip_address
			self.acl_source_type = "ip"
			index += 1
		elif RE_BARE_SUBNET.match(' '.join(acl[index : index + 1])):
			ip_address_string = ' '.join(acl[index: index + 1])
			ip_address_string.replace(' ', '/')
			ip_address = ipaddress.ip_network(ip_address_string)
			self.acl_source = ip_address
			self.acl_source_type = "ip"
			index += 1
		else:
			raise Exception("could not determine source/destination type:" + acl[index:])

		return index

	#def process_object(obj):
