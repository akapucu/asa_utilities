import re

RE_BARE_SUBNET = re.compile('(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?) (?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')

class ASA_ACL:
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


	def __init__(self, ACL_string):
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
		if acl[self.index] == "any":
			self.acl_source = "any"
			self.acl_source_type = "any"
			self.index += 1
		elif acl[self.index] == "object":
			self.acl_source = acl[self.index + 1]
			self.acl_source_type = "object"
			self.index += 2
		elif acl[self.index] == "object-group":
			self.acl_source = acl[self.index + 1]
			self.acl_source_type = "object-group"
			self.index += 2
		elif acl[self.index] == "host":
			self.acl_source = acl[self.index + 1]
			self.acl_source_type = "ip"
			self.index += 2
		elif RE_BARE_SUBNET.match(' '.join(acl[self.index : self.index + 1])):
			self.acl_source = "test"
			self.acl_source_type = "IPv4Obj"
			self.index += 2

		# process the destination

	#def process_object(obj):
