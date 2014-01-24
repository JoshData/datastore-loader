# CKAN Actions API Python Client Library.
#
# Written by the HealthData.gov team.
# As a work of the United States Government this file is
# in the public domain.
#
# Examples:
# 
# from ckan_client import CkanClient
#
# ckan = CkanClient("http://hub.healthdata.gov", "API_KEY")
#
# print ckan.action("package_list", {})

import urllib2, json

class CkanApiError(Exception):
	def __init__(self, err_type, msg):
		super(CkanApiError, self).__init__(msg)
		self.err_type = err_type

class CkanAccessDenied(CkanApiError):
	def __init__(self, err_type, msg):
		super(CkanAccessDenied, self).__init__(err_type, msg)

class CkanNotFound(CkanApiError):
	def __init__(self, err_type, msg):
		super(CkanNotFound, self).__init__(err_type, msg)

class CkanClient:
	
	def __init__(self, base_url, api_key):
		self.base_url = base_url
		self.api_key = api_key
	
	def action(self, action, params, squash_errors_if=None):
		# Invoke a CKAN API action.
		
		# Build the request.	
		request = urllib2.Request(
			"%s/api/3/action/%s" % (self.base_url, action),
			json.dumps(params))
		request.add_header("Content-Type", 'application/json')
		request.add_header("Authorization", self.api_key)
		
		# Execute the request.
		try:
			response = urllib2.urlopen(request)
		except urllib2.HTTPError as e:
			# HTTPError is a special exception that can be
			# treated as an HTTP response object. We'll do
			# an error check below.
			response = e
		
		# If the response was OK, parse the JSON and return
		# just the "result" part of the response.
		if response.getcode() == 200:
			return json.load(response)["result"]
			
		# Call failed. Raise an exception with an informative
		# error message.
		
		response_data = response.read()
		try:
			# Attempt to load the response as JSON.
			msg = json.loads(response_data)
			
			# Allow the caller to prevent the raising of an exception.
			# Pass the response JSON object to the error handler, and
			# if it returns True then we'll silently ignore the error
			# and return None.
			if squash_errors_if:
				if squash_errors_if(msg["error"]):
					return None
					
			# If the response JSON has an "error" key, get error
			# information from there.
			msg = msg["error"]
			
			if "__type" in msg and "message" in msg:
				err_type = msg["__type"]
				msg = msg["message"]
			else:
				# Or as a fallback, reformat the error value back into JSON
				# so we have a string.			
				err_type = "unknown"
				msg = json.dumps(msg, sort_keys=True, indent=4) 
		except:
			# If we can't decode the response as JSON, use the raw
			# response as the error message.
			err_type = "unknown"
			msg = response_data
			
		if response.getcode() == 403:
			# Custom message for 403.
			raise CkanAccessDenied(err_type, "Permission denied. CKAN indicated the API key was not valid for modifying the resource. (%s)" % msg)
		elif response.getcode() == 404:
			# Custom message for 404.
			raise CkanNotFound(err_type, "Resource not found. (%s)" % msg)
		else:
			# Generic message. We should not show this to the user if
			# we can help it.
			raise CkanApiError(err_type, msg)
		
