# Loads CKAN resources into the CKAN Datastore
# to make an API out of static files.

import argparse, logging
import os.path, re, unicodedata
import urllib2, json, cStringIO, hashlib
from datetime import datetime
from ckan_client import CkanClient, CkanApiError, CkanAccessDenied

# Configure Logging

logging.basicConfig(format="%(message)s")
log = logging.getLogger()
log.setLevel(logging.INFO)

# Utilities

class UserError(Exception):
	def __init__(self, msg):
		super(UserError, self).__init__(msg)
		
class UnhandledError(Exception):
	def __init__(self, msg):
		super(UnhandledError, self).__init__(msg)

# Command-line arguments

def ckan_action(ckan, action, params, squash_errors_if=None):
	try:
		return ckan.action(action, params, squash_errors_if=squash_errors_if)
	except CkanAccessDenied as e:
		raise UserError(str(e))
	except Exception as e:
		raise UnhandledError("CKAN API call failed: " + str(e))

# Main routines.

def upload_resource_to_datastore(resource, if_changed, locally_cache_content, ckan):
	# This is the main function of this module. It takes a
	# resource (a dict as returned from resource_show), downloads
	# the content, parses the content as a table, and uploads
	# it into the CKAN datastore.

	# Download the resource.
	resource_file, mime_type, fileext = load_resource_content(resource, locally_cache_content)
	
	# Get the SHA1 hash of the resource content.
	sha = hashlib.sha1()
	sha.update(resource_file)
	resource_hash = sha.hexdigest()
	
	# If --ifchanged is used, only upload to the datastore if we
	# have a new file.
	if if_changed:
		if resource.get("datastore_content_hash", None) == resource_hash:
			log.info("Skipping resource --- not changed.")
			return

	# From here on, resource_file is expected to be a file-like obj.
	resource_file = cStringIO.StringIO(resource_file)
	
	# Get the default schema from the resource metadata.
	default_schema = resource.get("datastore_schema", None)
	if default_schema:
		default_schema = json.loads(default_schema)
	
	# Parse the resource to get the file format, column headers, datatypes, etc.
	# recorditer is a sequence of rows in the table, as returned from messytables.
	schema, recorditer = parse_resource(resource_file, mime_type, fileext, default_schema)
	
	# Before we start to load the data, clear some metadata
	# to indicate the data is currently incomplete (especially
	# when updating an existing resource and the upload crashes).
	resource["datastore_last_updated"] = None
	resource["datastore_content_hash"] = None
	ckan_action(ckan, "resource_update", resource)

	# Upload the resource to the Datastore.
	try:
		num_rows = upload_resource_records(resource, schema, recorditer, ckan)
	except UserError as e:
		# There was some data format error. Instead of raising
		# the error, we should do something so that we are able
		# to pass the inferred schema back to the caller so that
		# the user can edit the schema to try to avoid the error.
		raise
		
	# After a successful load, write the file hash into the resource.
	resource["datastore_content_hash"] = resource_hash
	resource["datastore_last_updated"] = datetime.utcnow().isoformat() # CKAN assumes strings that look like dates are in UTC
	resource["datastore_schema"] = json.dumps(schema, sort_keys=True, indent=4)
	resource["datastore_rows"] = num_rows
	ckan_action(ckan, "resource_update", resource)
	
def load_resource_content(resource, locally_cache_content):
	# Downloads the content of the resource file (resource["url"]).
	#
	# While it might be nice to support streaming the resource
	# throughout, there are too many cases when we really need
	# the whole thing in memory. So we return it as a str.
	
	# If --cache is used, see if we already have this resource in the cache.
	# If so, return it from the cache.
	if locally_cache_content:
		import sqlite3, base64
		conn = sqlite3.connect('cache.db')
		c = conn.cursor()
		try:
			c.execute("CREATE TABLE cache (url TEXT UNIQUE, content BLOB, mimetype TEXT, fileext TEXT)")
		except sqlite3.OperationalError as e:
			if str(e) != "table cache already exists":
				raise
		c.execute("SELECT content, mimetype, fileext FROM cache WHERE url=?", (resource["url"],))
		cache_hit = c.fetchone()
		if cache_hit:
			content, mime_type, fileext = cache_hit
			return base64.b64decode(content), mime_type, fileext
		
	# Start a download of the resource. The actual download
	# will probably commence inside AnyTableSet.from_fileobj
	# when .read() is called.
	log.info("Downloading %s..." % resource["url"])
	try:
		resource_file = urllib2.urlopen(resource["url"])
	except urllib2.HTTPError as e:
		raise UserError("Error downloading resource: " + str(e))

	# Get the MIME type and the file extension, in case we
	# are auto-detecting the file format.
	mime_type = resource_file.info()["Content-Type"]
	filename, fileext = os.path.splitext(resource["url"])
	if fileext.strip() in ("", "."):
		fileext = None
	else:
		fileext = fileext[1:] # strip off '.'
		
	resource_file = resource_file.read()

	if locally_cache_content:
		# Store the value in the cache. We'll need to slurp the
		# resource into memory, then wrap it back in a file-like
		# object before we return it.
		c = conn.cursor()
		c.execute("DELETE FROM cache WHERE url=?", (resource["url"],))
		c.execute("INSERT INTO cache VALUES(?,?,?,?)", (resource["url"], base64.b64encode(resource_file), mime_type, fileext))
		conn.commit()
		
	return resource_file, mime_type, fileext

def parse_resource(resource_file, mime_type, fileext, default_schema):
	# Given resource data, returns a tuple of
	#  * the schema used to load the file
	#  * the resource as a table, as given by messytables (an iterator over rows) 
	
	# Schema defaults. We'll build up the schema with defaults
	# from the actual resource so that it is easy for the data
	# owner to customize the schema later.
	schema = {
		"_format": 1,
	}
	
	# Update defaults from the provided schema.
	if default_schema:
		schema.update(default_schema)
	else:
		schema["auto"] = True
	
	# Utility function that's like dict.get() but works on nested
	# dicts and takes a path through to dicts as arguments. Returns
	# None if no value is found.
	#   e.g. schema_get('format', 'name')
	#        This returns schema["format"]["name"], or None if
	#        "format" isn't in schema or "name" isn't in schema["format"].
	def schema_get(*path, **kwargs):
		if len(path) < 1: raise ValueError()
		v = schema
		for p in path: v = v.get(p, {})
		if v == { }: v = kwargs.get("default", None)
		return v
	
	# Utility function that sets a value in a set of nested dicts.
	# Takes a path plus a value as arguments.
	#   e.g. schema_set('format', 'name', 'zip')
	#        This is equivalent to:
	#          schema["format"]["name"] = "zip"
	#        but creating dicts as necessary along the way.
	def schema_set(*path_and_value):
		if len(path_and_value) < 2: raise ValueError()
		path = path_and_value[0:-2]
		field = path_and_value[-2]
		value = path_and_value[-1]
		container = schema
		for p in path:
			container = container.setdefault(p, {})
		container[field] = value
	
	# Parse the resource_file.
	
	# Get the table data format.
	
	if schema_get('format', 'name') == None:
		# Auto-detect format.
		from messytables import AnyTableSet as data_format
		data_format_args = { }
		
	elif schema_get('format', 'name') in ("csv", "tsv"):
		# "format" = {
		#   "name": "csv" | "tsv",
		#   "delimiter": ",",
		#   "quotechar": "\"",
		#   "encoding": "utf-8"
		# }
		
		# Load as CSV/TSV.
		from messytables import CSVTableSet as data_format
		
		# Default load parameters.
		data_format_args = {
			"delimiter": "," if schema_get('format', 'name') == "csv" else "\t",
			"quotechar": '"',
			"encoding": None,
		}
		
		# Override parameters from the schema.
		for n in ("delimiter", "quotechar", "encoding"):
			v = schema_get("format", n)
			if v:
				data_format_args[n] = v
		
	else:
		raise UserError("Invalid format name in schema. Allowed values are: csv, tsv.")
		
	# If the user specifies a ZIP container, then parse the
	# resource_file as a ZIP file and pass the format parameters
	# into ZIPTableSet so it knows how to parse the inner files.
	
	if schema_get("container", "name") == "zip":
		# "container = {
		#   "name": "zip"
		# }
		
		from messytables import ZIPTableSet
		table_set = ZIPTableSet.from_fileobj(resource_file,
			inner_data_format=data_format,
			inner_parser_args=data_format_args)

	elif schema_get("container", "name") != None:
		raise UserError("Invalid container name in schema. Allowed values are: zip.")

	# If format parameters were given explicity, do not use a container.
	# Just parse according to the specified format.

	elif schema_get('format', 'name') != None:
		table_set = data_format.from_fileobj(resource_file, **data_format_args)
		
	# If no container and no format was specified, auto-detect everything.
	
	else:
		# Use the AnyTableSet to guess all parsing parameters.
		from messytables import AnyTableSet
		try:
			table_set = AnyTableSet.from_fileobj(resource_file, mimetype=mime_type, extension=fileext)
		except Exception as e:
			raise UserError("The file format could not be recognized: %s" % str(e))
		
		# Provide the container information that may have been guessed.
		if type(table_set).__name__ == "ZIPTableSet":
			schema_set("container", "name", "zip")
		
	table = table_set.tables[0]

	# Provide the CSV parser settings that may have been guessed.
	if type(table).__name__ == "CSVRowSet":
		schema_set("format", "name", "tsv" if table.delimiter == "\t" else "csv")
		schema_set("format", "delimiter", table.delimiter)
		schema_set("format", "quotechar", table.quotechar)
		schema_set("format", "encoding", table.encoding)
        
	# Get the column header names and the row offset to the data.
	
	# Start by guessing.
	from messytables import headers_guess, headers_processor
	offset, headers = headers_guess(table.sample)
	
	# Overwrite the has_headers and offset values with the schema, if present.
	has_headers = schema_get("header", "present", default=True)
	offset = schema_get("header", "offset", default=offset)
	
	# Set the header information back into the schema.
	schema_set("header", "present", True)
	schema_set("header", "offset", offset)
	
	# Override the header names with what is specified in the schema.
	for cidx, col in enumerate(schema_get("columns", default=[])):
		try:
			headers[cidx] = col.get("name", headers[cidx])
		except IndexError:
			pass # ignore schema problems?
	
	# Since SQL column names are not case sensitive, prevent any
	# uniqueness clashes by converting all to lowercase. While
	# we're at it, also trim spaces.
	headers = [h.lower().strip() for h in headers]
	
	# Ensure the headers are valid SQL-ish & datastore column names:
	#  1st character: letter
	#  subsequent characters: letter, number, or underscore
	for i, header in enumerate(headers):
		# To play nice with international characters, convert to ASCII
		# by replacing extended characters with their closest ASCII
		# equivalent where possible.
		header = u"".join(c for c in unicodedata.normalize('NFKD', header)
			if not unicodedata.combining(c))
		
		# Replace any invalid characters with "".
		header = re.sub("[^a-z0-9_]", "", header)
		
		# If there is an invalid 1st character, prepend a valid start.
		if not re.match("^[a-z]", header):
			header = "field_" + header
			
		# And force to an ASCII byte string, which should be possible by now.
		headers[i] = str(header)

	# TODO: Check that there is not an insane number of columns.
	# That could crash headers_make_unique. 

	# Ensure the headers are unique, and not too long. Postgres
	# supports 63 (64?)-char-long col names, but that's ridiculous.
	from messytables import headers_make_unique
	headers = headers_make_unique(headers, max_length=24)
	
	# Skip the header row.
	# (Add one to begin with content, not the header.)
	from messytables import offset_processor
	table.register_processor(offset_processor(offset + 1))
	
	# Try to guess the datatypes.
	import messytables.types
	from messytables import type_guess, types_processor
	datatypes = type_guess(
		table.sample,
		[
			messytables.types.StringType,
			messytables.types.IntegerType,
			messytables.types.FloatType,
			messytables.types.DecimalType,
			messytables.types.DateType
		],
		strict=True
		)
	if len(datatypes) != len(headers):
		raise UserError("Could not guess data types. Column header count does not match rows found during type guessing.")
	messytable_datastore_type_mapping = {
		messytables.types.StringType: 'text',
		messytables.types.IntegerType: 'numeric',  # 'int' may not be big enough,
						# and type detection may not realize it needs to be big
		messytables.types.FloatType: 'float',
		messytables.types.DecimalType: 'numeric',
		messytables.types.DateType: 'timestamp',
	}
	datatypes = [messytable_datastore_type_mapping[type(t)] for t in datatypes] # convert objects to strings
	
	# Override the datatypes from the schema.
	for cidx, col in enumerate(schema_get("columns", default=[])):
		try:
			datatypes[cidx] = col.get("type", datatypes[cidx])
		except IndexError:
			pass # ignore schema problems?
	
	# Provide the header names and types back to the user in the schema.
	schema["columns"] = []
	for i in xrange(len(headers)):
		schema["columns"].append({
			"name": headers[i],
			"type": datatypes[i],
		})
		
	# Validate that the datatypes are all legit.
	for dt in datatypes:
		if dt not in ("text", "int", "float", "bool", "numeric", "date", "time", "timestamp", "json"):
			raise UserError("Invalid data type in schema: %s" % dt)
			
	return schema, table

def upload_resource_records(resource, schema, recorditer, ckan):
	# Given the parsed resource ready to be loaded, now actually
	# pass off the data to the Datastore API.

	# First try to delete any existing datastore for the resource.
	# If the error from CKAN has __type == "Not Found Error",
	# silently continue --- it means there is no datastore for
	# this resource yet.
	ckan_action(ckan, "datastore_delete", { "resource_id": resource["id"] },
		squash_errors_if = lambda err : err["__type"] == "Not Found Error")
	
	# Create the datastore.
	ckan_action(ckan, "datastore_create", {
		"resource_id": resource["id"],
		"fields": [
			{
				"id": col["name"],
				"type": col["type"],
			} for cidx, col in enumerate(schema["columns"]) ]
		})
		# TODO: also send primary_key, indexes?
	
	# Helper function to send rows in batches.
	def chunky(iterable, n):
		chunk = []
		for x in iterable:
			chunk.append(x)
			if len(chunk) == n:
				yield chunk
				chunk = []
		if len(chunk) > 0:
			yield chunk			
			
	# Helper function to validate that the raw string value from the file
	# is in a format appropriate for the JSON call to the API, which
	# will pass the value off to PostreSQL.
	def validate_cell(cell, datatype, rownum, colnum, colname):
		# Return value must be JSON-serializable so we can pass it
		# through the API. Then datastore had better know how to
		# convert that into a string for the SQL statement.
		
		# Get the type converter for the column's datatype.
		import messytables.types
		datastore_messytable_type_mapping = {
			'text': messytables.types.StringType,
			'int': messytables.types.IntegerType,
			'float': messytables.types.FloatType,
			'numeric': messytables.types.FloatType, # DecimalType is not JSON serializable
			'timestamp': messytables.types.DateType,
		}
		typ = datastore_messytable_type_mapping[datatype]

		if cell.type != None:
			# The XLS parser does type conversion for us. Just check
			# that the cell datatype matches the column datatype.
			if type(cell.type) != typ:
				raise UserError('The %s value %s in row %d column %d (%s) is invalid for a %s column.' % (str(cell.type), repr(cell.value), rownum+1, colnum+1, colname, datatype))
			
			# If it matches, return the value unchanged. We're relying
			# on the assumption that the casted value according to the
			# messytables datatype will be valid for the column in the
			# datastore, otherwise we may get an error.
			return cell.value
		
		# The empty string is invalid for columns besides text,
		# unless we treat it as a database NULL.
		if cell.value.strip() == "" and datatype != "text":
			return None # db NULL
		

		# Normalize the raw value.
		try:
			return typ().cast(cell.value)
		except ValueError:
			# If normalization fails, the user has provided an
			# invalid value.
			raise UserError('The value "%s" in row %d column %d (%s) is invalid for a %s column.' % (cell.value, rownum+1, colnum+1, colname, datatype))
			
	# Utility function to convert a messytables row to a
	# datastore API row.
	def format_record(rownum, row, columns):
		# Convert the table row that looks like
		#   [ Cell(value=___), ... ]
		# into a dictionary for datastore that looks like:
		#   { col1name: ___, ... }
		if len(columns) != len(row):
			raise UserError("Row %d does not have %d columns." % (rownum, len(columns)))
		row2 = { }
		for i, col in enumerate(columns):
			row2[col["name"]] = validate_cell(
				row[i], col["type"],
				rownum, i, col["name"])
		return row2
			 
	# Finally, the actual procedure to chunk the rows and do
	# the upload.
	
	rownum = 0
	for rows in chunky(recorditer, 2000):
		log.info("Uploading row %d..." % rownum)
		
		# Re-format messytables row into the list of dicts expected
		# by the CKAN Datastore API. Also track the row number for
		# error reporting.
		payload = []
		for row in rows:
			payload.append(format_record(rownum, row, schema["columns"]))
			rownum += 1
			
		# Execute API call.
		ckan_action(ckan, "datastore_upsert", {
			"resource_id": resource["id"],
			"method": "insert",
			"records": payload,
			})
		
	return rownum
		
#####################################################################

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Load a CKAN resource into the Datastore.')
	parser.add_argument('base_url', type=str, help='The CKAN base URL, e.g. http://www.example.org')
	parser.add_argument('api_key', type=str, help='A CKAN API key that can edit the resource.')
	parser.add_argument('resource_id', type=str, nargs="?", help='The resource GUID, or omit to load all resources in the CKAN catalog.')
	parser.add_argument('--cache', action="store_true", help='Cache the resource data file locally to make testing faster.')
	parser.add_argument('--ifchanged', action="store_true", help='Only load resources into the datastore if the content has changed.')
	args = parser.parse_args()
	
	ckan = CkanClient(args.base_url, args.api_key)
	
	if args.resource_id == None:
		# Upload all packages.
		packages = ckan_action("package_list", {})
		for package_id in packages:
			# Get the package's first resource.
			pkg = ckan_action("package_show", { "id": package_id })
			
			# Filter out resources to skip.
			resources = [r for r in pkg["resources"] if r["format"].lower() not in ("api","query tool")]
			
			# Has  aresource to upload? Get the first.
			if len(resources) == 0:
				log.error("Package %s has no uploadable resources." % pkg["name"])
				continue
			resource = resources[0]
	
			log.info("Processing %s/resource/%s ..." % (pkg["name"], resource["id"]))
	
			try:
				upload_resource_to_datastore(resource, args.ifchanged, args.cache, ckan)
			except UserError as e:
				log.error(e)
				
			log.info("") # blank line please
	else:
		# Upload a particular resource.
		resource = ckan_action("resource_show", { "id": args.resource_id })
		upload_resource_to_datastore(resource, args.ifchanged, args.cache, ckan)
		
