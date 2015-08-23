from django.shortcuts import render, HttpResponse
from django.contrib.auth.decorators import login_required
import json
# Create your views here.

def current_user(request):
	if request.user.is_authenticated():
		return HttpResponse(json.dumps({"email":request.user.email}))
	else:
		return HttpResponse(json.dumps({"email":None}))

@login_required
def dashboard(request):
	request.session['hello'] = "world"
	return HttpResponse("Logged In")


from django.views.decorators.csrf import csrf_exempt  
from django.views.generic import *
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from allauth.socialaccount.models import * 
from Workspaces import *
from digitsdb.models import *
from dropbox.client import DropboxClient
from dropbox.session import DropboxSession
from boto.s3.connection import * 
from apiclient import errors
from apiclient.http import MediaFileUpload
from Workspaces.settings import *
from os import path
import httplib2
import json
import traceback
import glob
import os
import dropbox


from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import authentication, permissions
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import SessionAuthentication, BasicAuthentication



class UploadAPI(APIView):
	# def get(self, request, *args, **kwargs):
	# 	providers = []
	# 	tokens = SocialToken.objects.filter(account__user__id = request.user.id)
	# 	for i in tokens:
	# 		providers.append(str(i.app))
	# 	s3 = StorageCredentials.objects.filter(user__id = request.user.id).count()
	# 	if s3:
	# 		providers.append("Amazon S3")
	# 	return render_to_response("app/upload_to_storage.html",{'p':providers},context_instance = RequestContext(request))
	def post(self,request):
		source_path = request.POST['source_path']
		path = request.POST['dest_path']
		user_id = request.POST['user_id']

		# Example 1: s3://bucket:/path/to/files
		# Example 2: dropbox:/path/to/files
		# Example 3: google:/path/to/file
		try:
			if path.split(":")[0].lower()=="s3":
				print "S3 is working "
				bucket = path.split(":")[1][2:]
				dest_path = str(path.split(":")[2])
				result = put_data_on_s3(request, source_path, dest_path, bucket, user_id)

			elif path.split(":")[0].lower()=="dropbox":
				dest_path = path.split(":")[1]
				access_token = SocialToken.objects.get(account__user__id = user_id, app__name = "Dropbox")
				session = DropboxSession(settings.DROPBOX_APP_KEY, settings.DROPBOX_APP_SECRET)
				access_key, access_secret = access_token.token, access_token.token_secret  # Previously obtained OAuth 1 credentials
				session.set_token(access_key, access_secret)
				client = DropboxClient(session)
				token = client.create_oauth2_access_token()
				result = put_data_on_dropbox(request, source_path, dest_path, token, user_id)

			elif path.split(":")[0].lower()=="Google Drive":
				print "############## GOOGLE DRIVE ##############   "
				storage = Storage(SocialToken, 'id', user_id, 'token')
				print storage
				credential = storage.get()
				# credentials = SocialToken.objects.get(account__user__id = request.user.id, app__name = storage)
				# credentials = credentials.token
				http = credential.authorize(httplib2.Http())
				service = discovery.build('drive', 'v2', http=http)
				results = service.files().list(maxResults=10).execute()
				items = results.get('items', [])
				if not items:
					print 'No files found.'
				else:
					print 'Files:'
					for item in items:
						print '{0} ({1})'.format(item['title'], item['id'])
				result = put_data_on_google_drive(request,path,access_token.token)

			else:
				result = {"error":"Check if you have attached the type of cloud storage with your account or enter valid path"}
		except:
			result = {"error":"Incorrect Input"}
		return HttpResponse(json.dumps(result), content_type="application/json")

	@csrf_exempt
	def dispatch(self, *args, **kwargs):
		return super(UploadAPI, self).dispatch(*args, **kwargs)

def put_data_on_s3(request, source_path, dest_path, bucket, user_id):
	result = {}
	files = [name for name in glob.glob(os.path.join(source_path,'*.*')) if os.path.isfile(os.path.join(source_path,name))]
	result['sourcePath'] = source_path
	result['dest_path'] = request.POST['dest_path']
	result['bucket'] = bucket
	result['uplaodedTo']= []
	result['user_id'] = user_id
	s3_user = StorageCredentials.objects.get(user__id = user_id)
	conn = S3Connection(s3_user.aws_access_key,s3_user.aws_access_secret)
	# conn = S3Connection('AKIAJISUCCBNYECJPTIA','1tLIgzgYIpGXlP3WGDeAXW2t4b+GU1QT7k/STi/J')
	try:
		# Use the bucket is already exists
		b = conn.get_bucket(bucket)
		print "TRY "
	except:
		# If the bucket does not exist, then create a new bucket
		print "CATCH"
		b = conn.create_bucket(bucket)
	for i in files:
		# Loop to upload the files on S3 One by one
		k = Key(b)
		k.key = dest_path+i.split("/")[-1]
		result['uplaodedTo'].append(k.key)
		k.set_contents_from_filename(i)
		print i
	return result


def put_data_on_dropbox(request, source_path, dest_path,access_token, user_id):
	result = {}
	client = dropbox.client.DropboxClient(access_token)
	result['pathProvided'] = dest_path
	result['user_id'] = user_id
	result['uplaodedTo'] = []
	files = [name for name in glob.glob(os.path.join(source_path,'*.*')) if os.path.isfile(os.path.join(source_path,name))]
	for i in files:
		f = open(i,'rb')
		response = client.put_file(dest_path+i.split("/")[-1], f)
		result['uplaodedTo'].append(response)
	return result

from django.contrib.auth import SESSION_KEY, BACKEND_SESSION_KEY, load_backend

def get_user_from_session(session_key):
	session_engine = __import__(settings.SESSION_ENGINE, {}, {}, [''])
	session_wrapper = session_engine.SessionStore(session_key)
	session = session_wrapper.load()
	user_id = session.get(SESSION_KEY)
	backend_id = session.get(BACKEND_SESSION_KEY)
	if user_id and backend_id:
		auth_backend = load_backend(backend_id)
		user = auth_backend.get_user(user_id)
		if user:
			return user
	return AnonymousUser()


class DownloadAPI(APIView):
	def post(self,request):
		result = {}
		print "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
		print request.session._session_key
		path = request.POST['source_path']
		dest_path = request.POST['dest_path']
		session_id = request.POST['session_id']
		print "POST Request to Download API "
		print "WE HAVE THE VALUES WITH US"
		print session_id
		print path
		print dest_path
		user_id = get_user_from_session(session_id).id

		try:
			if path.split(":")[0].lower()=="s3":
				print "S3 is working "
				bucket = path.split(":")[1][2:]
				source_path = str(path.split(":")[2])
				result = get_data_from_s3(request, source_path, dest_path, bucket, user_id)

			elif path.split(":")[0].lower()=="dropbox":
				access_token = SocialToken.objects.get(account__user__id = user_id, app__name = "Dropbox")
				session = DropboxSession(settings.DROPBOX_APP_KEY, settings.DROPBOX_APP_SECRET)
				access_key, access_secret = access_token.token, access_token.token_secret  # Previously obtained OAuth 1 credentials
				session.set_token(access_key, access_secret)
				client = DropboxClient(session)
				token = client.create_oauth2_access_token()
				result = get_data_from_dropbox(request, source_path, dest_path, token, user_id)

			elif path.split(":")[0].lower() =="Google Drive":
				get_data_from_google(request,path,access_token)

			else:
				result = {"error":"Check if you have attached the type of cloud storage with your account or enter valid path"}
		except:
			result = {"error":"Incorrect Input Provided"}
		print result
		return HttpResponse(json.dumps(result), content_type="application/json")


def get_data_from_s3(request,source_path, dest_path, bucket, user_id):
	result = {}
	try:
		s3 = StorageCredentials.objects.get(user__id = user_id)
		conn = S3Connection(s3.aws_access_key,s3.aws_access_secret)
		b = conn.get_bucket(bucket)
		result['user_id'] = user_id
		result['bucket'] = bucket
		result['location']= []
		result['dest_path'] = []
	except:
		result['error'] = "Check if the S3 bucket exists or not."
		return result
	bucket_entries = b.list(source_path[1:])
	if dest_path[-1]!="/":
		dast_path+="/"
	for i in bucket_entries:
		result['location'].append(i.key)
		file_name = str(i.key).split("/")[-1]
		result['dest_path'].append(dest_path+file_name)
		i.get_contents_to_filename(dest_path+file_name)
	return result



def get_data_from_dropbox(request,source_path, dest_path, access_token, user_id):
	result = {}
	try:
		client = dropbox.client.DropboxClient(str(access_token))
		images_metadata = client.metadata(source_path)
		result['user'] = request.user.email
		result['storage'] = request.POST['storageName']
		result['location']= []
		result['dest_path'] = []
		for i in images_metadata['contents']:
			if i['is_dir'] == False:
				result['location'].append(i['path'])
				f, metadata = client.get_file_and_metadata(i['path'])
				out = open(dest_path + str(i.name), 'wb')
				result['dest_path'].append(dest_path + str(i.name))
				out.write(f.read())
				out.close()
	except:
		result['error'] = "Check if the directory exists or not and then try again."
	return result   

"BELOW METHOD NOT WORKING FOR NOW"
def createDriveService():
	"""
		Builds and returns a Drive service object authorized with the
		application's service account.
		Returns:
		   Drive service object.
	"""
	from oauth2client.appengine import AppAssertionCredentials
	from apiclient.discovery import build
	credentials = AppAssertionCredentials(scope='https://www.googleapis.com/auth/drive')
	http = httplib2.Http()
	http = credentials.authorize(http)
	return build('drive', 'v2', http=http, developerKey=API_KEY)

"BELOW METHOD NOT WORKING FOR NOW"
def insert_file(service, title, parent_id, filename):
  """Insert new file.
  Args:
	service: Drive API service instance.
	title: Title of the file to insert, including the extension.
	description: Description of the file to insert.
	parent_id: Parent folder's ID.
	mime_type: MIME type of the file to insert.
	filename: Filename of the file to insert.
  Returns:
	Inserted file metadata if successful, None otherwise.
  """
 #  media_body = MediaFileUpload(filename,resumable=True)
 #  body = {
	# 'title': title,
 #  }
 #  # Set the parent folder.
 #  if parent_id:
	# body['parents'] = [{'id': parent_id}]

 #  try:
	# file = service.files().insert(
	#   body=body,
	#   media_body=media_body).execute()

	# # Uncomment the following line to print the File ID
	# print 'File ID: %s' % file['id']

	# return file
 #  except errors.HttpError, error:
	# print 'An error occured: %s' % error
	# return None


up_storage_api = csrf_exempt(UploadAPI.as_view())
down_storage_api = csrf_exempt(DownloadAPI.as_view())

