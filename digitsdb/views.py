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

# import os
# import time
# import subprocess
# from threading import Thread
# from flask import Flask, render_template, session, request
# from flask.ext.socketio import SocketIO, emit, join_room, leave_room, \
# 	close_room, disconnect

# thread = None

# import commands

# def get_download_status(source_size, dest_path):
# 	"""
# 		Method for calculating the percentage of completion
# 		and then sending a respinse to page using socketIO.
# 		This process is repeating untill the copy is not 
# 		done completely. 
# 	"""
# 	# dest_size = int(commands.getoutput('du -s '+dest_path).split()[0])
# 	source_size = int(source_size)
# 	dest_size = 1
# 	while(dest_size <= source_size):
# 		dest_size = int(commands.getoutput('du -s '+dest_path).split()[0])
# 		time.sleep(0.01)
# 		percent = (dest_size*100/source_size)
# 		# dest_size = get_size(dest_path)
# 		# dest_size+=1
# 		socketio.emit("my progressbar",
# 			{'percent':percent},namespace='/')

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
		session_id = request.POST['session_id']
		user_id = get_user_from_session(session_id).id
		# Example 1: s3://bucket:/path/to/files
		# Example 2: dropbox:/path/to/files
		# Example 3: google:/path/to/file
		try:
			if path.split(":")[0].lower()=="s3":
				# print "[CALLING METHOD] Uploading data to S3"
				bucket = path.split(":")[1][2:]
				dest_path = str(path.split(":")[2])
				# print "bucket: ", bucket
				# print "dest_path", dest_path
				result = put_data_on_s3(request, source_path, dest_path, bucket, user_id)

			elif path.split(":")[0].lower()=="dropbox":
				# print "[DATA TO DROPBOX]"
				dest_path = path.split(":")[1]
				access_token = SocialToken.objects.get(account__user__id = user_id, app__name = "Dropbox")
				session = DropboxSession(settings.DROPBOX_APP_KEY, settings.DROPBOX_APP_SECRET)
				access_key, access_secret = access_token.token, access_token.token_secret  # Previously obtained OAuth 1 credentials
				session.set_token(access_key, access_secret)
				client = DropboxClient(session)
				token = client.create_oauth2_access_token()
				result = put_data_on_dropbox(request, source_path, dest_path, token, user_id)

			elif path.split(":")[0].lower()=="Google Drive":
				# print "############## GOOGLE DRIVE ##############   "
				storage = Storage(SocialToken, 'id', user_id, 'token')
				# print storage
				credential = storage.get()
				# credentials = SocialToken.objects.get(account__user__id = request.user.id, app__name = storage)
				# credentials = credentials.token
				http = credential.authorize(httplib2.Http())
				service = discovery.build('drive', 'v2', http=http)
				results = service.files().list(maxResults=10).execute()
				items = results.get('items', [])
				if not items:
					pass
					# print 'No files found.'
				else:
					# print 'Files:'
					for item in items:
						print '{0} ({1})'.format(item['title'], item['id'])
				result = put_data_on_google_drive(request,path,access_token.token)

			else:
				result = {"error":"Check if you have attached the type of cloud storage with your account or enter valid path"}
		except:
			result = {"error":"Incorrect Input"}
		# print result
		return HttpResponse(json.dumps(result))

	@csrf_exempt
	def dispatch(self, *args, **kwargs):
		return super(UploadAPI, self).dispatch(*args, **kwargs)

def put_data_on_s3(request, source_path, dest_path, bucket, user_id):
	result = {}
	files = [name for name in glob.glob(os.path.join(source_path,'*.*')) if os.path.isfile(os.path.join(source_path,name))]
	result['sourcePath'] = source_path
	result['dest_path'] = dest_path
	result['bucket'] = bucket
	result['uplaodedTo']= []
	result['user_id'] = user_id
	s3_user = StorageCredentials.objects.get(user__id = user_id)
	conn = S3Connection(s3_user.aws_access_key,s3_user.aws_access_secret)
	# conn = S3Connection('AKIAJISUCCBNYECJPTIA','1tLIgzgYIpGXlP3WGDeAXW2t4b+GU1QT7k/STi/J')
	try:
		# Use the bucket is already exists
		b = conn.get_bucket(bucket)
		# print "TRY "
	except:
		# If the bucket does not exist, then create a new bucket
		# print "CATCH"
		b = conn.create_bucket(bucket)
	for i in files:
		# Loop to upload the files on S3 One by one
		k = Key(b)
		k.key = dest_path+i.split("/")[-1]
		result['uplaodedTo'].append(k.key)
		k.set_contents_from_filename(i)
		# print i
	return result


def put_data_on_dropbox(request, source_path, dest_path,access_token, user_id):
	result = {}
	client = dropbox.client.DropboxClient(access_token)
	result['dest_path'] = dest_path
	result['user_id'] = user_id
	# result['uplaodedTo'] = []
	files = [name for name in glob.glob(os.path.join(source_path,'*.*')) if os.path.isfile(os.path.join(source_path,name))]
	for i in files:
		f = open(i,'rb')
		response = client.put_file(dest_path+i.split("/")[-1], f)
		# result['uplaodedTo'].append(response)
	return result

class DownloadAPI(View):
	def post(self,request):
		try:
			result = {}
			path = request.POST['source_path']
			session_id = request.POST['session_id']
			user_id = get_user_from_session(session_id).id
			dest_path = request.POST['dest_path']
			dest_path = dest_path.split('/')
			dest_path.append(str(user_id))
			dest_path[-1],dest_path[-2] = dest_path[-2],dest_path[-1]
			dest_path = '/'.join(dest_path)
			try:
				# Increment the name of new directory by one
				directories = map(int, os.listdir(dest_path))
				dest_path+='/'+str(max(directories)+1)
			except:
				# If no directory exists then give it name 1
				dest_path+='/'+'1'
			if dest_path[-1]!="/":
				dest_path+="/"
			if not os.path.isdir(dest_path):
				os.makedirs(dest_path)
			if path.split(":")[0].lower()=="s3":
				print "S3 is working "
				bucket = path.split(":")[1][2:]
				source_path = str(path.split(":")[2])
				result = get_data_from_s3(request, source_path, dest_path, bucket, user_id)

			elif path.split(":")[0].lower()=="dropbox":
				print "[HERE]"
				source_path = path.split(':')[1][1:]
				access_token = SocialToken.objects.get(account__user__id = user_id, app__name = "Dropbox")
				session = DropboxSession(settings.DROPBOX_APP_KEY, settings.DROPBOX_APP_SECRET)
				access_key, access_secret = access_token.token, access_token.token_secret  # Previously obtained OAuth 1 credentials
				session.set_token(access_key, access_secret)
				print source_path
				print dest_path
				print user_id
				client = DropboxClient(session)
				token = client.create_oauth2_access_token()
				print token
				result = get_data_from_dropbox(request, source_path, dest_path, token, user_id)
				print "[DROPBOX]", result
			elif path.split(":")[0].lower() =="Google Drive":
				get_data_from_google(request,path,access_token)
			else:
				result = {"error":"Check if you have attached the type of cloud storage with your account or enter valid path"}
		except:
			result = {"error":"Invalid Input Provided"}
		# return result
		# print "########################################"
		# print result
		# print "########################################"
		return HttpResponse(json.dumps(result))


def get_data_from_s3(request,source_path, dest_path, bucket, user_id):
	result = {}
	try:
		# s3 = StorageCredentials.objects.get(user__id = user_id)
		# conn = S3Connection(s3.aws_access_key,s3.aws_access_secret)
		# conn = S3Connection('ZZZZZZZZAKIAJISUCCBNYECJPTIAZZZZZ','ZZZZZZ1tLIgzgYIpGXlP3WGDeAXW2t4b+GU1QT7k/STi/JZZZZZZZ')
		# print "bucket is ", bucket
		b = conn.get_bucket(bucket)
		result['user_id'] = user_id
		result['bucket'] = bucket
		result['location']= []
		result['dest_path'] = dest_path
	except:
		result['error'] = "Check if the S3 bucket exists or not."
		return result
	bucket_entries = b.list(source_path[1:])
	for i in bucket_entries:
		result['location'].append(i.key)
		file_name = str(i.key).split("/")[-1]
		i.get_contents_to_filename(dest_path + file_name)
	return result


def get_dropbox_directory_size(path,client):
	return sum(
		f['bytes'] if not f['is_dir'] else size(f['path'])
		for f in client.metadata(path)['contents']
	)


def get_data_from_dropbox(request,source_path, dest_path, access_token, user_id):
	result = {}
	try:
		client = dropbox.client.DropboxClient(str(access_token))
		images_metadata = client.metadata(source_path)
		result['user_id'] = user_id
		result['storage'] = source_path
		# result['location']= []
		if dest_path[-1]!="/":
			dest_path+="/"
		result['dest_path'] = dest_path
		# print "echo"
		# source_size = get_dropbox_directory_size(source_path,client)
		# global thread
		# if thread is None:
		# 	thread = Thread(target=get_download_status, args=(source_size, dest_path))
		# 	thread.start()
		# print len(images_metadata['contents'])
		for i in images_metadata['contents']:
			if not i['is_dir']:
				f, metadata = client.get_file_and_metadata(i['path'])
				out = open(dest_path + str(i['path'].split("/")[-1]), 'wb')
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

