from django.conf.urls import patterns, include, url
from django.contrib import admin
from organizations.backends import invitation_backend, registration_backend
from digitsdb import views
from digits import views
import os 
urlpatterns = [
	# Examples:
	url(r'^static/(.*)$', 'django.views.static.serve', {'document_root': os.path.join(os.path.abspath(os.path.dirname(__file__)), 'static')}),
	url(r'^email/', 'digits.views.current_user', name='current_user'),
	url(r'dashboard', 'digits.views.dashboard', name='dashboard'),
	# url(r'^blog/', include('blog.urls')),
	url(r'^accounts/', include('allauth.urls')),
	url(r'^workspace/', include('organizations.urls')),
	url(r'^invitations/', include(invitation_backend().get_urls())),
	url(r'^admin/', include(admin.site.urls)),
	url(r'^', include('organizations.urls')),
	url(r'api/upload', 'digitsdb.views.up_storage_api', name='api_upload'),
	url(r'api/download', 'digitsdb.views.down_storage_api', name='api_download'),

]

# urlpatterns += patterns('',
#     (r'^static/(.*)$', 'django.views.static.serve', {'document_root': os.path.join(os.path.abspath(os.path.dirname(__file__)), 'static')}),
# )