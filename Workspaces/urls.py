from django.conf.urls import include, url
from django.contrib import admin
from organizations.backends import invitation_backend, registration_backend

urlpatterns = [
    # Examples:
    # url(r'^$', 'Workspaces.views.home', name='home'),
    # url(r'^blog/', include('blog.urls')),
    (r'^accounts/', include('allauth.urls')),
    url(r'^accounts/', include('organizations.urls')),
    url(r'^invitations/', include(invitation_backend().get_urls())),
    url(r'^admin/', include(admin.site.urls)),

]
