from django.conf.urls import include, url
from django.contrib import admin
from organizations.backends import invitation_backend, registration_backend
from digits import views
urlpatterns = [
    # Examples:
    url(r'dashboard', 'digits.views.dashboard', name='dashboard'),
    # url(r'^blog/', include('blog.urls')),
    url(r'^accounts/', include('allauth.urls')),
    url(r'^org/', include('organizations.urls')),
    url(r'^invitations/', include(invitation_backend().get_urls())),
    url(r'^admin/', include(admin.site.urls)),

]
