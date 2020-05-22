from django.urls import path

from . import views
from . import consts

app_name = consts.app_name

urlpatterns = [
    path('acs/', views.sso_acs, name=consts.LABEL_SSO_ACS),
    path('login/', views.signin, name=consts.LABEL_SSO_LOGIN)
]

