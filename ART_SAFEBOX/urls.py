"""ART_SAFEBOX URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.index),
    path('index.html', views.index),
    path('signin', views.signinAction),
    path('signin.html', views.signin),
    path('signup', views.signupAction),
    path('signup.html', views.signup),
    path('home.html', views.home),
    path('personal.html', views.personal),
    path('others.html', views.other),
    path('checksignin', views.checkSigninState),
    path('signout', views.signOutAction),
    path('recharge', views.recharge),
    path('purchase', views.purchase),
    path('upload', views.upload),
    path('download', views.download),
    path('accept', views.accept),
    path('reject', views.reject)
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
