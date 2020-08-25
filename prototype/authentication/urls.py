from django.urls import path
from authentication.views import views

urlpatterns = [
    path('', views.home_view, name='home'),
    path('login/', views.login_view, name='login'),
    path('register/', views.register_view, name='register'),
    path('logout/', views.logout_view, name='logout'),    
    path('change/password', views.change_password_view, name='change_password'),    
]