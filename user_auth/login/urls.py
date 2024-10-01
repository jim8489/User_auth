from django.contrib.auth import views as auth_views 
from django.urls import path
from login import views

urlpatterns = [
    path('', views.signup, name='signup'),
    path('home/', views.home, name='home'),
    path('login/', views.loginUser, name='login'),
    path('logout', views.logoutUser, name='logout'),
    path('activate/<str:uidb64>/<str:token>/', views.activate_account, name='activate_account'),
    path('password_reset/', auth_views.PasswordResetView.as_view(),name='password_reset'),
    path('password_reset_em/', auth_views.PasswordResetDoneView.as_view(),name='password_reset_done'),
    path('pass_reset/<str:uidb64>/<str:token>/', auth_views.PasswordResetConfirmView.as_view(),name='password_reset_confirm'),
    path('password_reset_complete/', auth_views.PasswordResetCompleteView.as_view(template_name="pass_reset_login.html"),name='password_reset_complete'),

]
