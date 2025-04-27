from django.urls import path

from .views import ActivateInvitationView, ActiveDevicesAPIView, ActiveUserDropdownAPIView, BlacklistActiveDeviceAPIView, ChangePasswordView, BlacklistAPIView, LoginView,LogoutView, ProfileView, ResendInvitationView, SendForgotPasswordOTP, UpdateNewPassword, ValidateForgotPasswordOTP

urlpatterns = [
    # public
    path('login', LoginView.as_view()),
    path('send_forgot_password_otp', SendForgotPasswordOTP.as_view()),
    path('validate_forgot_password_otp', ValidateForgotPasswordOTP.as_view()),
    path('update_new_password', UpdateNewPassword.as_view()),
    
    # private
    path('resend_invitation/<int:pk>', ResendInvitationView.as_view()),
    path('activate_user/<str:key>',ActivateInvitationView.as_view()),
    path('changepassword', ChangePasswordView.as_view()),
    path('profile', ProfileView.as_view(), name="profile"),
    path('activedevices', ActiveDevicesAPIView.as_view()),
    path('blacklistactivedevice/<int:pk>', BlacklistActiveDeviceAPIView.as_view()),
    path('activeuserdropdown', ActiveUserDropdownAPIView.as_view()),
    path('blacklist',BlacklistAPIView.as_view()),
    path('logout', LogoutView.as_view()),
]