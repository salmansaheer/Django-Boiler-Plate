import jwt
from datetime import datetime, timedelta

from django.shortcuts import get_object_or_404
from django.contrib.auth.hashers import make_password
from django.conf import settings
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.decorators import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken

from utils.constants import send_email_context
from utils.functions import save_uploaded_image_from_base64, send_email
from utils.request_utils import save_login_details, save_logout_details

from .serializers import ActivateUserSerializer, ChangePasswordSerializer, ForgotPasswordSerializer, LoginSerializer, OTPValidateSerializer, UserAccessLogSerializer, UserAccessLogWithUserSerializer, UserSerializer
from .models import Account, UserAccessLog
import uuid
# Create your views here.
class LoginView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            try:
                account = Account.objects.get(email=serializer.validated_data['email'])
            except Exception as e:
                return Response({'error': 'Invalid credentials !!!'}, status=status.HTTP_403_FORBIDDEN)
            if account.status == "Invited":
                content = {'error': f'This account is not activated yet !!!'}
                return Response( content, status=status.HTTP_403_FORBIDDEN)
            if account.status != "Active":
                content = {'error': f'This account is {account.status.lower()}. Please contact your administrator !!!'}
                return Response( content, status=status.HTTP_403_FORBIDDEN)
            password_validity = account.check_password(serializer.validated_data['password'])
            if not password_validity:
                return Response({'error': 'Invalid credentials !!!'}, status=status.HTTP_403_FORBIDDEN)
            version_code = request.data.get('version_code')

            if (version_code and account.user_type != 'Inspector') or (not version_code and account.user_type == 'Inspector'):
                return Response({'error': 'Login access is denied for this user.'}, status=status.HTTP_403_FORBIDDEN)

            
            tokens = serializer.get_token(account)
            response = Response({'message': 'Login successful',
                                 'user':UserSerializer(account).data,
                                 'token':tokens['access'],}, status=status.HTTP_200_OK)
            response.set_cookie(key='access_token',value=tokens['access'],
                                httponly=True,  # If it true cannot access the cookies from frontend
                                secure = not settings.DEBUG # Uncomment when golive
                                )
            response.set_cookie(key='refresh_token',value=tokens['refresh'],httponly=True,
                                secure = not settings.DEBUG # Uncomment when golive
                                )
            save_login_details(account,request,tokens['refresh'],version_code)
            account.last_login = datetime.now()
            account.save()
            return response
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class ResendInvitationView(APIView):
    def get_object(self, pk):
        return get_object_or_404(Account,pk=pk)
    
    def put(self, request, pk):
        instance = self.get_object(pk)
        if instance.status == 'Invited':
            if instance.user_type in ['Employee', 'Driver']:
                content = {'error': 'Unauthorized user type.'}
                return Response(content, status=status.HTTP_400_BAD_REQUEST)
            inviting_key = jwt.encode({'email': instance.email,'user_type':instance.user_type}, 
                                        settings.JWT_SECRET_KEY, algorithm="HS256")

            instance.inviting_key        =   inviting_key
            instance.invite_expiry_date  =   timezone.now() + timedelta(days=3)
            instance.save()
            instance.send_invitation()
            content = {'Success': 'Invitation resend successfully !!!'}
            return Response(content, status=status.HTTP_202_ACCEPTED)
        else:
            content = {'error': 'User already activated !!!'}
            return Response(content, status=status.HTTP_404_NOT_FOUND)
        
class SendForgotPasswordOTP(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        data = request.data
        email    = data.get('email', None)
        user = Account.objects.filter(email = email)
        if user.exists():
            user=user.first()
            if user.status != "Active":
                content = {'error': 'This is not an active user !!!'}
                return Response(content, status=status.HTTP_405_METHOD_NOT_ALLOWED)
            if user.user_type in ['Employee', 'Driver']:
                content = {'error': 'User not found !!!'}
                return Response(content, status=status.HTTP_405_METHOD_NOT_ALLOWED)
            user.forgot_password()
            content = {'message': 'OTP sent successfully !!!'}
            return Response(content, status=status.HTTP_200_OK)
        content = {'error': 'User not found !!!'}
        return Response(content, status=status.HTTP_404_NOT_FOUND)
    
class ValidateForgotPasswordOTP(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        data = request.data
        serializer = OTPValidateSerializer(data=data)
        if serializer.is_valid():
            email           = serializer.validated_data.get('email')
            entered_otp     = serializer.validated_data.get('otp')

            user = Account.objects.filter(email = email)
            if user.exists():
                user=user.first()
                if user.status != "Active":
                    content = {'error': 'This is not an active user !!!'}
                    return Response(content, status=status.HTTP_405_METHOD_NOT_ALLOWED)

                if user.retrieve_password_otp:
                    if (user.password_otp_expiry_date < timezone.now()):
                        content = {'error': "OTP has been expired or incorrect"}
                        return Response(content, status=status.HTTP_405_METHOD_NOT_ALLOWED)
                    if(user.retrieve_password_otp != int(entered_otp)):
                        content = {'error': "Invalid OTP"}
                        return Response(content, status=status.HTTP_405_METHOD_NOT_ALLOWED)
                    else:
                        user.registration_key = jwt.encode(
                            {'email': serializer.validated_data.get('email'),'user_type':serializer.validated_data.get('user_type')}, 
                            settings.JWT_SECRET_KEY, algorithm="HS256")
                        user.save()
                        content = {
                                    'message': 'OTP validate successfully !!!',
                                    'registration_key': user.registration_key
                                    }
                        return Response(content, status=status.HTTP_200_OK)
                else:
                    content = {'error': 'OTP validation failed !!!'}
                    return Response(content, status=status.HTTP_405_METHOD_NOT_ALLOWED)
            content = {'error': 'User not found !!!'}
            return Response(content, status=status.HTTP_404_NOT_FOUND)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UpdateNewPassword(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        data                = request.data
        serializer = ForgotPasswordSerializer(data=data)
        if serializer.is_valid():
            email     =   data.get('email')
            password  =   serializer.validated_data.get('password')

            user = Account.objects.filter(email = email)
            if user.exists():
                user=user.first()
                user.password = make_password(password)
                user.retrieve_password_otp = None
                user.save()
                content = {'message': 'Password updated successfully !!!'}
                return Response(content, status=status.HTTP_200_OK)
            content = {'error': 'User not found !!!'}
            return Response(content, status=status.HTTP_404_NOT_FOUND)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ActivateInvitationView(APIView):
    permission_classes = [AllowAny]
    def get(self, request, key):

        instance = Account.objects.filter(inviting_key=key)
        if not instance.exists():
            content = {'error': 'Invitation not found !!!'}
            return Response(content, status=status.HTTP_405_METHOD_NOT_ALLOWED)
        user = instance.first()
        
        if user.status != 'Invited':
            content = {'error': 'Invited user is already activated !!!'}
            return Response(content, status=status.HTTP_405_METHOD_NOT_ALLOWED)

        if user.invite_expiry_date >= timezone.now() :
            registration_key = jwt.encode({'email': user.email,'user_type':user.user_type}, 
                            settings.JWT_SECRET_KEY, algorithm="HS256")
            user.registration_key   = registration_key.decode('utf-8')
            user.save()
            content = {
                "registration_key": user.registration_key,
                "email": user.email
            }
            return Response(content, status=status.HTTP_200_OK)
        else:
            content = {'error': 'The link is expired !!!'}
            return Response(content, status=status.HTTP_405_METHOD_NOT_ALLOWED)
        
    def post(self, request,key):
        serializer = ActivateUserSerializer(data=request.data)
        try:
            if serializer.is_valid():
                invitee_email = serializer.validated_data.get('email')
                queryset = Account.objects.filter(email=invitee_email).exclude(status='Deleted')
                if not queryset.exists():
                    content = {'error': 'Invitation not found !!!'}
                    return Response(content, status=status.HTTP_404_NOT_FOUND)
                elif queryset.first().registration_key != key:
                    content = {'error': 'Invalid registration key !!!'}
                    return Response(content, status=status.HTTP_404_NOT_FOUND)
                elif queryset.first().status != 'Invited':
                    content = {'error': 'User already activated !!!'}
                    return Response(content, status=status.HTTP_404_NOT_FOUND)
                else:
                    instance = queryset.first()
                    instance.status               = "Active"
                    instance.password             = make_password(serializer.validated_data.get('password'))
                    instance.save()
                    content = {'Success': 'User Activated Successfully !!!'}
                    subject = 'Notification: Created NMDC Account Successfully'
                    url = settings.FRONTEND_HOST + '/login'
                    context = send_email_context
                    context.update({"full_name": instance.full_name,"link" : url})
                    send_email(subject,context,'users/user_welcome.html',[instance.email])
                    return Response(content, status=status.HTTP_202_ACCEPTED)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error':str(e)},status=status.HTTP_404_NOT_FOUND)

class ChangePasswordView(APIView):
    def put(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        if serializer.is_valid():
            old_password = serializer.validated_data.get('old_password')
            new_password = serializer.validated_data.get('new_password')
            if(request.user.check_password(old_password)):
                request.user.password = make_password(new_password)
                request.user.save()
                content = {'message': 'Password Updated Successfully !'}
                return Response(content, status=status.HTTP_200_OK)
            else:
                content = {
                    'error': 'Old password provided is not matching !'}
                return Response(content, status=status.HTTP_400_BAD_REQUEST)
        else:
            content = {'error': serializer.errors}
            return Response(content, status=status.HTTP_406_NOT_ACCEPTABLE)

        
class ProfileView(APIView):
    def get(self, request):
        userobject = request.user
        return Response( {'user': UserSerializer(userobject).data}, status=status.HTTP_200_OK)

    def patch(self, request):
        userobject = request.user
        data = request.data
        serializer = UserSerializer(instance = userobject, data = data , partial="PATCH")
        serializer.is_valid(raise_exception=True)
        serializer.save()
        if 'avatar' in data and data['avatar'] != "":
            avatar = save_uploaded_image_from_base64(data['avatar'],True)
            if avatar is None:
                return Response({"error":"Invalid Avatar"}, status=status.HTTP_400_BAD_REQUEST)
            userobject.avatar.delete()
            userobject.avatar.save(f'{userobject.full_name}_{uuid.uuid4()}', avatar)
            userobject.thumbnail.delete()
            userobject.create_thumbnail()
        return Response(serializer.data, status=status.HTTP_200_OK)

class ActiveDevicesAPIView(APIView):
    def get(self, request):
        refresh_token = request.COOKIES.get('refresh_token')
        user_access_logs = UserAccessLog.objects.filter(user=request.user,logout_time__isnull=True).exclude(outstanding_token__token=refresh_token)
        current_device = UserAccessLog.objects.get(outstanding_token__token=refresh_token)
        return Response({"all_devices":UserAccessLogSerializer(user_access_logs, many=True).data,
                         "current_device":UserAccessLogSerializer(current_device).data})
    
class BlacklistActiveDeviceAPIView(APIView):
    def patch(self, request,pk):
        try:
            user_access_log =UserAccessLog.objects.get(pk=pk,user=request.user,logout_time__isnull=True)
        except:
            return Response({"message":"The device has already been logged out."})

        BlacklistedToken.objects.get_or_create(token=user_access_log.outstanding_token)
        user_access_log.logout_time = datetime.now()
        user_access_log.logout_type = 'Forced'
        user_access_log.save() 
        return Response({"message":"The device will be logged out in a few minutes.","device":user_access_log.id})
        

class ActiveUserDropdownAPIView(APIView):
    def get(self, request):
        users_list = UserAccessLog.objects.filter(logout_time__isnull=True).exclude(user=request.user).distinct('user')
        serializer = UserAccessLogWithUserSerializer(users_list, many=True)
        return Response(serializer.data)

class BlacklistAPIView(APIView):
    def post(self, request):
        user_id = request.data.get('user_id',None)
        user_types = request.data.get('user_types',[])
        
        outstanding_tokens = OutstandingToken.objects.filter(blacklistedtoken__isnull=True).exclude(user= request.user)
        if user_id:
            outstanding_tokens = outstanding_tokens.filter(user_id= user_id)
        if user_types:
            outstanding_tokens = outstanding_tokens.filter(user__user_type__in = user_types)
            
        for outstanding_token in outstanding_tokens:
            BlacklistedToken.objects.get_or_create(token=outstanding_token)
            save_logout_details(outstanding_token.token,'Forced')
        return Response({"message":"The users will be logged out in a few minutes."})


class LogoutView(APIView):
    def post(self, request):
        try:
            # If you're storing refresh tokens in httpOnly cookies
            refresh_token = request.COOKIES.get('refresh_token')
            if refresh_token:
                token = RefreshToken(refresh_token)
                token.blacklist()

            response = Response({"message": "Logout successful"}, status=status.HTTP_200_OK)
            # Clear cookies for access and refresh tokens
            response.delete_cookie('access_token')
            response.delete_cookie('refresh_token')
            save_logout_details(refresh_token,'Normal')
                
            return response
        except TokenError as e:
            return Response({"error": "Token is invalid or already blacklisted"}, status=403)
        except Exception as e:
            return Response({"error": str(e)}, status=400)
        