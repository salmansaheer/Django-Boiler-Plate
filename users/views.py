import jwt
from datetime import datetime, timedelta

from django.shortcuts import get_object_or_404
from django.contrib.auth.hashers import make_password
from django.conf import settings
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import AllowAny,IsAuthenticated
from rest_framework.decorators import APIView
from rest_framework.response import Response
from utils.constants import send_email_context

from .serializers import LoginSerializer, UserSerializer
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
            account.last_login = datetime.now()
            account.save()
            return response
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)