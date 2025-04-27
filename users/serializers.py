from rest_framework.serializers import Serializer,EmailField,CharField,ModelSerializer,ImageField,IntegerField
from users.models import Account, UserAccessLog
from rest_framework_simplejwt.tokens import RefreshToken

class LoginSerializer(Serializer):
    email = EmailField()
    password = CharField()
    
    def get_token(self, account):
        refresh = RefreshToken.for_user(account)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }

class UserSerializer(ModelSerializer):
    avatar = ImageField(read_only = True)
    class Meta:
        model = Account
        fields = [
                "id","email","username","first_name",
                "last_name","full_name",'contact_number',
                "is_active","user_type",'status','avatar'
                ,"thumbnail"]
        
class OTPValidateSerializer(Serializer):
    email = EmailField()
    otp = IntegerField()

class ForgotPasswordSerializer(Serializer):
    password = CharField(
        min_length=4,
        max_length=10,
        write_only=True,
        required=True,
        style={'input_type': 'password'}
    )

class ActivateUserSerializer(Serializer):
    email = EmailField()
    password = CharField(
        min_length=8,
        max_length=15,
        write_only=True,
        required=True,
        style={'input_type': 'password'}
    )

class ChangePasswordSerializer(Serializer):
    old_password = CharField(
        min_length=4,
        max_length=20,
        write_only=True,
        required=True,
        style={'input_type': 'password'}
    )
    new_password = CharField(
        min_length=4,
        max_length=10,
        write_only=True,
        required=True,
        style={'input_type': 'password'}
    )

class UserAccessLogSerializer(ModelSerializer):
    class Meta:
        model = UserAccessLog
        fields = ['id','version','browser','os','login_time']

class UserAccessLogWithUserSerializer(ModelSerializer):
    user = UserSerializer()
    class Meta:
        model = UserAccessLog
        fields = ['user']