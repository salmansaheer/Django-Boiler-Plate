from rest_framework.serializers import Serializer,EmailField,CharField,ModelSerializer,ImageField
from users.models import Account
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