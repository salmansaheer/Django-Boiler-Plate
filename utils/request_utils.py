from datetime import datetime
import json
from users.models import UserAccessLog
from user_agents import parse
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken

def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def get_device_details(user_agent):
    ua = parse(user_agent)
    return {
        "version": None,  # e.g., "iPhone", "Windows PC"
        "os": f"{ua.os.family} {ua.os.version_string}",  # e.g., "iOS 14.2"
        "browser": f"{ua.browser.family} {ua.browser.version_string}"  # e.g., "Chrome 91.0"
    }

def save_login_details(user,request,refresh_token,version_code):
    user_agent = request.META.get("HTTP_USER_AGENT")
    if not version_code:
        user_agent = get_device_details(user_agent) # web interface
    else:
        user_agent = json.loads(user_agent) # app interface
    token = OutstandingToken.objects.get(token = refresh_token)
    ip = get_client_ip(request)
    UserAccessLog.objects.create(user =user,
                                ip_address = ip,
                                login_time = datetime.now(),
                                version = user_agent.get("version"),
                                browser = user_agent.get("browser"),
                                os = user_agent.get("os"),
                                outstanding_token = token
    )

def save_logout_details(refresh_token,logout_type):
    try:
        user_access_log = UserAccessLog.objects.get(outstanding_token__token=refresh_token)
        user_access_log.logout_time = datetime.now()
        user_access_log.logout_type = logout_type
        user_access_log.save()
    except UserAccessLog.DoesNotExist:
        pass