from django.conf import settings

no_data_value = ' ---- '
send_email_context = {
    "logo":f"{settings.BACKEND_HOST}media/logo/NMDC.png",
    "support_email":"sample",
    "support_phone":"sample",
}