from django.urls import path

from users.views import LoginView

urlpatterns = [
    path('', LoginView.as_view()),
]