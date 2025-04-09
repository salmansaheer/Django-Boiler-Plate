import uuid
from datetime import timedelta
from random import randint

from django_currentuser.db.models import CurrentUserField

from django.db import models
from django.conf import settings
from django.utils import timezone
from django.core.validators import RegexValidator
from django.contrib.auth.models import (AbstractBaseUser,BaseUserManager)

from rest_framework.exceptions import ValidationError
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken

from utils.constants import send_email_context
from utils.functions import create_thumbnail, send_email
# Create your models here.

def content_file_name(instance, filename):
    path = 'avatars/' + str(filename) + '.png'
    return path

class MyUserManager(BaseUserManager):
    def create_user(self, email, first_name, password):
        if not email:
            raise ValueError('Users must have an email address')
        user = self.model(
            email=self.normalize_email(email),
            first_name=first_name,
        )
        user.status = 'Active'
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, first_name, password=None, user_type='Superuser'):
        user = self.create_user(
            email,
            password=password,
            first_name=first_name,
        )
        user.user_type = user_type
        user.save(using=self._db)
        return user
    
class Account(AbstractBaseUser):
    id = models.AutoField(primary_key=True)
    email = models.EmailField(verbose_name='email address',unique=True)
    username = models.CharField(max_length=254, null=True)
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100, null=True, blank=True)
    full_name = models.CharField(max_length=200, null=True)
    
    contact_number_validator = RegexValidator(
            regex=r'^\+?\d{9,15}$',
            message="Enter a valid mobile number. It must be between 9 to 15 digits and can optionally start with '+'.")
    contact_number = models.CharField(max_length=15,blank=True, null=True,unique=True,validators=[contact_number_validator])

    USER_TYPE_CHOICES = [
        ('Admin', 'Admin'),
        ('User', 'User'),
        ('Superuser','Superuser'),
    ]
    user_type = models.CharField(max_length=20, choices=USER_TYPE_CHOICES)
    avatar = models.ImageField(upload_to=content_file_name, null=True, blank=True)
    thumbnail = models.ImageField(upload_to='avatars/thumbnails/', null=True, blank=True)
    retrieve_password_otp = models.IntegerField(blank=True, null=True)
    password_otp_expiry_date = models.DateTimeField(verbose_name='created', null=True)
    STATUS_CHOICES = [
        ('Invited', 'Invited'),
        ('Active', 'Active'), 
        ('Disabled', 'Disabled'), 
        ('Deleted', 'Deleted'),
    ]
    status = models.CharField(max_length=10, choices=STATUS_CHOICES)
    remarks = models.TextField(blank=True, null=True)
    inviting_key = models.CharField(max_length=300, blank=True, null=True)
    invited_date = models.DateTimeField(verbose_name='created', auto_now_add=True)
    invite_expiry_date = models.DateTimeField(verbose_name='created', null=True)
    inviter = CurrentUserField(related_name='invited_by_account')
    registration_key = models.CharField(max_length=300, blank=True, null=True)
    
    objects = MyUserManager()
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name']
    
    def save(self, *args, **kwargs):    
        self.username = self.email
        try:
            self.full_name = self.first_name
            if self.last_name:
                self.full_name = self.full_name + ' ' + self.last_name
        except:
            self.full_name = self.first_name
        
        super().save(*args, **kwargs)
        return self

    def has_perm(self, perm, obj=None):
        "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return True

    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True
    
    def forgot_password(self):
        self.retrieve_password_otp = randint(100000, 999999)
        self.password_otp_expiry_date = timezone.now() + timedelta(minutes=10)
        self.save()
        context = send_email_context
        context.update({"otp": self.retrieve_password_otp,"name": self.first_name})
        subject = "Reset your NMDC password"
        send_email(subject,context,'users/forgot_password.html',[self.email])
        
    def save_thumbnail(self):
        if not self.avatar:
            return
        img = create_thumbnail(self.avatar)
        self.thumbnail.save(f"{self.full_name}_{uuid.uuid4()}_thumbnail.jpg", img , save=False)
        super().save(update_fields=["thumbnail"])
        
    def send_invitation(self):
        if not self.email:
            raise ValidationError("No email associated with the user.")
        url = f"{settings.FRONTEND_HOST}public/activation/{self.inviting_key}"
        invitee_name = self.full_name
        inviter_name = self.inviter.full_name
        subject = "Invitation to Join NMDC"
        
        context = send_email_context
        context.update({
            "invitee": invitee_name,
            "inviter" : inviter_name,
            "link" : url})
        send_email(subject,context,'users/invite_email.html',[self.email])

class UserAccessLog(models.Model):
    user = models.ForeignKey(Account, on_delete=models.CASCADE, related_name="login_details")
    ip_address = models.GenericIPAddressField()
    version = models.CharField(max_length = 10,null=True, blank=True)
    browser = models.CharField(max_length = 50,null=True, blank=True)
    os = models.CharField(max_length = 50,null=True, blank=True)
    outstanding_token = models.ForeignKey(OutstandingToken,related_name="user_token",on_delete=models.CASCADE)
    login_time = models.DateTimeField(auto_now_add=True)
    logout_time = models.DateTimeField(null=True, blank=True)
    LOGOUT_TYPE_CHOICES = [
        ('Normal', 'Normal'),
        ('Forced', 'Forced'),
        ('Refresh Token Expired', 'Refresh Token Expired'),
    ]
    logout_type = models.CharField(max_length=21, choices=LOGOUT_TYPE_CHOICES, null=True, blank=True)