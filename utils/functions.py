import os
import base64
from io import BytesIO
from PIL import Image
from threading import Thread

from django.conf import settings
from django.core.mail import EmailMessage
from django.template.loader import render_to_string,get_template
from django.core.files import File as Files
from django.core.files.base import ContentFile

class SendEmail(Thread):
    def __init__(self, subject, html_message, receivers):
        self.subject = subject
        self.html_message = html_message
        self.sender = settings.SENDER_EMAIL
        self.receivers = receivers
        Thread.__init__(self)

    def run(self):
        message = EmailMessage(
            self.subject, self.html_message, self.sender, self.receivers)
        message.content_subtype = 'html'
        message.send()
        
def send_email(subject,context,template,receivers):
    html_message = render_to_string(template, context)
    SendEmail(subject, html_message, receivers).start()

def generate_pdf(template_path, destination_folder, pdf_content, file_path):
    try:
        if not os.path.isdir(destination_folder):
            os.mkdir(destination_folder)
        if os.path.exists(file_path):
            os.remove(file_path)
        template        =   get_template(template_path)
        html            =   template.render(pdf_content)
        result_file     =   open(file_path, "w+b")
        HTML(string=html).write_pdf(result_file)
        return True
    except Exception as e:
        return False
    
def save_uploaded_image_from_base64(image,is_resize = False):
    try:
        image = image.split(',')[1]
        image = Image.open(BytesIO(base64.b64decode(image)))
        if is_resize and image.width > 200:
            image = image.resize((200, 200))
        if image.mode in ("RGBA", "LA") and image.format == "PNG":
            blob_format = 'PNG'
        else:
            image = image.convert('RGB')
            blob_format = 'JPEG'
        blob    = BytesIO()
        image.save(blob, format=blob_format)
        image = Files(blob)
        return image
    except Exception as e:
        return None
    
def create_thumbnail(image):
    img = Image.open(image)
    if img.mode in ("RGBA", "P"):
        img = img.convert("RGB")
    img.thumbnail((100, 100))
    buffer = BytesIO()
    img.save(buffer, format="JPEG")
    buffer.seek(0)
    return ContentFile(buffer.read())