from django.shortcuts import render, redirect
from django.views.generic import View
from django.contrib.auth.models import User
from validate_email import validate_email
from django.contrib import messages

from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_text, DjangoUnicodeDecodeError
from django.core.mail import EmailMessage
from django.contrib.auth import authenticate, login, logout

from django.contrib.auth.tokens import PasswordResetTokenGenerator

from .utils import generate_token
from django.conf import settings

import threading


class EmailThread(threading.Thread):
    def __init__(self, email_message):
        self.email_message = email_message
        threading.Thread.__init__(self)

    def run(self):
        self.email_message.send()


# Create your views here.


class RegistrationView(View):
    def get(self, request):
        return render(request, 'authapp/registration.html')

    def post(self, request):
        data = request.POST

        context = {'data': data, 'has_validation_error': False}

        email = request.POST.get('email')
        username = request.POST.get('username')
        full_name = request.POST.get('fullname')
        new_password = request.POST.get('newpassword')
        confirm_password = request.POST.get('confirmpassword')

        if not validate_email(email):
            context['has_validation_error'] = True
            messages.add_message(request, messages.ERROR,
                                 " Pls provide valid Email Id")

        if User.objects.filter(username=username).exists():
            context['has_validation_error'] = True
            messages.add_message(request, messages.ERROR,
                                 "Username already someone is using.")

        if User.objects.filter(email=email).exists():
            context['has_validation_error'] = True
            messages.add_message(request, messages.ERROR,
                                 "Email already someone is using.")

        if len(new_password) < 6:
            context['has_validation_error'] = True
            messages.add_message(request, messages.ERROR,
                                 "Enter atleast 6 digits for password")

        if new_password != confirm_password:
            context['has_validation_error'] = True
            messages.add_message(request, messages.ERROR,
                                 "Passwords not matching")

        if context['has_validation_error']:
            return render(request, 'authapp/registration.html', context, status=400)

        user = User.objects.create(username=username, email=email)
        user.set_password(new_password)
        user.first_name = full_name
        user.last_name = full_name
        user.is_active = False

        user.save()

        current_site = get_current_site(request)
        email_subject = 'Activate Your Account!!',
        message = render_to_string('authapp/activate.html', {
            'user': user,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'token': generate_token.make_token(user)})

        email_message = EmailMessage(
            email_subject,
            message,
            settings.EMAIL_HOST_USER,
            ['manohaar.d@gmail.com', email]
        )

        EmailThread(email_message).start()

        messages.add_message(request, messages.SUCCESS,
                             "User created successfully!!!")

        return redirect('login')


class LoginView(View):
    def get(self, request):
        return render(request, 'authapp/login.html')

    def post(self, request):
        context = {
            'data': request.POST,
            'has_validation_error': False
        }

        username = request.POST.get('username')
        password = request.POST.get('password')

        if username == '':
            messages.add_message(request, messages.ERROR,
                                 'Username is required!')
            context['has_validation_error'] = True

        if password == '':
            messages.add_message(request, messages.ERROR,
                                 'Password is required!')
            context['has_validation_error'] = True

        user = authenticate(request, username=username, password=password)

        if not user and not context['has_validation_error']:
            messages.add_message(request, messages.ERROR, 'Invalid logins!')
            context['has_validation_error'] = True

        if context['has_validation_error']:
            return render(request, 'authapp/login.html', status=401, context=context)
        login(request, user)
        return redirect('home')


class ActivateAccountView(View):
    def get(self, request, uidb64, token):
        try:
            uid = force_text(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except Exception as identifier:
            user = None

        if user is not None and generate_token.check_token(user, token):
            user.is_active = True
            user.save()
            messages.add_message(request, messages.INFO,
                                 'Account activate successfully!!')
            return redirect('login')
        return render(request, 'authapp/activate_failed.html', status=401)


class HomeView(View):
    def get(self, request):
        return render(request, 'authapp/home.html')


class LogoutView(View):
    def post(self, request):
        logout(request)
        messages.add_message(request, messages.SUCCESS,
                             "Logout successfully!!!")

        return redirect('login')


class RequestResetView(View):
    def get(self, request):
        return render(request, 'authapp/request-reset-email.html')

    def post(self, request):
        email = request.POST['email']
        print(email)

        if not validate_email(email):
            messages.add_message(request, messages.INFO,
                                 'Account activate successfully!!')
            return render(request, 'authapp/request-reset-email.html')

        user = User.objects.filter(email=email)

        if user.exists():
            current_site = get_current_site(request)
            email_subject = '[Reset Your Password!!]',
            message = render_to_string('authapp/reset-password.html', {
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user[0].pk)),
                'token': PasswordResetTokenGenerator().make_token(user[0])})

            email_message = EmailMessage(
                email_subject,
                message,
                settings.EMAIL_HOST_USER,
                ['manohaar.d@gmail.com', email]
            )

            EmailThread(email_message).start()

        messages.add_message(request, messages.SUCCESS,
                             "Sent an email with instructions, to reset your password..!!")
        return render(request, 'authapp/request-reset-email.html')


class SetNewPasswordView(View):
    def get(self, request, uidb64, token):
        context = {
            'uidb64': uidb64,
            'token':   token
        }

        try:
            user_id = force_text(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=user_id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                messages.add_message(request, messages.ERROR,
                                     "Password reset link is expired. Please request agian!!")
                return render(request, 'authapp/request-reset-email.html')

        except DjangoUnicodeDecodeError as identifier:
            messages.add_message(request, messages.ERROR,
                                 "Invalid link. Try agian!!")
            return render(request, 'authapp/request-reset-email.html')

        return render(request, 'authapp/set-new-password.html', context)

    def post(self, request, uidb64, token):
        context = {
            'uidb64': uidb64,
            'token':   token,
            'has_validation_error': False
        }

        new_password = request.POST.get('newpassword')
        confirm_password = request.POST.get('confirmpassword')

        if len(new_password) < 6:
            context['has_validation_error'] = True
            messages.add_message(request, messages.ERROR,
                                 "Enter atleast 6 digits for password")

        if new_password != confirm_password:
            context['has_validation_error'] = True
            messages.add_message(request, messages.ERROR,
                                 "Passwords not matching")

        if context['has_validation_error']:
            return render(request, 'authapp/set-new-password.html', context)

        try:
            user_id = force_text(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=user_id)

            user.set_password(new_password)
            user.save()

            messages.add_message(request, messages.SUCCESS,
                                 "Password reset done!!")
            return redirect('login')

        except DjangoUnicodeDecodeError as identifier:
            messages.add_message(request, messages.ERROR,
                                 "Something went wrong. Try later!!")
            return render(request, 'authapp/set-new-password.html', context)

        return render(request, 'authapp/set-new-password.html', context)
