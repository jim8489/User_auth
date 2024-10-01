from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.sites.shortcuts import get_current_site  # Add this import
from .forms import CreateUserForm, LoginForm
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth import get_user_model

User = get_user_model()

def signup(request):
    if request.user.is_authenticated:
        return redirect('home')
    else:
        form = CreateUserForm()
        if request.method == 'POST':
            form = CreateUserForm(request.POST)
            if form.is_valid():
                email = form.cleaned_data.get('email')
                if User.objects.filter(email=email).exists():
                    messages.error(request, 'An account with this email already exists.')
                    return redirect('signup')
                
                user = form.save(commit=False)
                user.is_active = False  # Deactivate the user until email confirmation
                user.save()

                # Send email verification
                token = default_token_generator.make_token(user)
                current_site = get_current_site(request)
                subject = 'Activate Your Account'
                message = render_to_string('account_activation_email.html', {
                    'user': user,
                    'domain': current_site.domain,
                    'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                    'token': default_token_generator.make_token(user),
                })
                user_email = form.cleaned_data.get('email')
                send_mail(subject, message, 'cse12005007brur@gmail.com', [user_email])

                messages.success(request, 'Account created successfully. Please check your email to activate your account.')
                return redirect('login')

        context = {'form': form}
        return render(request, 'signup.html', context)
    
def activate_account(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(request, 'Your account has been activated successfully. Please log in.')
        return redirect('login')
    else:
        messages.error(request, 'The activation link is invalid or has expired.')
        return redirect('login')
    
def loginUser(request):
    if request.user.is_authenticated:
        return redirect('home')
    else:
        if request.method == 'POST':
            form = LoginForm(request.POST)
            if form.is_valid():
                email = form.cleaned_data['email']
                password = form.cleaned_data['password']
                
                user = authenticate(request, email=email, password=password)
                    
                if user is not None:
                    login(request, user)
                    return redirect('home')
                else:
                    messages.error(request, 'Invalid email or password.')
        else:
            form = LoginForm()
        
        context = {'form': form}
        return render(request, 'login.html', context)

@login_required(login_url='login')
def home(request):
    if request.user.is_authenticated:
        return render(request, 'home.html')
    else:
        return render(request, 'login.html')
        
    
def logoutUser(request):
    logout(request)
    return redirect('login')

