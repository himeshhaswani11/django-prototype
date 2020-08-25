from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.models import User, auth
from django.contrib.auth.decorators import login_required
import re

def check_password(password):
    '''
    This function takes password as input and return True when password matches the required expression.
        Parameters:
            password (Alphanumeric String)
        Returns:
            True/False (Boolean)
    '''
    regex = r"^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[a-zA-Z]).{8,16}$"
    matches = re.match(regex, password)
    if matches:
        return True
    else:
        return False

def login_view(request):
    '''
    This function takes request as input and redirect user to Home or Login Page depending on condition.
        Parameters:
            request (object)
        Returns:
            Home or Login page
    '''
    if request.user.is_authenticated:
        return redirect('home')

    elif request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = auth.authenticate(username=username, password=password)
        if user is not None:
            auth.login(request, user)
            return redirect('home')
        else:
            messages.info(request, 'Invalid Username or Password')
            return redirect('login')

    else:
        return render(request, 'login.html')

@login_required(login_url='/login/')
def change_password_view(request):
    '''
    This function takes request as input and redirect user to Change Password or Login Page depending on condition.
    This function even consist of a decorator which verifies is user is authenticated or not.
        Parameters:
            request (object)
        Returns:
            Home or Login page
    '''
    if request.method == 'POST':

        password = request.POST['password']
        confirm_password = request.POST['confirm_password']

        result = check_password(password)

        if not result:
            messages.error(request, 'Password didn\'t matched the required criteria.')
            return redirect('change_password')            

        elif password!=confirm_password:
            messages.info(request, 'Password and Confirmed Password didn\'t matched.')
            return redirect('change_password')            

        else:
            user = request.user
            user.set_password(password)
            user.save()
            logout_view(request)
            messages.success(request, 'Password updated successfully!!')
            return redirect('login')

    else:
        return render(request, 'change_password.html')

def logout_view(request):
    '''
    This function takes request as input and redirect user to Login Page after logout.
        Parameters:
            request (object)
        Returns:
            Login page
    '''
    auth.logout(request)
    return redirect("login")

def register_view(request):
    '''
    This function takes request as input and redirect user Register or Login Page depending on condition.
        Parameters:
            request (object)
        Returns:
            Register or Login page
    '''    
    if request.user.is_authenticated:
        return redirect('home')
    elif request.method == 'POST':
        firstname = request.POST['firstname']
        lastname = request.POST['lastname']
        username = request.POST['username']
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']

        result = check_password(password)
        
        if User.objects.filter(email=username).exists():
            messages.info(request, 'Email already exists.')
            return redirect('register')

        elif not result:
            messages.error(request, 'Password didn\'t matched the required criteria.')
            return redirect('register')            

        elif password!=confirm_password:
            messages.info(request, 'Password and Confirmed Password didn\'t matched.')
            return redirect('register')            

        else:
            user = User.objects.create_user(username=username, password=password, email=username, first_name=firstname, last_name=lastname)
            user.save()
            messages.success(request, 'Account created successfully.')
            return redirect('login')

    else:    
        return render(request, 'register.html')

@login_required(login_url='/login/')
def home_view(request):
    '''
    This function takes request as input and redirect user to Home Page if user is autheticated.
    This function even consist of a decorator which verifies is user is authenticated or not.
        Parameters:
            request (object)
        Returns:
            Home or Login page
    '''
    if not request.user.is_authenticated:
        return redirect('login')
    else:    
        return render(request, 'home.html')