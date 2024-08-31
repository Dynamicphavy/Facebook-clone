from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login
from django.db import IntegrityError

def redirect_to_login(request):
    return redirect('login')

def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            request.session['username'] = username
            return redirect('greet')
        else:
            return HttpResponse("Invalid credentials")
    return render(request, 'main/login.html')

def signup_view(request):
    if request.method == 'POST':
        fullname = request.POST.get('fullname')
        username = request.POST.get('username')
        password = request.POST.get('password')

        # Check if any of the fields are empty
        if not fullname or not username or not password:
            error_message = "All fields are required. Please fill out the form completely."
            return render(request, 'main/signup.html', {'error': error_message})
        
        try:
            # Attempt to create the user
            user = User.objects.create_user(username=username, password=password, first_name=fullname)
            request.session['username'] = username
            return redirect('greet')
        except IntegrityError:
            # Handle the case where the username is already taken
            error_message = "Username already exists. Please choose a different one."
            return render(request, 'main/signup.html', {'error': error_message})
        except ValueError:
            # Handle any other value errors (e.g., empty username)
            error_message = "Invalid credentials. Please try again."
            return render(request, 'main/signup.html', {'error': error_message})
        
    return render(request, 'main/signup.html')

def greet_view(request):
    username = request.session.get('username') # Retrieve username from session
    return render(request, 'main/greet.html', {'username': username})