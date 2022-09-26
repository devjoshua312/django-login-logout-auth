from django.shortcuts import render, redirect
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from django.contrib.auth import login, logout, authenticate
from django.db import IntegrityError


def home(request):
    return render(request, 'users/home.html')


def signup(request):
    if request.method == 'GET':
        return render(request, 'users/signup.html', {'form': UserCreationForm()})
    else:
        if request.POST['password1'] == request.POST['password2']:
            try:
                user = User.objects.create_user(request.POST['username'],
                                                password=request.POST['password1'])
                user.save()
                login(request, user)
                return redirect('currentuserss')

            except IntegrityError:
                return render(request, 'users/signup.html',
                              {'form': UserCreationForm(),
                               'error': 'That username has already been taken. Please choose a new username'})
            else:
                # Tell the user the passwords didn't match
                return render(request, 'users/signup.html',
                              {'form': UserCreationForm(),
                               'error': 'Passwords did not match'})


def login(request):
    if request.method == 'GET':
        return render(request, 'users/login.html', {'form': AuthenticationForm()})
    else:
        user = authenticate(request, username=request.POST['username'],
                            password=request.POST['password'])
        if user is None:
            return render(request, 'users/login.html',
                          {'form': AuthenticationForm(), 'error': 'Username and password did not match'})
        else:
            login(request, user)
            return redirect('home')


def logout(request):
    if request.method == 'POST':
        logout(request)
        return redirect('homepage')



