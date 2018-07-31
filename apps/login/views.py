# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.shortcuts import render, redirect, HttpResponse
from django.contrib import messages
from models import User
import bcrypt

import re
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

def index(request):
    print "index"
    return render(request, 'login/index.html')

def success(request):
    if not 'user_id' in request.session:
        messages.error(request,"must be logged on to view")
        return redirect('/')
    print "success"
    context = {
        'users': User.objects.all(),
        'jay' : 'silent bob',
        'user': User.objects.get(id = request.session['user_id'])
    }
    return render(request, 'login/success.html', context)

def odell(request):
    return HttpResponse("odell catches everything")

def register(request):
    if not request.POST:
        messages.error(request,"must be logged on to view")
        return redirect ('/')
    #validations
    errors = False
    if len(request.POST['first_name']) < 2:
        messages.error(request, "first name must be 2 or more char")
        print "first name must be 2 or more characters"
        errors = True
    if len(request.POST['last_name']) < 2:
        messages.error(request, "last name must be 2 or more char")
        print "last name must be 2 or more characters"
        errors = True
    if request.POST['password'] != request.POST['confirm_password']:
        messages.error(request, "passwords don't match")
        print "passwords don't match"
        errors = True
    if not EMAIL_REGEX.match(request.POST['email']): # .match??
        messages.error(request, "email invalid")
        errors = True
    if len(User.objects.filter(email=request.POST['email'])) > 0:
        messages.error(request, "email taken")
        errors = True

    if errors == True:
        print "errors == true"
        return redirect('/')
    print "registering"
    # hash the password
    hashed_pw = bcrypt.hashpw(request.POST['password'].encode(), bcrypt.gensalt())

    # create user
    user = User.objects.create(first_name=request.POST['first_name'], last_name=request.POST['last_name'], email=request.POST['email'], password=hashed_pw)

    print user
    print user.first_name
    print user.password

    # store in session

    request.session['user_id'] = user.id
    # redirect to success

    return redirect('/success')

def login(request):
    if not request.POST:
        messages.error(request,"must be logged on to view")
        return redirect ('/')
    print "logging in"
    print request.POST
# comment out

    # user_list = User.objects.filter(email=request.POST['email'])
    # if len(user_list) > 0:
    #     user = user_list[0]
    # else:
    #     messages.error(request,"email not found")
    #     return redirect('/')
# comment out
    try:
        user = User.objects.get(email = request.POST['email'])
    except:
        messages.error(request, "email not found")
        return redirect('/')

    #check pw
    if bcrypt.checkpw(request.POST['password'].encode(), user.password.encode()):
        print "pw match"
    else:
        print "pw fail"
        messages.error(request,"incorrect password")
        return redirect('/')
    request.session['user_id'] = user.id
    return redirect('/success')

def logout(request):
    print "logging out"
    request.session.clear()
    return redirect('/')