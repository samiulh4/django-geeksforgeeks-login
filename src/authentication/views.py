from django.http.response import HttpResponse
from django.shortcuts import redirect, render
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate,login, logout
from gfg import settings
from django.core.mail import send_mail,EmailMessage
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes, force_text
from . tokens import generate_token





def home(request):
    return render(request, 'authentication/index.html')
# end -:- home()


def signup(request):

    if request.method == 'POST':
        username = request.POST['username']
        fname = request.POST['fname']
        lname = request.POST['lname']
        email = request.POST['email']
        pass1 = request.POST['pass1']
        pass2 = request.POST['pass2']
        if User.objects.filter(username=username):
            messages.error(request, 'Username Already Exist, Please Try Another Username !')
            return redirect('home')
        if User.objects.filter(email=email):
            messages.error(request, 'Email Already Exist, Please Try Another Email !')
            return redirect('home') 
        if len(username) < 6:
            messages.error(request, 'Username Must Be Less Than  6 !')
            return redirect('home') 
        if pass1 != pass2:
            messages.error(request, 'Password Not Matched With Confirm !')
            return redirect('home')
        if not username.isalnum():
            messages.error(request, "Username must be Alpha-Numeric !")
            return redirect('home')                
        myuser = User.objects.create_user(username, email, pass1)
        myuser.first_name = fname
        myuser.last_name = lname
        myuser.is_active = False
        myuser.save()
        messages.success(request, 'Your Account Has Been Registered Successfully.')

        # Welcome Email
        subject = "Welcome Message From Django Login App"
        message = "Hello " + myuser.first_name + "! \n" + "Welcome to GFG!! \nThank you for visiting our website\n. We have also sent you a confirmation email, please confirm your email address. \n\nThanking You\nDjango Developer"        
        from_email = settings.EMAIL_HOST_USER
        to_list = [myuser.email]
        send_mail(subject, message, from_email, to_list, fail_silently=True)

        # Email Address Confirmation Email
        current_site = get_current_site(request)
        email_subject = "Confirm your Email @ GFG - Django Login!!"
        message2 = render_to_string('email_confirmation.html',{
            
            'name': myuser.first_name,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(myuser.pk)),
            'token': generate_token.make_token(myuser)
        })
        email = EmailMessage(
        email_subject,
        message2,
        settings.EMAIL_HOST_USER,
        [myuser.email],
        )
        email.fail_silently = True
        email.send()


        return redirect('signin')

    return render(request, 'authentication/signup.html')
# end -:- signup()



def signin(request):
    
    if request.method == 'POST':
        username = request.POST['username']
        pass1 = request.POST['pass1']
        user = authenticate(username=username, password=pass1)
        if user is not None:
            login(request, user)
            fname = user.first_name
            return render(request, 'authentication/index.html', {'fname':fname})
        else:
            messages.error(request, 'Bad Crediential !')
            return redirect('home')  

    return render(request, 'authentication/signin.html')
# end -:- signin()



def signout(request):
    logout(request)
    messages.success(request,'You Are Successfully Logout.')
    return redirect('home')



def activate(request,uidb64,token):
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        myuser = User.objects.get(pk=uid)
    except (TypeError,ValueError,OverflowError,User.DoesNotExist):
        myuser = None

    if myuser is not None and generate_token.check_token(myuser,token):
        myuser.is_active = True
        # user.profile.signup_confirmation = True
        myuser.save()
        login(request,myuser)
        messages.success(request, "Your Account has been activated!!")
        return redirect('home')
    else:
        return render(request,'activation_failed.html')
