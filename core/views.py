from django.views.generic import TemplateView
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.http import HttpResponse
from .models import *
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from .token_generator import account_activation_token
from django.core.mail import EmailMessage
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_bytes, force_text
from django.shortcuts import reverse
from django.shortcuts import redirect, get_object_or_404
from django.http import HttpResponse
from django.http import JsonResponse
from django.contrib.auth.decorators import user_passes_test
from django.core import serializers
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from django.core.mail import EmailMessage
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_bytes, force_text
from django.shortcuts import reverse
from django.shortcuts import redirect, get_object_or_404
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
import datetime
from django.utils import timezone

def guide(user):
    customUser = CustomUser.objects.get(user=request.user)
    return customUser.isGuide == True

class Homepage(TemplateView):
    template_name = 'home.html'

def login_function(request):
    if request.method=="POST":
            username = request.POST["email"]
            password = request.POST["password"]
            user = authenticate(request, username=username, password=password)
            if user is not None and user.is_active==True:
                login(request, user)
                # url = "/dashboard/"
                # return redirect(url)
                return redirect('/profile/')
            elif user is not None and user.is_active==False:
                return render(request, "login.html", {"message": "Please Activate your Account."})
            else:
                return render(request, "login.html", {"message": "Invalid credentials."})
    else:
        if not request.user.is_authenticated:
            return render(request, "login.html", {"message": None, 'action_url':'/login/'})
        else:
            # url = "/messenger/"
            # return redirect(url)
            return redirect('/profile/')

def register_function(request):
    if request.method == "POST":
        first_name = request.POST.get("first_name")
        last_name = request.POST.get("last_name")
        email_id = request.POST.get("email")
        # username = request.POST.get("username")
        password = request.POST.get("password")
        try:
            User.objects.get(username=username)
            return render(request, "register.html", {"message": "Username exists"})
        except:
            if "@" not in email_id:
                return render(request, "register.html", {"message": "Invalid Email Id"})
            else:
                if len(password) < 6:
                    return render(request, "register.html", {"message": "Password needs to be atleast 8 characters long"})
                else:
                    try:
                        User.objects.get(email=email_id)
                        return render(request, "register.html", {"message": "User with Email Id exists"})
                    except:
                        user = User.objects.create_user(email_id, email_id, password)
                        user.first_name=first_name
                        user.last_name=last_name
                        user.save()
                        customUser = CustomUser.objects.create(
                            user=user
                        )
                        user.first_name = first_name
                        user.is_active = False
                        user.save()
                        current_site = get_current_site(request)
                        email_subject = 'Trivy - Activate your Account'
                        message = render_to_string('activate_account.html', {
                            'user': user,
                            'domain': current_site.domain,
                            'uid': urlsafe_base64_encode(force_bytes(user.pk)).encode().decode(),
                            'token': account_activation_token.make_token(user),
                        })
                        to_email = request.POST.get('email')
                        from_email = 'info@foop.com'
                        email = EmailMessage(email_subject, message, "Trivy Email Verification <info@foop.com>", to=[to_email])
                        email.send()
                        return render(request, 'goodm.html')
    return render(request, "register.html", {'message':None})

def logout_view(request):
    logout(request)
    return redirect('/')

def activate_account(request, uidb64, token):
    try:
        uid = force_bytes(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()
        return render(request, 'continue.html')
    else:
        return HttpResponse('<h2 style="color:red; text-align:center">Activation link is invalid!</h3>')

@login_required(login_url='/login/')
def profile(request):
    if request.method=="GET":
        interests = InterestsActivities.objects.all()
        customUser = CustomUser.objects.get(user=request.user)
        chosen_interests = customUser.interests.all()
        places = Places.objects.all()
        isGuide = customUser.isGuide
        place = customUser.place_of_stay
        context = {
            'interests':interests,
            'chosen_interests':chosen_interests,
            'places':places,
            'isGuide':isGuide,
            'place':place,
            'customUser':customUser
        }
        return render(request,  'profile.html', context)
    elif request.method=="POST":
        place_id = request.POST.get('places')
        print(place_id)
        isGuideRadio = request.POST.get('isGuide')
        price = request.POST.get('price')
        if isGuideRadio == "on":
            isGuideValue = True
        elif isGuideRadio == None:
            isGuideValue = False
        print(isGuideRadio)
        print(isGuideValue)
        interests = request.POST.getlist('interests')
        print(interests)
        customUser = CustomUser.objects.get(user=request.user)
        customUser.isGuide = isGuideValue
        customUser.save()
        if isGuideValue:
            place = Places.objects.get(id=place_id)
            customUser.place_of_stay=place
            customUser.general_price=price
            customUser.save()
        else:
            customUser.place_of_stay=None
            customUser.general_price=None
            customUser.save()
        interestObjects = []
        for i in interests:
            interestObject = InterestsActivities.objects.get(id=i)
            print(interestObject.name)
            interestObjects.append(interestObject)
            print(interestObjects)
        customUser.interests.clear()
        for i in interestObjects:
            print(i)
            customUser.interests.add(i)
            print(customUser.interests.all())
            print(f"added {i}")
        # customUser.interests.set(interestObjects)
        print(customUser.interests.all())
        url = '/travel-dashboard/'
        return redirect(url)

@login_required(login_url='/login/')
def traveller_dashboard(request):
    if request.method == "GET":
        for guide in CustomUser.objects.filter(isGuide=True):
            guide.searching_for = None
            guide.interestCount = 0
            guide.save()
        customUser = CustomUser.objects.get(user=request.user)
        interests = customUser.interests
        print(interests)
        isGuide = customUser.isGuide
        print(isGuide)
        places = Places.objects.all()
        context = {
            'isGuide':isGuide,
            'places':places
        }
        return render(request,  'traveller_dashboard.html', context)
    elif request.method=="POST":
        customUser = CustomUser.objects.get(user=request.user)
        place_id = request.POST.get('place')
        place_selected = Places.objects.get(id=place_id)
        guides = []
        for guide in CustomUser.objects.filter(place_of_stay=place_selected, isGuide=True):
            print(guide)
            guide.searching_for = customUser
            for i in customUser.interests.all():
                print("i is ",i)
                if guide.interests.filter(name=i.name).exists():
                    guide.interestCount += 1
                    guide.save()
            print(guide.interestCount)
        guidesToSend = CustomUser.objects.filter(place_of_stay=place_selected, isGuide=True, searching_for=customUser).order_by('-interestCount')
        print(guidesToSend)
        print("Guide is",guidesToSend)
        customUser = CustomUser.objects.get(user=request.user)
        interests = customUser.interests.all()
        print(interests)
        isGuide = customUser.isGuide
        print(isGuide)
        places = Places.objects.all()
        print(guidesToSend)
        context = {
            'isGuide':isGuide,
            'places':places,
            'place':place_selected,
            'guides':guidesToSend
        }
        return render(request, 'traveller_dashboard.html', context)

@login_required(login_url='/login/')
def traveller_guide(request):
    customUser = CustomUser.objects.get(user=request.user)
    hirings = Hiring.objects.filter(traveller=customUser).order_by('status')
    context = {
        'hirings':hirings
    }
    return render(request, "traveller_guide.html", context)

@login_required(login_url='/login/')
def guide_dashboard(request):
    customUser = CustomUser.objects.get(user=request.user)
    if request.method == "GET":
        if not customUser.isGuide:
            return HttpResponse('<h2 style="color:red">You need to be a guide to be able to access this page</h2>')
        else:
            hirings = Hiring.objects.filter(guide=customUser).order_by('status')
            context = {
                'hirings':hirings
            }
            return render(request, "guide_dashboard.html", context)

@login_required(login_url='/login/')
def guide_detail(request, guide_id):
    if request.method == "GET":
        guide = CustomUser.objects.get(id=guide_id)
        meUser = CustomUser.objects.get(user=request.user)
        context  = {
            'guide':guide,
            'meUser':meUser
        }
        return render(request, 'guide_detail.html', context)
    elif request.method == "POST":
        expected_date = request.POST.get('date')
        guide = CustomUser.objects.get(id=guide_id)
        meUser = CustomUser.objects.get(user=request.user)
        h = Hiring.objects.create(
            traveller=meUser,
            guide=guide,
            place=guide.place_of_stay,
            status=1,
            expected_date=expected_date
        )
        to_email = guide.user.email
        email_subject = "Trivy - Someone has matched up with you..."
        current_site = get_current_site(request)
        message = render_to_string('recruited.html', {
            'guide': guide,
            'meUser': CustomUser.objects.get(user=request.user),
            'h':h,
            'domain': current_site.domain
        })
        email = EmailMessage(email_subject, message, "Trivy <info@foop.com>", to=[to_email])
        email.send()
        # url = '/guide-detail/'+str(guide_id)
        # return redirect(url)
        context  = {
            'guide':guide,
            'meUser':meUser,
            'message':'Sent an email to the Guide'
        }
        return render(request, 'guide_detail.html', context)

@login_required(login_url='/login/')
def traveller_detail(request, traveller_id, hiring_id):
    if request.method == "GET":
        traveller = CustomUser.objects.get(id=traveller_id)
        meUser = CustomUser.objects.get(user=request.user)
        h = Hiring.objects.get(id=hiring_id)
        context  = {
            'traveller':traveller,
            'meUser':meUser,
            'h':h
        }
        return render(request, 'traveller_detail.html', context)

@login_required(login_url='/login/')
def guide_interested(request, traveller_id, hiring_id):
    if request.method == 'POST':
        traveller = CustomUser.objects.get(id=traveller_id)
        meUser = CustomUser.objects.get(user=request.user)
        h = Hiring.objects.get(id=hiring_id)
        h.status=2
        h.save()
        to_email = traveller.user.email
        email_subject = "Trivy - " + meUser.user.first_name + ' ' + meUser.user.last_name + ' is interested'
        current_site = get_current_site(request)
        message = render_to_string('interested.html', {
            'traveller': traveller,
            'meUser': meUser,
            'domain': current_site.domain
        })
        email = EmailMessage(email_subject, message, "Trivy <info@foop.com>", to=[to_email])
        email.send()
        # url = '/guide-detail/'+str(guide_id)
        # return redirect(url)
        # context  = {
        #     'guide':guide,
        #     'meUser':meUser,
        #     'message':'Sent an email to the Guide'
        # }
        url = '/traveller-detail/'+str(traveller_id)+'/'+str(h.id)
        return redirect(url)

@login_required(login_url='/login/')
def guide_cancelled(request, traveller_id, hiring_id):
    if request.method == 'POST':
        traveller = CustomUser.objects.get(id=traveller_id)
        meUser = CustomUser.objects.get(user=request.user)
        h = Hiring.objects.get(id=hiring_id)
        h.status=8
        h.save()
        to_email = traveller.user.email
        email_subject = "Trivy - " + meUser.user.first_name + ' ' + meUser.user.last_name + ' has cancelled'
        current_site = get_current_site(request)
        message = render_to_string('cancelled.html', {
            'traveller': traveller,
            'meUser': meUser,
            'domain': current_site.domain
        })
        email = EmailMessage(email_subject, message, "Trivy <info@foop.com>", to=[to_email])
        email.send()
        # url = '/guide-detail/'+str(guide_id)
        # return redirect(url)
        # context  = {
        #     'guide':guide,
        #     'meUser':meUser,
        #     'message':'Sent an email to the Guide'
        # }
        url = '/traveller-detail/'+str(traveller_id)+'/'+str(h.id)
        return redirect(url)

@login_required(login_url='/login/')
def guide_confirmed(request, traveller_id, hiring_id):
    if request.method == 'POST':
        traveller = CustomUser.objects.get(id=traveller_id)
        meUser = CustomUser.objects.get(user=request.user)
        h = Hiring.objects.get(id=hiring_id)
        h.status=3
        h.save()
        to_email = traveller.user.email
        email_subject = "Trivy - " + meUser.user.first_name + ' ' + meUser.user.last_name + ' has confirmed'
        current_site = get_current_site(request)
        message = render_to_string('confirmed.html', {
            'traveller': traveller,
            'meUser': meUser,
            'domain': current_site.domain
        })
        email = EmailMessage(email_subject, message, "Trivy <info@foop.com>", to=[to_email])
        email.send()
        # url = '/guide-detail/'+str(guide_id)
        # return redirect(url)
        # context  = {
        #     'guide':guide,
        #     'meUser':meUser,
        #     'message':'Sent an email to the Guide'
        # }
        url = '/traveller-detail/'+str(traveller_id)+'/'+str(h.id)
        return redirect(url)

@login_required(login_url='/login/')
def guide_started(request, traveller_id, hiring_id):
    if request.method == 'POST':
        traveller = CustomUser.objects.get(id=traveller_id)
        meUser = CustomUser.objects.get(user=request.user)
        h = Hiring.objects.get(id=hiring_id)
        h.status=4
        h.save()
        to_email = traveller.user.email
        email_subject = "Trivy - " + meUser.user.first_name + ' ' + meUser.user.last_name + ' has started'
        current_site = get_current_site(request)
        message = render_to_string('started.html', {
            'traveller': traveller,
            'meUser': meUser,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(meUser.pk)).encode().decode(),
            'token': account_activation_token.make_token(meUser.user),
            'h':h
        })
        email = EmailMessage(email_subject, message, "Trivy <info@foop.com>", to=[to_email])
        email.send()
        # url = '/guide-detail/'+str(guide_id)
        # return redirect(url)
        # context  = {
        #     'guide':guide,
        #     'meUser':meUser,
        #     'message':'Sent an email to the Guide'
        # }
        url = '/traveller-detail/'+str(traveller_id)+'/'+str(h.id)
        return redirect(url)


def start_meeting_link(request, uidb64, token, traveller_id, guide_id, hiring_id):
    try:
        uid = force_bytes(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        # user.is_active = True
        # user.save()
        # return render(request, 'continue.html')
        h = Hiring.objects.get(id=hiring_id)
        h.status=5
        h.start_time = timezone.now()
        h.save()
        return HttpResponse('<h2 style="color:#f66666; text-align:center">The meeting has started!</h3>')
    else:
        return HttpResponse('<h2 style="color:red; text-align:center">Activation link is invalid!</h3>')

@login_required(login_url='/login/')
def guide_ending(request, traveller_id, hiring_id):
    if request.method == 'POST':
        traveller = CustomUser.objects.get(id=traveller_id)
        meUser = CustomUser.objects.get(user=request.user)
        h = Hiring.objects.get(id=hiring_id)
        h.status=6
        h.save()
        to_email = traveller.user.email
        email_subject = "Trivy - " + meUser.user.first_name + ' ' + meUser.user.last_name + ' has ended'
        current_site = get_current_site(request)
        message = render_to_string('ending.html', {
            'traveller': traveller,
            'meUser': meUser,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(meUser.pk)).encode().decode(),
            'token': account_activation_token.make_token(meUser.user),
            'h':h
        })
        email = EmailMessage(email_subject, message, "Trivy <info@foop.com>", to=[to_email])
        email.send()
        # url = '/guide-detail/'+str(guide_id)
        # return redirect(url)
        # context  = {
        #     'guide':guide,
        #     'meUser':meUser,
        #     'message':'Sent an email to the Guide'
        # }
        url = '/traveller-detail/'+str(traveller_id)+'/'+str(h.id)
        return redirect(url)

def end_meeting_link(request, uidb64, token, traveller_id, guide_id, hiring_id):
    try:
        uid = force_bytes(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        # user.is_active = True
        # user.save()
        # return render(request, 'continue.html')
        meUser = CustomUser.objects.get(user=request.user)
        guide = CustomUser.objects.get(id=guide_id)
        h = Hiring.objects.get(id=hiring_id)
        h.status=7
        h.end_time = timezone.now()
        timedelta = h.end_time - h.start_time
        seconds = timedelta.days * 24 * 3600 + timedelta.seconds
        minutes, seconds = divmod(seconds, 60)
        hours, minutes = divmod(minutes, 60)
        days, hours = divmod(hours, 24)
        print(hours)
        h.total_hours = hours
        h.pay = guide.general_price * hours
        h.save()
        to_email = guide.user.email
        email_subject = "Trivy - " + meUser.user.first_name + ' ' + meUser.user.last_name + ' has ended. Payment...'
        current_site = get_current_site(request)
        message = render_to_string('payment.html', {
            'guide': guide,
            'meUser': meUser,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(meUser.pk)).encode().decode(),
            'token': account_activation_token.make_token(meUser.user),
            'h':h,
            'pay':h.pay
        })
        email = EmailMessage(email_subject, message, "Trivy <info@foop.com>", to=[to_email])
        email.send()
        return HttpResponse('<h2 style="color:#f66666; text-align:center">The meeting has ended! You need to pay $'+str(h.pay)+' </h3>')
    else:
        return HttpResponse('<h2 style="color:red; text-align:center">Activation link is invalid!</h3>')

@login_required(login_url='/login/')
def guide_paid(request, traveller_id, hiring_id):
    if request.method == 'POST':
        traveller = CustomUser.objects.get(id=traveller_id)
        meUser = CustomUser.objects.get(user=request.user)
        h = Hiring.objects.get(id=hiring_id)
        h.status=9
        h.save()
        to_email = traveller.user.email
        email_subject = "Trivy - We've got confirmation that you have paid"
        current_site = get_current_site(request)
        message = render_to_string('paid.html', {
            'traveller': traveller,
            'meUser': meUser,
            'domain': current_site.domain
        })
        email = EmailMessage(email_subject, message, "Trivy <info@foop.com>", to=[to_email])
        email.send()
        # url = '/guide-detail/'+str(guide_id)
        # return redirect(url)
        # context  = {
        #     'guide':guide,
        #     'meUser':meUser,
        #     'message':'Sent an email to the Guide'
        # }
        url = '/traveller-detail/'+str(traveller_id)+'/'+str(h.id)
        return redirect(url)