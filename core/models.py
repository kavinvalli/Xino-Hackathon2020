from django.db import models
from django.contrib.auth.models import User

class Places(models.Model):
    name = models.CharField(max_length=100)
    country = models.CharField(max_length=100)

    def __str__(self):
        return self.name

class InterestsActivities(models.Model):
    name = models.CharField(max_length=100)

    def __str__(self):
        return self.name

class CustomUser(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    isGuide = models.BooleanField(default=False)
    place_of_stay = models.ForeignKey(Places, on_delete=models.CASCADE, related_name="guide_play_of_stay", null=True)
    searching_for = models.ForeignKey('self', on_delete=models.SET_NULL, null=True)
    interestCount = models.IntegerField(default=0)
    general_price = models.FloatField(null=True)
    places_of_interest = models.ManyToManyField(Places, related_name='user_places_of_interest')
    interests = models.ManyToManyField(InterestsActivities, related_name='InterestsActivities')

PENDING = 1
INTERESTED = 2
CONFIRMED = 3
STARTED_BY_GUIDE = 4
STARTED = 5
ENDED_BY_GUIDE = 6
ENDED = 7
CANCELLED = 8
PAYMENT = 9
HIRING_STATUS = (
    (PENDING, "Pending Reply"),
    (CONFIRMED, "Confirmed"),
    (STARTED, "Started"),
    (ENDED, "Ended"),
    (CANCELLED, "Cancelled"),
    (PAYMENT, "Paid")
)
class Hiring(models.Model):
    traveller = models.ForeignKey(CustomUser, related_name='hiring_traveller', on_delete=models.SET_NULL, null=True)
    guide = models.ForeignKey(CustomUser, related_name='hiring_guide', on_delete=models.SET_NULL, null=True)
    place = models.ForeignKey(Places, related_name='hiring_place', on_delete=models.SET_NULL, null=True)
    pay = models.FloatField(null=True)
    status = models.IntegerField(choices=HIRING_STATUS, default=1)
    expected_date = models.DateField(null=True)
    start_time = models.DateTimeField(null=True)
    end_time = models.DateTimeField(null=True)
    total_hours = models.IntegerField(null=True)