from django.urls import path
from .views import Homepage
from . import views

urlpatterns = [
    path('', Homepage.as_view(), name='home'),
    path('login/', views.login_function, name='login'),
    path('registration/', views.register_function, name='registration'),
    path("activate/<uidb64>/<token>", views.activate_account, name="activate"),
    path('logout/', views.logout_view, name='logout'),
    path('profile/', views.profile, name='profile'),
    path('travel-dashboard/', views.traveller_dashboard, name='travel-dashboard'),
    path('guide-dashboard/', views.guide_dashboard, name='guide-dashboard'),
    path('guide-detail/<int:guide_id>/', views.guide_detail, name='guide-detail'),
    path('traveller-detail/<int:traveller_id>/<int:hiring_id>', views.traveller_detail, name='traveller-detail'),
    path('traveller-detail/<int:traveller_id>/<int:hiring_id>/yes', views.guide_interested, name='guide-interested'),
    path('traveller-detail/<int:traveller_id>/<int:hiring_id>/no', views.guide_cancelled, name='guide-cancelled'),
    path('traveller-detail/<int:traveller_id>/<int:hiring_id>/confirmed', views.guide_confirmed, name='guide-confirmed'),
    path('traveller-detail/<int:traveller_id>/<int:hiring_id>/started', views.guide_started, name='guide-started'),
    path('traveller-detail/<int:traveller_id>/<int:hiring_id>/ending', views.guide_ending, name='guide-ending'),
    path("activate/<uidb64>/<token>/<int:traveller_id>/<int:guide_id>/<int:hiring_id>", views.start_meeting_link, name="startmeeting"),
    path("end-activate/<uidb64>/<token>/<int:traveller_id>/<int:guide_id>/<int:hiring_id>", views.end_meeting_link, name="endmeeting"),
    path('traveller-detail/<int:traveller_id>/<int:hiring_id>/paid', views.guide_paid, name='guide-paid'),
]
