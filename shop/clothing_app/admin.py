from django.contrib import admin
from .models import UserProfile, Category, Product,Cart,Order,OrderItem,Review

admin.site.register(UserProfile)
admin.site.register(Category)
admin.site.register(Product)
admin.site.register(Cart)
admin.site.register(Order)
admin.site.register(OrderItem)
admin.site.register(Review)
