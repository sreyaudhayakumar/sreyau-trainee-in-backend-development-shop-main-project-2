from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.conf import settings
from .forms import UserRegistrationForm, OTPVerificationForm
from .models import UserProfile
from django.contrib import messages
from django.utils.crypto import get_random_string
from django.contrib.auth import authenticate, login as auth_login
from .models import Product, Category,Cart,OrderItem,Review
from .models import Order
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.contrib.auth import logout
from django.db.models import Avg


def register_user(request):
    if request.method == 'POST':
        registration_form = UserRegistrationForm(request.POST)
        if registration_form.is_valid():
            username = registration_form.cleaned_data['username']
            email = registration_form.cleaned_data['email']
            password = registration_form.cleaned_data['password']
            
            user = User.objects.create_user(username=username, email=email, password=password)
        
            otp = get_random_string(length=6, allowed_chars='1234567890')
            user_profile = UserProfile.objects.create(user=user, otp=otp)

            subject = 'Email Verification OTP'
            message = f'Your OTP is: {otp}'
            send_mail(subject, message, settings.EMAIL_HOST_USER, [email])

            return redirect('verify_otp')
    else:
        registration_form = UserRegistrationForm()
    return render(request, 'registration.html', {'registration_form': registration_form})

def verify_otp(request):
    if request.method == 'POST':
        otp_form = OTPVerificationForm(request.POST)
        if otp_form.is_valid():
            otp = otp_form.cleaned_data['otp']
            try:
                user_profile = UserProfile.objects.get(user=request.user)
            except UserProfile.DoesNotExist:
                messages.error(request, 'User profile not found. Please register again.')
                return redirect('/')

            if otp == user_profile.otp:
                user_profile.user.is_active = True
                user_profile.user.save()
                messages.success(request, 'Email verified successfully. You can now login.')
                return redirect('login')
            else:
                messages.error(request, 'Invalid OTP. Please try again.')
    else:
        otp_form = OTPVerificationForm()
    return render(request, 'verify_otp.html', {'otp_form': otp_form})



def base_view(request):
    return render(request, 'base.html')

def base2_view(request):
    return render(request, 'base2.html')

from django.shortcuts import render
from .models import Product


def admin_view(request):
    products = Product.objects.all()
    product = products.first()
    return render(request, 'admin.html', {'products': products, 'product': product})


def login(request):
    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)

        if user is not None:
            auth_login(request, user)

            if user.is_staff:
                return redirect('admin_view')  
            else:
                return redirect('base2') 
        else:
            return render(request, 'login.html', {'error_message': 'Invalid username or password'})

    return render(request, 'login.html')

def logout_view(request):
    logout(request)
    return redirect('login')

def add_category(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        Category.objects.create(name=name)
        return redirect('category_list')
    return render(request, 'add_category.html')


def category_list(request):
    categories = Category.objects.all()
    return render(request, 'category_list.html', {'categories': categories})

def category_detail(request, pk):
    category = get_object_or_404(Category, pk=pk)
    products = Product.objects.filter(category=category)
    return render(request, 'category_details.html', {'category': category, 'products': products})

def men_category(request):
    men_products = Product.objects.filter(category__name='Men')
    return render(request, 'men.html', {'products': men_products})

def women_category(request):
    women_products = Product.objects.filter(category__name='Women')
    return render(request, 'women.html', {'products': women_products})

def kids_category(request):
    kids_products = Product.objects.filter(category__name='Kids')
    return render(request, 'kids.html', {'products': kids_products})

def product_list(request):
    query = request.GET.get('q')
    category_id = request.GET.get('category')
    min_price = request.GET.get('min_price')
    max_price = request.GET.get('max_price')

    products = Product.objects.all()

    if query:
        products = products.filter(Q(name__icontains=query))

    if category_id:
        products = products.filter(category_id=category_id)

    if min_price:
        products = products.filter(price__gte=min_price)

    if max_price:
        products = products.filter(price__lte=max_price)
        
    for product in products:
        product.average_rating = Review.objects.filter(product=product).aggregate(Avg('rating'))['rating__avg']

    categories = Category.objects.all()

    return render(request, 'product_list.html', {'products': products, 'categories': categories})


def product_detail(request, pk):
    product = get_object_or_404(Product, pk=pk)
    all_products = Product.objects.exclude(pk=pk)
    return render(request, 'product_details.html', {'product': product, 'all_products': all_products})

def add_product(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        description = request.POST.get('description')
        price = request.POST.get('price')
        image = request.FILES.get('image')
        category_id = request.POST.get('category')
        available_quantity = request.POST.get('available_quantity')

        category = Category.objects.get(id=category_id)

        Product.objects.create(
            name=name,
            description=description,
            price=price,
            image=image,
            category=category,
            available_quantity=available_quantity
        )
        return redirect('product_list')
    else:
        categories = Category.objects.all()
        return render(request, 'add_product.html', {'categories': categories})

def edit_product(request, pk):
    product = get_object_or_404(Product, pk=pk)
    if request.method == 'POST':
        product.name = request.POST.get('name')
        product.description = request.POST.get('description')
        product.price = request.POST.get('price')
        product.image = request.FILES.get('image')
        category_id = request.POST.get('category')
        product.category = Category.objects.get(id=category_id)
        product.available_quantity = request.POST.get('available_quantity')
        product.save()
        return redirect('product_list')
    else:
        categories = Category.objects.all()
        return render(request, 'edit_product.html', {'product': product, 'categories': categories})

def delete_product(request, pk):
    product = get_object_or_404(Product, pk=pk)
    if request.method == 'POST':
        product.delete()
        return redirect('product_list')
    return render(request, 'delete_product.html', {'product': product})

    

@login_required
def add_to_cart(request, product_id):
    if request.method == 'POST':
        product = get_object_or_404(Product, id=product_id)
        quantity = int(request.POST.get('quantity', 0))
        cart_item, created = Cart.objects.get_or_create(user=request.user, product=product)
        cart_item.quantity += quantity
        cart_item.save()

    return redirect('cart')

@login_required
def cart(request):
    cart_items = Cart.objects.filter(user=request.user)
    total_price = sum(item.calculate_total() for item in cart_items)
    return render(request, 'cart.html', {'cart_items': cart_items, 'total_price': total_price})

@login_required
def update_cart(request, product_id):
    if request.method == 'POST':
        product = get_object_or_404(Product, id=product_id)
        quantity = int(request.POST.get('quantity', 0))
        cart_item = Cart.objects.get(user=request.user, product=product)
        cart_item.quantity = quantity
        cart_item.save()

    return redirect('cart')

@login_required
def delete_from_cart(request, product_id):
    if request.method == 'POST':
        product = get_object_or_404(Product, id=product_id)
        cart_item = Cart.objects.get(user=request.user, product=product)
        cart_item.delete()

    return redirect('cart')

def send_order_confirmation_email(order):
    subject = 'Order Confirmation'
    message = f'Your order has been placed successfully. Order ID: {order.id}'
    send_mail(subject, message, settings.EMAIL_HOST_USER, [order.user.email])

def order_confirmation_view(request, order_id):
    order = Order.objects.get(id=order_id)
    return render(request, 'order_confirmation.html', {'order': order})

@login_required
def checkout_view(request):
    if request.method == 'POST':
        shipping_address = request.POST.get('shipping_address')
        shipping_city = request.POST.get('shipping_city')
        shipping_postal_code = request.POST.get('shipping_postal_code')
        shipping_country = request.POST.get('shipping_country')
        payment_method = request.POST.get('payment_method')

        order = Order.objects.create(
            user=request.user,
            shipping_address=shipping_address,
            shipping_city=shipping_city,
            shipping_postal_code=shipping_postal_code,
            shipping_country=shipping_country,
            payment_method=payment_method,
            total_price=0  
        )
        
        cart_items = Cart.objects.filter(user=request.user)
        for cart_item in cart_items:
            OrderItem.objects.create(
                order=order,
                product=cart_item.product,
                quantity=cart_item.quantity,
                price=cart_item.product.price * cart_item.quantity
            )

      
        order.total_price = sum(item.price for item in order.items.all())
        order.save()
        cart_items.delete()
        return redirect('order_confirmation', order_id=order.id)

    return render(request, 'checkout.html')

def order_confirmation_view(request, order_id):
    order = Order.objects.get(id=order_id)
    return render(request, 'order_confirmation.html', {'order': order})

@login_required
def order_history(request):
    if request.user.is_staff:  
        orders = Order.objects.all()  
    else:
        orders = Order.objects.filter(user=request.user)  
    
    return render(request, 'order_history.html', {'orders': orders})


@login_required
def order_detail(request, order_id):
    order = get_object_or_404(Order, id=order_id)
    
    if request.user.is_superuser or order.user == request.user:
        if request.method == 'POST' and request.user.is_superuser:  
            new_status = request.POST.get('status')
            order.status = new_status
            order.save()
            return redirect('order_detail', order_id=order_id)

        return render(request, 'order_detail.html', {'order': order})
    else:
        return render(request, 'access_denied.html')
    

@login_required
def add_product_review(request, product_id):
    if request.method == 'POST':
        rating = request.POST.get('rating')
        comment = request.POST.get('comment')
        user = request.user
        product = Product.objects.get(id=product_id)
        review = Review.objects.create(user=user, product=product, rating=rating, comment=comment)
        return redirect('thank_you')  
    else:
        product = Product.objects.get(id=product_id)
        return render(request, 'add_product_review.html', {'product': product})
    

def thank_you(request):
    return render(request, 'review_thankyou.html')

def about(request):
    return render(request, 'about.html')

def contact(request):
    return render(request, 'contact.html')

