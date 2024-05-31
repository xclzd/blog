from django.shortcuts import render
from django.http.response import HttpResponseBadRequest
import re
from users.models import User
from django.db import DatabaseError
from django.shortcuts import redirect
from django.urls import reverse
# Create your views here.
from django.views import View



class RegisterView(View):


    def get(self,request):

        return render(request,'register.html')

    def post(self,request):

        mobile=request.POST.get('mobile')
        password=request.POST.get('password')
        password2=request.POST.get('password2')
        smscode=request.POST.get('sms_code')

        if not all([mobile,password,password2,smscode]):
            return HttpResponseBadRequest('缺少必要的参数')

        if not re.match(r'^1[3-9]\d{9}$',mobile):
            return HttpResponseBadRequest('手机号不符合规则')

        if not re.match(r'^[0-9A-Za-z]{8,20}$',password):
            return HttpResponseBadRequest('请输入8-20位密码，密码是数字，字母')

        if password != password2:
            return HttpResponseBadRequest('两次密码不一致')

        redis_conn=get_redis_connection('default')
        redis_sms_code=redis_conn.get('sms:%s'%mobile)
        if redis_sms_code is None:
            return HttpResponseBadRequest('短信验证码已过期')
        if smscode != redis_sms_code.decode():
            return HttpResponseBadRequest('短信验证码不一致')
        try:
            user=User.objects.create_user(username=mobile,
                                      mobile=mobile,
                                      password=password)
        except DatabaseError as e:
            logger.error(e)
            return HttpResponseBadRequest('注册失败')

        from django.contrib.auth import login
        login(request,user)


        response =  redirect(reverse('home:index'))

        response.set_cookie('is_login',True)
        response.set_cookie('username',user.username,max_age=7*24*3600)


        return response
        # return HttpResponse('注册成功,重定向到首页')

from django.http.response import HttpResponseBadRequest
from libs.captcha.captcha import captcha
from django_redis import get_redis_connection
from django.http import HttpResponse
class ImageCodeView(View):


    def get(self,request):
        uuid=request.GET.get('uuid')

        if uuid is None:
            return HttpResponseBadRequest('没有传递uuid')

        text,image=captcha.generate_captcha()


        redis_conn = get_redis_connection('default')

        redis_conn.setex('img:%s'%uuid,300,text)
        return HttpResponse(image,content_type='image/jpeg')

from django.http.response import JsonResponse
from utils.response_code import RETCODE
import logging
logger=logging.getLogger('django')
from random import randint
from libs.yuntongxun.sms import CCP
class SmsCodeView(View):

    def get(self,request):

        mobile=request.GET.get('mobile')
        image_code=request.GET.get('image_code')
        uuid=request.GET.get('uuid')

        if not all([mobile,image_code,uuid]):
            return JsonResponse({'code':RETCODE.NECESSARYPARAMERR,'errmsg':'缺少必要的参数'})
        redis_conn=get_redis_connection('default')
        redis_image_code=redis_conn.get('img:%s'%uuid)
        if redis_image_code is None:
            return JsonResponse({'code':RETCODE.IMAGECODEERR,'errmsg':'图片验证码已过期'})
        try:
            redis_conn.delete('img:%s' % uuid)
        except Exception as e:
            logger.error(e)

        if redis_image_code.decode().lower() != image_code.lower():
            return JsonResponse({'code':RETCODE.IMAGECODEERR,'errmsg':'图片验证码错误'})

        sms_code= '%04d'%randint(0,9999)

        logger.info(sms_code)

        redis_conn.setex('sms:%s'%mobile,300,sms_code)

        CCP().send_template_sms(mobile,[sms_code,5],1)

        return JsonResponse({'code':RETCODE.OK,'errmsg':'短信发送成功'})

from django.contrib.auth import login
from django.contrib.auth import authenticate

class LoginView(View):

    def get(self, request):



        return render(request, 'login.html')

    def post(self,request):
        # 接受参数
        mobile = request.POST.get('mobile')
        password = request.POST.get('password')
        remember = request.POST.get('remember')

        # 校验参数
        # 判断参数是否齐全
        if not all([mobile, password]):
            return HttpResponseBadRequest('缺少必传参数')

        # 判断手机号是否正确
        if not re.match(r'^1[3-9]\d{9}$', mobile):
            return HttpResponseBadRequest('请输入正确的手机号')

        # 判断密码是否是8-20个数字
        if not re.match(r'^[0-9A-Za-z]{8,20}$', password):
            return HttpResponseBadRequest('密码最少8位，最长20位')

        # 认证登录用户
        # 认证字段已经在User模型中的USERNAME_FIELD = 'mobile'修改
        user = authenticate(mobile=mobile, password=password)

        if user is None:
            return HttpResponseBadRequest('用户名或密码错误')

        # 实现状态保持
        login(request, user)

        # 响应登录结果

        next_page = request.GET.get('next')
        if next_page:
            response = redirect(next_page)
        else:
            response = redirect(reverse('home:index'))

        # 设置状态保持的周期
        if remember != 'on':
            # 没有记住用户：浏览器会话结束就过期
            request.session.set_expiry(0)
            # 设置cookie
            response.set_cookie('is_login', True)
            response.set_cookie('username', user.username, max_age=14 * 24 * 3600)
        else:
            # 记住用户：None表示两周后过期
            request.session.set_expiry(None)
            # 设置cookie
            response.set_cookie('is_login', True, max_age=14 * 24 * 3600)
            response.set_cookie('username', user.username, max_age=14 * 24 * 3600)
        # 返回响应
        return response

from django.contrib.auth import logout

class LogoutView(View):

    def get(self, request):
            # 清理session
        logout(request)
            # 退出登录，重定向到登录页
        response = redirect(reverse('home:index'))
            # 退出登录时清除cookie中的登录状态
        response.delete_cookie('is_login')

        return response


from django.views import View

class ForgetPasswordView(View):

    def get(self, request):

        return render(request, 'forget_password.html')

    def post(self, request):
        # 接收参数
        mobile = request.POST.get('mobile')
        password = request.POST.get('password')
        password2 = request.POST.get('password2')
        smscode = request.POST.get('sms_code')

        # 判断参数是否齐全
        if not all([mobile, password, password2, smscode]):
            return HttpResponseBadRequest('缺少必传参数')

        # 判断手机号是否合法
        if not re.match(r'^1[3-9]\d{9}$', mobile):
            return HttpResponseBadRequest('请输入正确的手机号码')

        # 判断密码是否是8-20个数字
        if not re.match(r'^[0-9A-Za-z]{8,20}$', password):
            return HttpResponseBadRequest('请输入8-20位的密码')

        # 判断两次密码是否一致
        if password != password2:
            return HttpResponseBadRequest('两次输入的密码不一致')

        # 验证短信验证码
        redis_conn = get_redis_connection('default')
        redis_sms_code = redis_conn.get('sms:%s' % mobile)
        if redis_sms_code is None:
            return HttpResponseBadRequest('短信验证码已过期')
        if redis_sms_code.decode() != smscode:
            return HttpResponseBadRequest('短信验证码错误')

        # 根据手机号查询数据
        try:
            user = User.objects.get(mobile=mobile)
        except User.DoesNotExist:
            # 如果该手机号不存在，则注册个新用户
            try:
                User.objects.create_user(username=mobile, mobile=mobile, password=password)
            except Exception:
                return HttpResponseBadRequest('修改失败，请稍后再试')
        else:
            # 修改用户密码
            user.set_password(password)
            user.save()

        # 跳转到登录页面
        response = redirect(reverse('users:login'))

        return response

from django.views import View
from django.contrib.auth.mixins import LoginRequiredMixin

class UserCenterView(LoginRequiredMixin,View):

    def get(self, request):
        # 获取用户信息
        user = request.user

        # 组织模板渲染数据
        context = {
            'username': user.username,
            'mobile': user.mobile,
            'avatar': user.avatar.url if user.avatar else None,
            'user_desc': user.user_desc
        }
        return render(request, 'center.html', context=context)

    def post(self, request):
        # 接收数据
        user = request.user
        avatar = request.FILES.get('avatar')
        username = request.POST.get('username', user.username)
        user_desc = request.POST.get('desc', user.user_desc)

        # 修改数据库数据
        try:
            user.username = username
            user.user_desc = user_desc
            if avatar:
                user.avatar = avatar
            user.save()
        except Exception as e:
            logger.error(e)
            return HttpResponseBadRequest('更新失败，请稍后再试')

        # 返回响应，刷新页面
        response = redirect(reverse('users:center'))
        # 更新cookie信息
        response.set_cookie('username', user.username, max_age=14 * 24 * 3600)
        return response

from home.models import ArticleCategory,Article
class WriteBlogView(LoginRequiredMixin,View):

    def get(self,request):
        # 获取博客分类信息
        categories = ArticleCategory.objects.all()

        context = {
            'categories': categories
        }
        return render(request,'write_blog.html',context=context)

    def post(self, request):
        # 接收数据
        avatar = request.FILES.get('avatar')
        title = request.POST.get('title')
        category_id = request.POST.get('category')
        tags = request.POST.get('tags')
        sumary = request.POST.get('sumary')
        content = request.POST.get('content')
        user = request.user

        # 验证数据是否齐全
        if not all([avatar, title, category_id, sumary, content]):
            return HttpResponseBadRequest('参数不全')

        # 判断文章分类id数据是否正确
        try:
            article_category = ArticleCategory.objects.get(id=category_id)
        except ArticleCategory.DoesNotExist:
            return HttpResponseBadRequest('没有此分类信息')

        # 保存到数据库
        try:
            article = Article.objects.create(
                author=user,
                avatar=avatar,
                category=article_category,
                tags=tags,
                title=title,
                sumary=sumary,
                content=content
            )
        except Exception as e:
            logger.error(e)
            return HttpResponseBadRequest('发布失败，请稍后再试')

        # 返回响应，跳转到文章详情页面
        # 暂时先跳转到首页
        return redirect(reverse('home:index'))


