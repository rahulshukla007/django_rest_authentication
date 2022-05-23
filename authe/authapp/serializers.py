from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from xml.dom import ValidationErr
from django.forms import ValidationError
from rest_framework import serializers
from . utils import Util
from . models import User

class UserRegistrationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={'input_type':'password'}, write_only=True)
    class Meta:
        model = User
        fields = ['email', 'name', 'tc', 'password', 'password2']
        extra_kwargs = {
            'password':{'write_only':True}
        }

    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        if password != password2:
            raise serializers.ValidationError('Password and confirm password not match')
        return attrs

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)

class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length = 255)
    class Meta:
        model = User
        fields = ['email', 'password']

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'password']

class UserChangePasswordSerializers(serializers.Serializer):
    password = serializers.CharField(max_length = 255, style={'input_type':'password'}, write_only=True)
    password2 = serializers.CharField(max_length = 255, style={'input_type':'password'}, write_only=True)

    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        user = self.context.get('user')
        if password != password2:
            raise serializers.ValidationError('Password and confirm password not match')
        user.set_password(password)
        user.save()
        return attrs

class SendPasswordResetEmailViewSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length = 255)
    class Meta:
        fields = ['email']

    def validate(self, attrs):
        email = attrs.get('email')
        if User.objects.filter(email = email).exists():
            user = User.objects.get(email = email)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            link = " http://127.0.0.1:8000/reset/" + uid + '/' + token
            body = "Click Following Link to reset your password " + link
            data = {
                'subject' : "Reset your password",
                'body' : body,
                'to_email':user.email
            }
            Util.send_email(data)
            print('link', link)
            return attrs
        else:
            raise ValidationErr("you are not registered user")


class UserPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(max_length = 255, style={'input_type':'password'}, write_only=True)
    password2 = serializers.CharField(max_length = 255, style={'input_type':'password'}, write_only=True)

    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        uid = self.context.get('uid')
        token = self.context.get('token')
        if password != password2:
            raise serializers.ValidationError('Password and confirm password not match')
        id = smart_str(urlsafe_base64_decode(uid))
        user = User.objects.get(id=id)
        if not PasswordResetTokenGenerator().check_token(user, token):
            raise ValidationError("token is not valid or expired")
        user.set_password(password)
        user.save()
        return attrs



