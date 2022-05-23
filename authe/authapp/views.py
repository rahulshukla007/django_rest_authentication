# from rest_framework.decorators import api_view
# from datetime import datetime
# from rest_framework_simplejwt.authentication import JWTAuthentication

from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated



from .serializers import UserLoginSerializer, UserPasswordResetSerializer, UserRegistrationSerializer,  UserProfileSerializer, UserChangePasswordSerializers, SendPasswordResetEmailViewSerializer
from . renderers import UserRenderer

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

class UserRegistrationView(APIView):
    def post(self, request, format=None):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            token = get_tokens_for_user(user)
            return Response({"token":token, 'msg':'Registration Success'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserLoginView(APIView):
    renderer_classes = [UserRenderer]
    def post(self, request, format=None):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            email       = serializer.data.get('email')
            password    = serializer.data.get('password')
            user        = authenticate(email=email, password=password) 

            if user is not None:
                token = get_tokens_for_user(user)
                return Response({"token":token,'msg':'Login Success'}, status=status.HTTP_200_OK)
            else:
                return Response({'errors':{'non_field_errors':['Email or password is not valid']}}, status=status.HTTP_404_NOT_FOUND)



class UserProfileView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    def get(self, request, format = None):
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data,  status=status.HTTP_200_OK)

class UserChangePasswordView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    def post(self, request, format = None):
        serializer = UserChangePasswordSerializers(data = request.data, 
        context={'user':request.user})
        if serializer.is_valid(raise_exception=True):
            return Response({'msg':'Password changed successfully'}, status=status.HTTP_200_OK)


class SendPasswordResetEmailView(APIView):
    renderer_classes = [UserRenderer]
    def post(self, request, format = None):
        serializer = SendPasswordResetEmailViewSerializer(data = request.data)
        if serializer.is_valid(raise_exception=True):
            return Response({'msg':'Password Reset Link Send. Please Check your email'}, status=status.HTTP_200_OK)

class UserPasswordResetView(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request, uid, token, format=None):
        serializer = UserPasswordResetSerializer(data=request.data, context={
            'uid':uid, 'token':token
        })

        if serializer.is_valid(raise_exception=True):
            return Response({'msg':'Password Reset Successful'}, status=status.HTTP_200_OK)














# class SnippetList(APIView):
#     authentication_classes = [JWTAuthentication]
#     permission_classes = [IsAuthenticated]
#     """
#     List all snippets, or create a new snippet.
#     """
#     def get(self, request, format=None):
#         date = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
#         message = "Clock in server is live current time is "
#         return Response(data = message + date, status=status.HTTP_200_OK)

# # Create your views here.
# @api_view(['GET'])
# def index(request):
#     authentication_classes = [JWTAuthentication]
#     permission_classes = [IsAuthenticated]
#     date = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
#     message = "Clock in server is live current time is "
#     return Response(data = message + date, status=status.HTTP_200_OK)