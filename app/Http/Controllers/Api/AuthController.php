<?php

namespace App\Http\Controllers\Api;


use Exception;
// use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Http\Request;
use App\Notifications\OtpUser;

use Tymon\JWTAuth\Facades\JWTAuth;
use App\Http\Requests\LoginRequest;
use App\Http\Controllers\Controller;
use App\Http\Requests\UpdateRequest;
use App\Http\Resources\UserResource;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use App\Http\Requests\RegisterRequest;
use App\Http\Traits\ApiResponserTrait;
use Tymon\JWTAuth\Exceptions\JWTException;

class AuthController extends Controller
{
    use ApiResponserTrait;
    public function register(RegisterRequest $request)
    {
        $otpCode = rand(1000, 9999);
        // $user->otp_code = $otpCode;
        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
            'otp_code' => $otpCode,
            'otp_expires_at' => now()->addMinutes(10)
        ]);
        $user->notify(new OtpUser($otpCode));

        $token = Auth::guard('api')->login($user);

        return $this->successResponse(
            new UserResource($user),
            'User registered successfully',
            201
        );
    }
    public function login(LoginRequest $request)
    {
        $user = User::where('email', $request->email)->first();
        if (!$user) {
            return $this->errorResponse('User not found', 401);
        }
        if (!Hash::check($request->password, $user->password)) {
            return $this->errorResponse('Invalid password', 401);
        }
        // إذا في رمز تحقق موجود، يعني لازم يدخل OTP ويوقف الدخول حتى التحقق
        if (!empty($user->otp_code)) {
            return $this->errorResponse('OTP verification required', 403);
        }

        // لو ما في رمز تحقق، يعني الحساب مفعّل وجاهز للدخول
        $token = Auth::guard('api')->login($user);

        return $this->successResponse(new UserResource($user) ,
            'User logged in successfully',
            200,
            [
                'token' => $token
            ]

        );
    }

    // public function login(LoginRequest $request)
    // {
    //     $user = $request->validated();
    //     $token = Auth::guard('api')->attempt($login);
    //     if (!$token) {
    //         // return response()->json(['error' => 'Unauthorized'], 401);
    //         return $this->errorResponse('Unauthorized', 401);
    //     }
    //     $user = Auth::guard('api')->user();
    //     return $this->successResponse(
    //         new UserResource($user),
    //         'User logged in successfully',
    //         200
    //     );
    // }
    public function logout()
    {
        try {
            auth()->guard('api')->logout();
            return response()->json(['message' => 'User logged out successfully'], 200);
        } catch (JWTException $e) {
            return $this->errorResponse($e->getMessage(), 500);
        }
    }

    // public function refresh()
    // {
    //     try {
    //         $newToken = JWTAuth::parseToken()->refresh();
    //         return response()->json([
    //             'status' => 'success',
    //             'token' => $newToken
    //         ], 200);
    //     } catch (JWTException $e) {
    //         return $this->errorResponse('Could not refresh token', 401);
    //     }
    // }
    public function update(UpdateRequest $request)
    {
        $user = Auth::user();
        $data = $request->validated();
        if (isset($data['password'])) {
            $data['password'] = Hash::make($data['password']);
        }
        dd($data, $user);

        $user->update($data);
        return $this->successResponse(
            new UserResource($user),
            'User updated successfully',
            200
        );
    }

    // public function resendOtp(Request $request)
    // {
    //     $request->validate([
    //         'email' => 'required|email'
    //     ]);

    //     $user = User::where('email', $request->email)->first();

    //     if (!$user) {
    //         return response()->json(['message' => 'User not found.'], 404);
    //     }

    //     $otp = rand(100000, 999999);

    //     $user->update([
    //         'otp_code' => $otp,
    //         'otp_expires_at' =>now()->addMinutes(10)
    //     ]);
    //     $user->notify(new OtpUser($otp));
    //     return response()->json(['message' => 'OTP resent. Check your email.']);
    // }


    public function verifyOtp(Request $request)
    {
        $request->validate([
            'email' => 'required|email|exists:users,email',
            'otp_code' => 'required|digits:4',
        ]);
        $user = User::where('email', $request->email)->first();
        if ($user->otp_code != $request->otp_code) {
            return $this->errorResponse('Invalid OTP code', 400);
        }
        if (now()->greaterThan($user->otp_expires_at)) {
            return $this->errorResponse('OTP code has expired', 400);
        }
        $user->update([
            'otp_code' => null,
            'otp_expires_at' => null,
        ]);
        $token = Auth::guard('api')->login($user);

        return $this->successResponse([
            'token' => $token,
            'user' => new UserResource($user),
        ], 'OTP verified and logged in successfully.');
    }
}
