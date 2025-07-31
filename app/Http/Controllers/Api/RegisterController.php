<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Http\Requests\RegisterRequest;
use App\Http\Resources\UserResource;
use App\Http\Traits\ApiResponserTrait;
use App\Models\User;
use App\Notifications\OtpUser;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;


class RegisterController extends Controller
{
    use ApiResponserTrait;

    public function register(RegisterRequest $request)
    {
        $otpCode = rand(1000, 9999);

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
            'otp_code' => $otpCode,
            'otp_expires_at' => now()->addMinutes(10),
        ]);

        $user->notify(new OtpUser($otpCode));
        return $this->successResponse(null, 'User registered successfully, please check your email for OTP verification.', 201);
    }

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

            'user' => new UserResource($user),
            'token' => $token,
        ], 'OTP verified and logged in successfully.');
    }

    public function resendOtp(Request $request)
    {
        $request->validate([
            'email' => 'required|email|exists:users,email',
        ]);

        $user = User::where('email', $request->email)->first();

        if (!$user) {
            return $this->errorResponse('User not found.', 404);
        }

        $newOtp = rand(1000, 9999);

        $user->update([
            'otp_code' => $newOtp,
            'otp_expires_at' => now()->addMinutes(10),
        ]);

        $user->notify(new OtpUser($newOtp));

        return $this->successResponse(null, 'OTP code resent. Please check your email.', 200);
    }
}
