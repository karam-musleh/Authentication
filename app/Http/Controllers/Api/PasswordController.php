<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Http\Requests\ResetPasswordRequest;
use App\Http\Traits\ApiResponserTrait;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Tymon\JWTAuth\Exceptions\JWTException;

class PasswordController extends Controller
{
    use ApiResponserTrait;

    public function resetPassword(ResetPasswordRequest $request)
    {
        $user = User::where('email', $request->email)->first();

        if (
            !$user ||
            $user->otp_code != $request->otp_code ||
            now()->greaterThan($user->otp_expires_at)
        ) {
            return $this->errorResponse('Invalid or expired OTP', 400);
        }

        $user->update([
            'password' => Hash::make($request->password),
            'otp_code' => null,
            'otp_expires_at' => null,
        ]);

        return $this->successResponse($user, 'Password reset successfully', 200);
    }
}
