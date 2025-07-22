<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\AuthController;
use App\Http\Controllers\Api\UserController;
use App\Http\Controllers\Api\PasswordController;
use App\Http\Controllers\Api\RegisterController;

Route::get('/user', function (Request $request) {
    return $request->user();
})->middleware('auth:sanctum');

Route::middleware('auth:api')->group(function () {
    Route::get('/profile', [UserController::class, 'profile']);
    Route::put('/update', [UserController::class, 'update']);
    Route::delete('/delete', [UserController::class, 'delete']);
    Route::post('/logout', [AuthController::class, 'logout']);
    Route::post('/refresh', [AuthController::class, 'refresh']);
});
Route::post('/login', [AuthController::class, 'login']);
Route::post('/register', [RegisterController::class, 'register']);
Route::post('/verify-otp', [RegisterController::class, 'verifyOtp']);
Route::post('resend-otp', [RegisterController::class, 'resendOtp']);
Route::post('/reset-password', [PasswordController::class, 'resetPassword']);
