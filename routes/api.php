<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\AuthController;

Route::get('/user', function (Request $request) {
    return $request->user();
})->middleware('auth:sanctum');

Route::post('/login', [AuthController::class, 'login']);
Route::post('/register', [AuthController::class, 'register']);
Route::post('/logout', [AuthController::class, 'logout'])
    ->middleware('auth:api');
// Route::post('/refresh', [AuthController::class, 'refresh'])
//     ->middleware('auth:api');
// Route::post('/refresh', [AuthController::class, 'refresh'])
//     ->middleware('auth:api');
Route::post('/refresh' , [AuthController::class , 'refresh'])->middleware('auth:api');
Route::put('/update', [AuthController::class, 'update'])->middleware('auth:api');
Route::post('/verify-otp', [AuthController::class, 'verifyOtp']);

