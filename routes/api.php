<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Auth\UserAuthController;

Route::get('/user', function (Request $request) {
    return $request->user();
})->middleware('auth:sanctum');



Route::controller(UserAuthController::class)->group(function () {
    Route::post('login','Login')->name('login');
    Route::post('logout','Logout')->middleware('auth:sanctum')->name('logout');
    Route::post('register','Register')->name('register');
    //Email varifaction
    Route::post('send/otp','sendOtp')->middleware('guest');
    Route::post('verify/register/otp','verifyRegisterOtp');
    Route::post('verify/reset/password/otp','verifyResetPasswordOtp');
    Route::post('reset/password','resetPassword')->name('reset.password');



 });
