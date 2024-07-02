<?php

namespace App\Http\Controllers\Auth;

use Exception;
use App\Models\User;
use Illuminate\Http\Request;
use App\Helper\ResponseHelper;
use Illuminate\Support\Facades\Log;
use App\Http\Controllers\Controller;
use App\Mail\OtpEmail;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Validator;

class UserAuthController extends Controller
{
    public function Register(Request $request)
    {
        try{
            $rules = [
                'shop_name' => 'required|string|max:255',
                'name' => 'required|string|max:255',
                'email' => 'required|string|email|max:255|unique:users',
                'phone' => 'required|string|max:15|unique:users', // assuming a max length of 15 for phone numbers
                'gender' => 'required|in:male,female',
                'password' => 'required|string|min:6|confirmed',


            ];

            // Validate the request
            $validator = Validator::make($request->all(), $rules);

            if ($validator->fails()) {
                return ResponseHelper::Out('failed',$validator->errors(), '401', 401);

            }
            $email = $request->input('email');


            $otp = rand(1000, 9999);

            $data = [
                'shop_name' => $request->input('shop_name'),
                'name' => $request->input('name'),
                'email' => $request->input('email'),
                'phone' => $request->input('phone'),
                'gender' => $request->input('gender'),
                'password' => Hash::make($request->input('password')),
                'otp' => $otp,
            ];

            // If validation passes, create the user
            $user = User::create($data);

            Mail::to($email)->send(new OtpEmail($otp));

            return ResponseHelper::Out('success', 'OTP sent to your email', '200', 200);

        }catch (Exception $e) {
            Log::error($e);

            return ResponseHelper::Out('failure', $e->getMessage(), '500', 500);
           // return ResponseHelper::Out('failure', 'Something went wrong', '500', 500);

        }



    }
    public function verifyRegisterOtp(Request $request)
    {
     try {
            $rules = [
                'email' => 'required|string|email|max:255|exists:users,email',
                'otp' => 'required|min:4|max:4',

            ];

            $validator = Validator::make($request->all(), $rules);
            if ($validator->fails()) {
                return ResponseHelper::Out('failed',$validator->errors(), '401', 401);
            }


            $count = User::where('email', $request->input('email'))->where('otp', $request->input('otp'))->count();

            if ($count === 1) {
                User::where('email', $request->email)->update([
                    'email_verified_at' => now(),
                    'otp' => '0']);
                return ResponseHelper::Out('success', 'Your Email is verified', '200', 200);
            }
            return ResponseHelper::Out('failure', 'Invalid OTP', '300', 300);

        } catch (Exception $e) {
            Log::error($e);
            return ResponseHelper::Out('failure', 'Something went wrong', '500', 500);

        }

    }



    public function Login(Request $request)
    {

        try {
            $user = User::where('email', $request->input('email'))->first();

            if (!$user || !Hash::check($request->input('password'), $user->password)) {
                return ResponseHelper::Out('failure', 'credentials are incorrect', '401', 401);

            }
            if ($user->email_verified_at === null){
                return ResponseHelper::Out('failure', 'Email is not verified', '403', 403);
            } else {
                $token = $user->createToken('auth_token')->plainTextToken;

                return response()->json([
                    'access_token' => $token,
                    'token_type' => 'Bearer',
                    'code' => '200'
                ], 200);
            }

        } catch (Exception $e) {
            Log::error($e);
            return ResponseHelper::Out('failure', 'Something Went Worng', '500', 500);
        }

    }
    public function Logout()
    {
        try {
            auth()->user()->tokens()->delete();
            return ResponseHelper::Out('success', 'logout', '200', 200);

        } catch (Exception $e) {
            Log::error($e);
            return ResponseHelper::Out('failure', 'Something Went Worng', '500', 500);
        }

    }



    public function sendOtp(Request $request)
    {
        try {
            $rules = [
                'email' => 'required|string|email|max:255|exists:users,email',

            ];

            $validator = Validator::make($request->all(), $rules);
            if ($validator->fails()) {
                return ResponseHelper::Out('failed',$validator->errors(), '401', 401);
            }

            $otp = rand(1000, 9999);

            Mail::to($request->input('email'))->send(new OtpEmail($otp));

            User::where('email', $request->input('email'))->update(['otp' => $otp]);
            return ResponseHelper::Out('success', 'OTP sent to your email', '200', 200);

        } catch (Exception $e) {
            Log::error($e);
            return ResponseHelper::Out('failure', 'Something went wrong', '500', 500);

        }

    }

    public function verifyResetPasswordOtp(Request $request)
    {

        try {
            $rules = [
                'email' => 'required|string|email|max:255|exists:users,email',
                'otp' => 'required|min:4|max:4',

            ];

            $validator = Validator::make($request->all(), $rules);
            if ($validator->fails()) {
                return ResponseHelper::Out('failed',$validator->errors(), '401', 401);
            }


            $count = User::where('email', $request->input('email'))->where('otp', $request->input('otp'))->count();

            if ($count === 1) {
                User::where('email', $request->email)->update(['otp' => '0']);
                return ResponseHelper::Out('success', 'Otp is verified', '200', 200);
            }
            return ResponseHelper::Out('failure', 'Invalid OTP', '300', 300);

        } catch (Exception $e) {
            Log::error($e);
            return ResponseHelper::Out('failure', 'Something went wrong', '500', 500);

        }

    }

    public function resetPassword(Request $request)
    {

        try {
            $rules = [
                'email' => 'required|string|email|max:255|exists:users,email',
                'password' => 'required|string|min:6|confirmed',

            ];

            $validator = Validator::make($request->all(), $rules);
            if ($validator->fails()) { return ResponseHelper::Out('failed',$validator->errors(), '401', 401);
            }

            $hashedPassword = Hash::make($request->input('password')); // Hash the new password

            User::where('email', $request->input('email'))->update(['password' => $hashedPassword]);
            return ResponseHelper::Out('success', 'Password reset successfully', '200', 200);
        } catch (Exception $e) {
            Log::error($e);
            return ResponseHelper::Out('failed','Something went wrong', '500', 500);
        }

    }





}
