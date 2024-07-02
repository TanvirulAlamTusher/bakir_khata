<?php

namespace App\Helper;

use Illuminate\Http\JsonResponse;

class ResponseHelper
{
 public static function Out($status,$message,$code,$status_code):JsonResponse{
   return  response()->json(['status' => $status, 'message' =>  $message, 'code' =>  $code],$status_code);
 }
}
