<?php

namespace App\Http\Controllers;

use Exception;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class LoginController extends Controller
{
    public function login(Request $request)
    {
        try {
            $email = $request->email == null;
            if ($email) {
                return response()->json((['success' => false, 'message' => 'email field is required']));
            }
            $passwrod = $request->password == null;
            if ($passwrod) {
                return response()->json((['success' => false, 'message' => 'password field is required']));
            }
            // $check_passwrod =base64_decode($request->password);
            if (Auth::attempt(['email' => $request->email, 'password' => $request->password])) {
                $user = Auth::user();

                // $success['token'] = $user->createToken('MyApp')->accessToken;
                $request = Request::create('oauth/token', 'POST', [
                    "grant_type"=>"password",
                    "client_id" => "3",
                    "client_secret" => "XOXzfQtetIJTrwEJFa6F9kbUN1bPUTRDCVltq7vG",
                    "username" => $request->email,
                    "password" => $request->password,
                    "scope" => ""
                ]);
                $result = app()->handle($request);
                $response = json_decode($result->getContent(), true);
                $success['token']=$response['access_token'];
                $success['refreshToken']=$response['refresh_token'];
                $success['id'] = $user->id;
                $success['name'] = $user->name;
                $success['email'] = $user->email;
                return response()->json(['success' => true, 'user' => $success]);
            } else {
                return response()->json(['success' => false, 'message' => 'Unauthorized access']);
            }
        } catch (Exception $e) {
            return response()->json(["success" => false, "error" => "internal Server error"], 500);
        }
    }

    public function refreshToken(Request $request)
    {
        try{
        if (Auth::guard('api')->check()) {
        $request = Request::create('oauth/token', 'POST', [
            'grant_type' => 'refresh_token',
            'refresh_token' => $request->refreshToken,
            'client_id' => '3',
            'client_secret' => "XOXzfQtetIJTrwEJFa6F9kbUN1bPUTRDCVltq7vG",
            'scope' => '',
        ]);
        $result = app()->handle($request);
        $response = json_decode($result->getContent(), true);
        if(array_key_exists('error', $response))
        {
           return response()->json(['success'=>false,'token'=>$response]);
        }else{
            $user = User::find(Auth::guard('api')->user()->id);
            $success['token']=$response['access_token'];
            $success['refreshToken']=$response['refresh_token'];
            $success['id'] = $user->id;
            $success['name'] = $user->name;
            $success['email'] = $user->email;
            return response()->json(['success'=>true,'user'=>$success]);
        }
        } else {
            return response()->json(["success" => false, "error" => "Not Authorized"], 401);
        }
        } catch (Exception $e) {
            return response()->json(["success" => false, "error" => "internal Server error"], 500);
        }
    }

    //register
    public function register(Request $request)
    {
        $data = new User();
        $data->name = $request->name;
        $data->email = $request->email;
        $data->password = Hash::make($request->password);
        $data->save();

    }
}
