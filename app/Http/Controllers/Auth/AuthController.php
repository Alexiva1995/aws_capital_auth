<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\Rules\Password;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Foundation\Auth\AuthenticatesUsers;
use Illuminate\Support\Facades\Log;
use Str;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'last_name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => [
                'required', 'string', 'confirmed',
                Password::min(8) // Debe tener por lo menos 8 caracteres
                            ->mixedCase() // Debe tener mayúsculas + minúsculas
                            ->letters() // Debe incluir letras
                            ->numbers() // Debe incluir números
                            ->symbols(), // Debe incluir símbolos,
            ]
        ]);

        if ($validator->fails()) {
            Log::debug('La validacion fallo');
            Log::debug($validator->errors());
            return response()->json($validator->errors()->toJson(), 400);
        }
        $data = $validator->validated();
        $data['password'] = Hash::make($request->password);

        $user = User::create($data);

        $token = JWTAuth::fromUser($user);

        Log::debug('Usuario registrado');

        return response()->json(compact('user', 'token'), 201);
    }

    public function login(Request $request)
    {
        // $emailEncrypt = $request->email;
        // $request->merge([
        //     'email' => Crypt::decrypt($request->email)
        // ]);

        $credentials = $request->only('email', 'password');

        $user = User::where('email', $request->email)->first();

        if(!$user) {
            return response()->json(['success' => false, 'message' => 'Email no registrado.', 'em' => null]);
        }

        if ($token = JWTAuth::attempt($credentials)) {

            return response()->json(['success' => true, 'token' => $token, 'em' => $request->email, 'message' => 'Inicio de sesión exitoso.']);
        }

        return response()->json(['success' => false, 'message' => 'Contraseña incorrecta.', 'em' => null]);
    }
}
