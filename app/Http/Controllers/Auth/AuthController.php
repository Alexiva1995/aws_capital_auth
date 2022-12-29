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
    /**
     * Registra a un nuevo usuario
     *
     * @return \Illuminate\Http\JsonResponse
     */
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
            return response()->json($validator->errors()->toJson(), 400);
        }
        $data = $validator->validated();
        $data['password'] = Hash::make($request->password);

        $user = User::create($data);

        // $token = JWTAuth::fromUser($user);

        return response()->json(['user' => $user], 201);
    }

    public function login(Request $request)
    {
        $credentials = $request->only('email', 'password');

        $user = User::where('email', $request->email)->first();

        if(!$user) {
            return response()->json(['success' => false, 'message' => 'Email no registrado.', 'em' => null]);
        }

        if ($token = JWTAuth::attempt($credentials)) {

            return response()->json(['success' => true, 'token' => $token, 'em' => $request->email, 'message' => 'Inicio de sesión exitoso.'],200);
        }

        return response()->json(['success' => false, 'message' => 'Contraseña incorrecta.', 'em' => null],400);
    }
    /**
     * Obtiene el token JWT y valida. Comprueba si es tun token valido. (Cumple la función de middleware)
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function me(Request $request)
    {
        try {
            $user = JWTAuth::parseToken()->authenticate();

            return response()->json(['status' => 'success', 'user' => $user],200);
            
        } catch (Exception $th) {

            if($e instanceof TokenInvalidException) {
                return response()->json(['status' => 'invalid token'],401);
            }

            if($e instanceof TokenExpiredException){
                return response()->json(['status' => 'expired token'],401);
            }
            return response()->json(['status' => 'token not found'],401);
        }

    }
    /**
     * Invalida el token JWT del usuario para cerrar sesión
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        JWTAuth::parseToken()->invalidate();

        return response()->json(['status' => 'success', 'message' => 'ha cerrado la sesión exitosamente'],200);
    }
    /**
     * Actualiza la password del usuario
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function updatePassword(Request $request)
    {
        $user = User::where('email', $request->email)->first();

        $user->update(['password' => Hash::make($request->password)]);

        $response = ['status' => 'success', 'message' => 'Su contraseña ha sido actualizada con exito'];

        return response()->json($response, 200);
    }
}
