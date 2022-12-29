<?php

use App\Http\Controllers\Auth\AuthController;
use App\Http\Middleware\Seccurity;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/
// El middleare Seccurity valida que las peticiones vengan del backend AWS
Route::middleware([Seccurity::class])->group(function(){

    Route::controller(AuthController::class)->group( function($router) {
        Route::post('register', 'register');
        Route::post('login', 'login');
        Route::post('logout', 'logout');
        Route::post('update-password', 'updatePassword');
        // Ruta que devuelve los datos del usuario autenticado si el token es valido y no ha expirado.
        Route::get('me','me');
    });

});

