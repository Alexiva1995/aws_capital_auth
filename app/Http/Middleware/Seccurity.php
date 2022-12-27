<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class Seccurity
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure(\Illuminate\Http\Request): (\Illuminate\Http\Response|\Illuminate\Http\RedirectResponse)  $next
     * @return \Illuminate\Http\Response|\Illuminate\Http\RedirectResponse
     */
    public function handle(Request $request, Closure $next)
    {
        if ( $request->header('apikey') != config('services.auth.key') ) 
        {
            abort(403, "api_key dont match.");
        }
        return $next($request);
    }
}
