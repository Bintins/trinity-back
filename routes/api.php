<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\API\AuthController;

// Rutas públicas
Route::post('/auth/register', [AuthController::class, 'register']);
Route::post('/auth/login', [AuthController::class, 'login'])->name('login');

// Rutas protegidas (requieren autenticación)
Route::middleware('auth:api')->group(function () {
    Route::post('/auth/profile', [AuthController::class, 'profile']);
    Route::post('/auth/logout', [AuthController::class, 'logout']);
    Route::post('/auth/refresh', [AuthController::class, 'refresh']);
});