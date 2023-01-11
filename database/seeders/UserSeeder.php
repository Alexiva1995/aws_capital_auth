<?php

namespace Database\Seeders;

use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Support\Facades\Hash;
use Illuminate\Database\Seeder;
use Illuminate\Support\Str;
use App\Models\User;

class UserSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run()
    {
        User::create([
            'name'=> 'user',
            'last_name'=> 'admin',
            'email'=> 'admin@awscapital.com',
            'password' => Hash::make('123456789'),
        ]);

        User::create([
            'name'=> 'user',
            'last_name'=> 'user',
            'email'=> 'user@awscapital.com',
            'password' => Hash::make('123456789'),
        ]);
    }
}
