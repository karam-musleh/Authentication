<?php

namespace App\Http\Controllers\Api;


use Exception;
// use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Http\Request;

use App\Http\Controllers\Controller;
use App\Http\Requests\UpdateRequest;
use App\Http\Resources\UserResource;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use App\Http\Traits\ApiResponserTrait;


class UserController extends Controller
{
    use ApiResponserTrait;

    public function profile(Request $request)
    {
        $user = Auth::guard('api')->user();

        if (!$user) {
            return $this->errorResponse('User not found', 404);
        }
        return $this->successResponse(new UserResource($user), 'User profile retrieved successfully', 200);
    }
    public function update(UpdateRequest $request)
    {
        $user = Auth::guard('api')->user();

        if (!$user) {
            return $this->errorResponse('User not found', 404);
        }
        $data = $request->validated();
        if (isset($data['password'])) {
            $data['password'] = Hash::make($data['password']);
        }
        $user->update($data);

        return $this->successResponse(
            new UserResource($user),
            'User updated successfully',
            200
        );
    }

    public function delete(Request $request)
    {
        $user = Auth::guard('api')->user();

        if (!$user) {
            return $this->errorResponse('User not found', 404);
        }

        $user->delete();
        return $this->successResponse(null, 'User deleted successfully', 200);
    }
}
