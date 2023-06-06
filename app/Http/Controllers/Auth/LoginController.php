<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use App\Providers\RouteServiceProvider;
use Illuminate\Foundation\Auth\AuthenticatesUsers;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\ValidationException;

class LoginController extends Controller
{
    /*
    |--------------------------------------------------------------------------
    | Login Controller
    |--------------------------------------------------------------------------
    |
    | This controller handles authenticating users for the application and
    | redirecting them to your home screen. The controller uses a trait
    | to conveniently provide its functionality to your applications.
    |
    */

    use AuthenticatesUsers;

    /**
     * Where to redirect users after login.
     *
     * @var string
     */
    protected $redirectTo = RouteServiceProvider::HOME;

    protected $maxAttempts = 3;

    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('guest')->except('logout');
    }

    public function login(Request $request)
    {
        $this->validateLogin($request);

        if($this->suspendedUser($request)){
            return $this->sendSuspendedUserResponse();
        }

        // If the class is using the ThrottlesLogins trait, we can automatically throttle
        // the login attempts for this application. We'll key this by the username and
        // the IP address of the client making these requests into this application.
        if (method_exists($this, 'hasTooManyLoginAttempts') &&
            $this->hasTooManyLoginAttempts($request)) {
            $this->fireLockoutEvent($request);

            return $this->sendLockoutResponse($request);
        }

        if ($this->attemptLogin($request)) {
            if ($request->hasSession()) {
                $request->session()->put('auth.password_confirmed_at', time());
            }

            $this->clearUserTooManyAttempts($request);

            return $this->sendLoginResponse($request);
        }

        // If the login attempt was unsuccessful we will increment the number of attempts
        // to login and redirect the user back to the login form. Of course, when this
        // user surpasses their maximum number of attempts they will get locked out.
        $this->incrementLoginAttempts($request);

        if($this->afterTooManyLoginAttempts($request)){
            return $this->sendSuspendedUserResponse();
        }

        return $this->sendFailedLoginResponse($request);
    }

    protected function afterTooManyLoginAttempts(Request $request): bool
    {
        if($user = User::where('email', $request->input('email'))->where('too_many_attempts', true)->first()){
            $user->update(['suspended' => true]);
            return true;
        }
        return false;
    }

    protected function suspendedUser(Request $request): bool
    {
        if(User::where('email', $request->input('email'))->where('suspended', true)->first()){
            return true;
        }
        return false;
    }

    protected function clearUserTooManyAttempts(Request $request): void
    {
        User::where('email', $request->input('email'))->where('too_many_attempts', true)->update(['too_many_attempts' => false]);
    }

    /**
     * @throws ValidationException
     */
    protected function sendSuspendedUserResponse()
    {
        throw ValidationException::withMessages([
            $this->username() => ['Your Account is suspended, please contact Admin.'],
        ]);
    }

    /**
     * Login The User
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function api_login(Request $request)
    {
        try {
            $validateUser = Validator::make($request->all(),
                [
                    'email' => 'required|email',
                    'password' => 'required'
                ]);

            if($validateUser->fails()){
                return response()->json([
                    'status' => false,
                    'message' => 'validation error',
                    'errors' => $validateUser->errors()
                ], 401);
            }

            if(!Auth::attempt($request->only(['email', 'password']))){
                return response()->json([
                    'status' => false,
                    'message' => 'Email & Password does not match with our record.',
                ], 401);
            }

            $user = User::where('email', $request->email)->first();

            if($user->tokens()->count() == 2){
                return response()->json([
                    'status' => false,
                    'message' => 'You\'re logged in from two devices',
                ], 401);
            }

            return response()->json([
                'status' => true,
                'message' => 'User Logged In Successfully',
                'token' => $user->createToken("authToken")->accessToken
            ], 200);

        } catch (\Throwable $th) {
            return response()->json([
                'status' => false,
                'message' => $th->getMessage()
            ], 500);
        }
    }

    public function api_logout(): \Illuminate\Http\JsonResponse
    {
        if (Auth::guard('api')->check()) {
            Auth::guard('api')->user()->tokens()->delete();
            return response()->json([
                'status' => true,
                'message' => 'User Logged Out Successfully'
            ], 200);
        }
        return response()->json([
            'status' => false,
            'message' => 'Invalid Data'
        ], 401);
    }
}
