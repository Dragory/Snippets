<?php

/**
 * An authentication class for Laravel.
 * Uses BCrypt for password hashing and generates
 * a login token to keep the user logged in.
 */

class Authentication
{
    private $tokenName = 'loginToken';

    private $cryptMethod  = PASSWORD_BCRYPT,
            $cryptOptions = ['cost' => 12];

    private $tokenChars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

    private $authAttemptTimeout = 7200;

    /**
     * Checks if the visitor is logged in and returns
     * the user's ID if so.
     */
    public function getCurrentUser()
    {
        // Get the login token
        $token = Session::get($this->tokenName);
        if ($token == null) $token = Cookie::get($this->tokenName);
        if ($token == null) return null;

        // See if a user exists with the given login token
        $user = DB::table('users')
            ->where('user_token', '=', $token)
            ->first();

        // If a user was not found for the login token,
        // remove the login token from Session and the Cookie.
        if ($user == null)
        {
            Session::forget($this->tokenName);
            Cookie::forget($this->tokenName);

            return null;
        }

        // If a user DOES exist with that login token,
        // we should be fine to log in. Probably.
        // Also refresh the token in the Session.
        Session::put($this->tokenName, $token);

        // If the user has chosen to stay logged in,
        // also refresh the cookie.
        if (Cookie::get('stayLogged') != null)
            Cookie::put($this->tokenName, $token);

        return $user->id_user;
    }

    /**
     * Tries to register a user.
     * Returns true on success and an error code on failure.
     * Can also optionally log the user in after registering.
     */
    public function register($username, $password, $email, $login = false)
    {
        if (empty($username) || empty($password) || empty($email)) return 1; // Fields left empty

        // Make sure nobody else uses the same username and/or E-Mail
        $user = DB::table('users')
            ->where(DB::raw('LOWER(user_username)'), '=', strtolower($username))
            ->or_where(DB::raw('LOWER(user_email)'), '=', strtolower($email))
            ->first();

        if ($user != null)
        {
            if (strtolower($user->user_username) == strtolower($username)) return 2; // Username in use
            else return 3; // E-Mail in use
        }

        // Validate the E-Mail
        if (filter_var($email, FILTER_VALIDATE_EMAIL) === false) return 4; // Invalid E-Mail

        // Register!
        // Get the default group
        $id_group = 0;
        $group = DB::table('groups')
            ->where('group_default', '=', 1)
            ->first();

        if ($group != null) $id_group = $group->id_group;

        // Hash the password
        $hash = password_hash($password, $this->cryptMethod, $this->cryptOptions);

        // Add the user
        DB::table('users')
            ->insert([
                'id_group' => $id_group,
                'user_username' => $username,
                'user_hash' => $hash,
                'user_email' => $email,
            ]);

        // Should we also log in after registering?
        if ($login)
        {
            $this->login($username, $password);
        }

        return true;
    }

    /**
     * Tries to log in with a specified username and password.
     * Staying logged in via cookies is optional.
     * Returns true on success and false on failure.
     */
    public function login($username, $password, $stayLogged = false)
    {
        if (empty($username) || empty($password)) return false;

        // Find the user
        $user = DB::table('users')
            ->where(DB::raw('LOWER(user_username)'), '=', strtolower($username))
            ->first();

        if (!$user) return false;

        // Check the password
        if (!password_verify($password, $user->user_hash)) return false;

        // Do we have a login token?
        if ($user->user_token == null)
        {
            // If not, generate a new one and store it
            $token = $this->generateLoginToken();
            DB::table('users')
                ->where('id_user', '=', $user->id_user)
                ->update(['user_token' => $token]);
        }
        else
        {
            $token = $user->user_token;
        }

        // Log us in
        Session::put($this->tokenName, $token);

        // If the user wanted to stay logged in,
        // save the token in a cookie.
        if ($stayLogged)
            Cookie::put($this->tokenName, $token);

        return true;
    }

    public function changePassword($id_user, $password)
    {
        $hash = password_hash($password, $this->cryptMethod, $this->cryptOptions);
        DB::table('users')
            ->where('id_user', '=', intval($id_user))
            ->update([
                'user_hash' => $hash,
                'user_updated_pass' => 1
            ]);

        return true;
    }

    /**
     * Generates a login token to avoid storing usernames
     * and/or passwords and/or password hashes in the session
     * and/or cookies. This can also be deleted to log the
     * user out everywhere they've logged in from.
     */
    private function generateLoginToken($length = 64)
    {
        $token = '';
        $isUnique = false;
        $tokenCharsLastIndex = strlen($this->tokenChars)-1;

        // While we have not ended up with a valid
        // and unique token
        while (!$isUnique)
        {
            $token = '';

            // Generate the token
            for ($i = 0; $i < $length; $i++)
                $token .= $this->tokenChars[mt_rand(0, $tokenCharsLastIndex)];

            // Check if it exists in the database
            $tokenUser = DB::table('users')
                ->where('user_token', '=', $token)
                ->first();

            if ($tokenUser == null) $isUnique = true;
        }

        // Once we got to a valid token, return it
        return $token;
    }

    /**
     * Adds/logs that an IP has attempted a login
     * and failed.
     */
    public function addAuthAttempt($ip)
    {
        // Get previous auth attempts for this IP
        $attempts = DB::table('auth_attempts')
            ->where('attempt_ip', '=', $ip)
            ->first();

        // If no previous attempts were found,
        // add a new record.
        if ($attempts == null)
        {
            DB::table('auth_attempts')
                ->insert([
                    'attempt_ip' => $ip,
                    'attempt_num' => 1
                ]);
        }
        // Otherwise update our previous records.
        else
        {
            if ($attempts->attempt_time < time() - $this->authAttemptTimeout) $attempts = 0;
            else $attempts = $attempts->attempt_num + 1;

            DB::table('auth_attempts')
                ->where('attempt_ip', '=', $ip)
                ->update([
                    'attempt_num' => $attempts,
                    'attempt_time' => DB::raw('NOW()')
                ]);
        }
    }

    /**
     * Gets the number of authentication attempts
     * for a certain IP.
     */
    public function getAuthAttempts($ip)
    {
        // Get previous auth attempts for this IP
        $attempts = DB::table('auth_attempts')
            ->where('attempt_ip', '=', $ip)
            ->first();

        if ($attempts == null) return 0;
        else return $attempts->attempt_num;
    }
}