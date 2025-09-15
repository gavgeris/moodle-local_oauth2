<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

/**
 * OAuth2 UserInfo endpoint for OIDC compatibility
 *
 * @package local_oauth2
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

use core\session\manager;
use OAuth2\Request;
use OAuth2\Response;

// phpcs:ignore moodle.Files.RequireLogin.Missing -- This is an API endpoint
require_once(__DIR__ . '/../../config.php');

manager::write_close();

try {
    // Get access token from Authorization header or query parameter
    $authheader = null;
    $headers = apache_request_headers();
    if (isset($headers['Authorization'])) {
        $authheader = $headers['Authorization'];
    } else if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
        $authheader = $_SERVER['HTTP_AUTHORIZATION'];
    }
    
    $accesstoken = null;
    if ($authheader && strpos($authheader, 'Bearer ') === 0) {
        $accesstoken = substr($authheader, 7);
    } else {
        $accesstoken = optional_param('access_token', null, PARAM_TEXT);
    }

    if (!$accesstoken) {
        header('HTTP/1.1 401 Unauthorized');
        header('Content-Type: application/json');
        echo json_encode(['error' => 'invalid_request', 'error_description' => 'Missing access token']);
        exit;
    }

    // Validate access token
    $storage = new \local_oauth2\moodle_oauth_storage([]);
    $tokendata = $storage->getAccessToken($accesstoken);
    
    if (!$tokendata || $tokendata['expires'] < time()) {
        header('HTTP/1.1 401 Unauthorized');
        header('Content-Type: application/json');
        echo json_encode(['error' => 'invalid_token', 'error_description' => 'Access token expired or invalid']);
        exit;
    }

    // Get user information
    $user = $DB->get_record('user', ['id' => $tokendata['user_id']]);
    if (!$user) {
        header('HTTP/1.1 500 Internal Server Error');
        header('Content-Type: application/json');
        echo json_encode(['error' => 'server_error', 'error_description' => 'User not found']);
        exit;
    }

    // Build OIDC UserInfo response
    $userinfo = [
        'sub' => $user->username,  // Subject - unique identifier
        'name' => fullname($user),
        'given_name' => $user->firstname,
        'family_name' => $user->lastname,
        'preferred_username' => $user->username,
        'email' => $user->email,
        'email_verified' => !empty($user->confirmed),
    ];

    // Add additional claims based on scope
    if (isset($tokendata['scope'])) {
        $scopes = explode(' ', $tokendata['scope']);
        
        if (in_array('profile', $scopes)) {
            // Profile scope already included above
        }
        
        if (in_array('email', $scopes)) {
            // Email scope already included above
        }
    }

    header('Content-Type: application/json');
    echo json_encode($userinfo);

} catch (Exception $e) {
    header('HTTP/1.1 500 Internal Server Error');
    header('Content-Type: application/json');
    if (debugging('', DEBUG_DEVELOPER)) {
        echo json_encode(['error' => 'server_error', 'error_description' => $e->getMessage()]);
    } else {
        echo json_encode(['error' => 'server_error', 'error_description' => 'Internal server error']);
    }
}
?>
