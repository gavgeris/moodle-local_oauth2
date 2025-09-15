<?php
// This file is part of Moodle - http://moodle.org/
//
// OpenID Connect Discovery Document
//
// @package local_oauth2
// @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later

// phpcs:ignore moodle.Files.RequireLogin.Missing -- This is a discovery endpoint
require_once('../../../config.php');

$baseurl = $CFG->wwwroot . '/local/oauth2';

$config = [
    'issuer' => $baseurl,
    'authorization_endpoint' => $baseurl . '/login.php',
    'token_endpoint' => $baseurl . '/token_oidc.php',
    'userinfo_endpoint' => $baseurl . '/userinfo.php',
    'jwks_uri' => $baseurl . '/jwks.php',  // ← Προσθήκη αυτού
    'response_types_supported' => ['code','id_token'],
    'subject_types_supported' => ['public'],
    'id_token_signing_alg_values_supported' => ['RS256'],
    'scopes_supported' => ['openid', 'profile', 'email', 'login'],
    'claims_supported' => [
        'sub',
        'name', 
        'given_name',
        'family_name',
        'preferred_username',
        'email',
        'email_verified'
    ],
    'grant_types_supported' => ['authorization_code', 'refresh_token']
    'token_endpoint_auth_methods_supported' => ['client_secret_post', 'client_secret_basic'], // ← Σημαντικό
    'code_challenge_methods_supported' => ['S256', 'plain']  // ← Προσθήκη για PKCE support
];

header('Content-Type: application/json');
echo json_encode($config, JSON_PRETTY_PRINT);
?>
