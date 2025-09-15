<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * OAuth2 authentication authorization endpoint.
 *
 * @package local_oauth2
 * @author Pau Ferrer Ocaña <pferre22@xtec.cat>
 * @author Lai Wei <lai.wei@enovation.ie>
 * @author Dorel Manolescu <dorel.manolescu@enovation.ie>
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @copyright (C) 2025 Enovation Solutions
 */

use local_oauth2\event\user_granted;
use local_oauth2\event\user_not_granted;

// phpcs:ignore moodle.Files.RequireLogin.Missing -- This file is used to log in users.
require_once(__DIR__ . '/../../config.php');

$clientid = required_param('client_id', PARAM_TEXT);
$responsetype = required_param('response_type', PARAM_TEXT);
$scope = optional_param('scope', false, PARAM_TEXT);
$state = optional_param('state', false, PARAM_TEXT);
$url = new moodle_url('/local/oauth2/login.php', ['client_id' => $clientid, 'response_type' => $responsetype]);

if ($scope) {
    $url->param('scope', $scope);
}

if ($state) {
    $url->param('state', $state);
}

$PAGE->set_url($url);
$PAGE->set_context(context_system::instance());
$PAGE->set_pagelayout('login');

if (isloggedin() && !isguestuser()) {
    $server = local_oauth2\utils::get_oauth_server();

    $request = OAuth2\Request::createFromGlobals();
    $response = new OAuth2\Response();

    if (!$server->validateAuthorizeRequest($request, $response)) {
        $logparams = ['objectid' => $USER->id, 'other' => ['clientid' => $clientid, 'scope' => $scope]];

        $event = user_not_granted::create($logparams);
        $event->trigger();

        $response->send();
        die();
    }

    $isauthorized = local_oauth2\utils::get_authorization_from_form($url, $clientid, $scope);

    $logparams = ['objectid' => $USER->id, 'other' => ['clientid' => $clientid, 'scope' => $scope]];
    if ($isauthorized) {
        $event = user_granted::create($logparams);
        $event->trigger();
    } else {
        $event = user_not_granted::create($logparams);
        $event->trigger();
    }

    $server->handleAuthorizeRequest($request, $response, $isauthorized, $USER->id);
// If successful authorization (302 with Location), capture the auth code and store nonce
//    try {
        // Only proceed if we have a nonce in the incoming request
        $nonce = optional_param('nonce', null, PARAM_TEXT);
        if (!empty($nonce) && $response->getStatusCode() == 302) {
            // Extract the code=... from the Location header
            $headers = $response->getHttpHeaders();
            if (!empty($headers['Location'])) {
                $location = $headers['Location'];
                $parts = parse_url($location);
                if (!empty($parts['query'])) {
                    parse_str($parts['query'], $q);
                    if (!empty($q['code'])) {
                        $code = $q['code'];
                        global $DB;
                        $record = new stdClass();
                        $record->code = $code;
                        $record->nonce = $nonce;
                        $record->createdat = time();
                        // Table name with Moodle prefix
                        $DB->insert_record('local_oauth2_nonce', $record);
                    }
                }
            }
        }
//    } catch (\Throwable $e) {
//        // Non-fatal: do not break the OAuth redirect even if we couldn't store the nonce
//        // Consider logging with error_log() or Moodle debugging if needed
//    }

    $response->send();
} else {
    $SESSION->wantsurl = $url;
    redirect(new moodle_url('/login/index.php'));
}
