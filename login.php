<?php
// local/oauth2/login.php — Authorization Endpoint with resilient nonce handling
use core\session\manager;
use OAuth2\Request;
use OAuth2\Response;

require_once(__DIR__ . '/../../config.php');

// --- EARLY CAPTURE: Store nonce by state in session BEFORE any login redirects ---
$state = optional_param('state', null, PARAM_ALPHANUMEXT);
// Nonce can be fairly free-form; keep it trimmed and cap length to 255 (table limit).
$nonce_raw = optional_param('nonce', null, PARAM_RAW_TRIMMED);
$nonce = $nonce_raw !== null ? mb_substr($nonce_raw, 0, 255) : null;

if (!empty($state) && !empty($nonce)) {
    if (!isset($SESSION->local_oauth2_state_nonce) || !is_array($SESSION->local_oauth2_state_nonce)) {
        $SESSION->local_oauth2_state_nonce = [];
    }
    // Record/overwrite the nonce for this state. This survives CAS redirects.
    $SESSION->local_oauth2_state_nonce[$state] = $nonce;
}

// Ensure the user is logged in (CAS may redirect). Session mapping above persists across redirects.
require_login();

// Release session lock while we talk to the OAuth2 server.
manager::write_close();

// Load OAuth2 lib (bshaffer)
require_once($CFG->dirroot . '/local/oauth2/vendor/bshaffer/oauth2-server-php/src/OAuth2/Autoloader.php');
OAuth2\Autoloader::register();

/** @var \OAuth2\Server $server */
$server   = local_oauth2\utils::get_oauth_server();
$request  = Request::createFromGlobals();
$response = new Response();

// Since the user is logged-in, auto-approve. Add consent UI here if you need it.
$isauthorized = true;
$userid = $USER->id;

// Handle the authorization request. On success, this prepares a 302 with ?code=...&state=...
$server->handleAuthorizeRequest($request, $response, $isauthorized, $userid);

/**
 * POST-AUTH: Bind code -> nonce.
 * We extract ?code and ?state from the Location header the OAuth2 server set,
 * look up the nonce from session using 'state', and persist (code, nonce) to DB.
 */
try {
    if ($response->getStatusCode() == 302) {
        $headers = $response->getHttpHeaders();
        if (!empty($headers['Location'])) {
            $location = $headers['Location'];
            $parts = parse_url($location);
            if (!empty($parts['query'])) {
                parse_str($parts['query'], $q);

                $code  = $q['code']  ?? null;
                $stret = $q['state'] ?? ($state ?? null); // fallback if lib doesn't echo state

                // Prefer the nonce just provided in THIS request, else pick from session by state
                $nonce_to_store = $nonce;
                if (empty($nonce_to_store) && !empty($stret)
                    && !empty($SESSION->local_oauth2_state_nonce[$stret])) {
                    $nonce_to_store = $SESSION->local_oauth2_state_nonce[$stret];
                }

                if (!empty($code) && !empty($nonce_to_store)) {
                    global $DB;
                    $rec = (object)[
                        'code'      => $code,
                        'nonce'     => $nonce_to_store,
                        'createdat' => time(),
                    ];
                    // Insert with unique(code); if exists, update.
                    try {
                        $DB->insert_record('local_oauth2_nonce', $rec);
                    } catch (dml_write_exception $ex) {
                        if ($exists = $DB->get_record('local_oauth2_nonce', ['code' => $code])) {
                            $exists->nonce     = $nonce_to_store;
                            $exists->createdat = $rec->createdat;
                            $DB->update_record('local_oauth2_nonce', $exists);
                        } else {
                            debugging('local_oauth2_nonce insert failed: ' . $ex->getMessage(), DEBUG_DEVELOPER);
                        }
                    }
                }

                // Clean up the session entry for this state (one-time use)
                if (!empty($stret) && !empty($SESSION->local_oauth2_state_nonce[$stret])) {
                    unset($SESSION->local_oauth2_state_nonce[$stret]);
                }
            }
        }
    }
} catch (Throwable $e) {
    // Never break the OAuth redirect on bookkeeping failure
    debugging('Nonce binding error: ' . $e->getMessage(), DEBUG_DEVELOPER);
}

// Send the response prepared by the OAuth2 server (302 or JSON error)
$response->send();
exit;
