<?php
// local/oauth2/db/install.php
defined('MOODLE_INTERNAL') || die();

/**
 * Runs immediately after db/install.xml has been applied.
 * Generates and stores an RSA keypair for JWT signing if not present.
 */
function xmldb_local_oauth2_install() {
    global $DB;

    // Table and lookup key used by the (former) create_keys.php.
    $table = 'local_oauth2_public_key';
    $lookup = ['client_id' => 'global_jwks_key'];

    // Do everything quietly; never echo during install.
    ob_start();
    try {
        // If the table isn't there for some reason, just bail out safely.
        // (Normally, install.xml will have created it before this runs.)
        if (!$DB->get_manager()->table_exists($table)) {
            debugging("Table '{$table}' does not exist yet during install.", DEBUG_DEVELOPER);
            ob_end_clean();
            return true;
        }

        // Skip if a key already exists.
        if ($DB->record_exists($table, $lookup)) {
            ob_end_clean();
            return true;
        }

        // ---- Generate RSA key pair (2048-bit) ----
        if (!function_exists('openssl_pkey_new')) {
            // OpenSSL extension not available – do not break the installer.
            debugging('OpenSSL extension not available; cannot generate RSA keys.', DEBUG_DEVELOPER);
            ob_end_clean();
            return true;
        }

        $opensslconfig = [
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ];

        $res = openssl_pkey_new($opensslconfig);
        if ($res === false) {
            // Collect any OpenSSL error for developer logs.
            $err = function_exists('openssl_error_string') ? openssl_error_string() : 'unknown';
            debugging('Failed to create RSA key pair: ' . $err, DEBUG_DEVELOPER);
            ob_end_clean();
            return true;
        }

        // Export private key (PEM).
        $privatepem = '';
        if (!openssl_pkey_export($res, $privatepem)) {
            $err = function_exists('openssl_error_string') ? openssl_error_string() : 'unknown';
            debugging('Failed to export private key: ' . $err, DEBUG_DEVELOPER);
            ob_end_clean();
            return true;
        }

        // Extract public key (PEM).
        $details = openssl_pkey_get_details($res);
        if ($details === false || empty($details['key'])) {
            debugging('Failed to obtain public key details.', DEBUG_DEVELOPER);
            ob_end_clean();
            return true;
        }
        $publicpem = $details['key'];

        // Optional: derive a stable key identifier (kid) from the public key.
        // Keep this robust even if the column does not exist.
        $kid = substr(sha1($publicpem), 0, 16);

        // Prepare record. Only set known/common fields; extra required fields
        // in your schema (if any) should be added here.
        $record = (object)[
            'client_id'     => $lookup['client_id'],
            'public_key'    => $publicpem,
            'private_key'   => $privatepem,
            'timecreated'   => time(),     // If your table uses timecreated/timemodified.
            'timemodified'  => time(),
        ];

        // If your schema has a 'kid' column, set it (ignore otherwise).
        $columns = $DB->get_columns($table);
        if (isset($columns['kid'])) {
            $record->kid = $kid;
        }

        // Insert and finish.
        $DB->insert_record($table, $record);

    } catch (\Throwable $e) {
        // Never break installation; just log for developers.
        debugging('local_oauth2 install keygen failed: ' . $e->getMessage(), DEBUG_DEVELOPER);
    } finally {
        // Discard any accidental output from OpenSSL or future edits.
        ob_end_clean();
    }

    return true;
}
