<?php

/**
 * Security Checklist Dashboard
 * Displays a Tools > Security Checklist page with pass/fail checks.
 */

if (!defined('ABSPATH')) {
    exit;
}

function bbp_security_audit_menu()
{
    add_management_page(
        __('Security Checklist', 'barebones'),
        __('Security Checklist', 'barebones'),
        'manage_options',
        'bbp-security-checklist',
        'bbp_security_checklist_page'
    );
}
add_action('admin_menu', 'bbp_security_audit_menu');

function bbp_security_checklist_page()
{
    if (!current_user_can('manage_options')) {
        wp_die(__('You do not have sufficient permissions to access this page.', 'barebones'));
    }

    if (!function_exists('is_plugin_active')) {
        require_once ABSPATH . 'wp-admin/includes/plugin.php';
    }

    $checks = [];
    $errors = [];

    try {
        $checks = bbp_get_security_checks();
    } catch (\Throwable $e) {
        $errors[] = $e->getMessage();
    }

    $pass_count = 0;
    $fail_count = 0;
    $warn_count = 0;
    $total = count($checks);
    foreach ($checks as $check) {
        if ($check['status'] === 'pass') {
            $pass_count++;
        } elseif ($check['status'] === 'fail') {
            $fail_count++;
        } else {
            $warn_count++;
        }
    }
    ?>
    <div class="wrap">
        <h1><?php esc_html_e('Security Checklist', 'barebones'); ?> <a href="<?php echo esc_url(admin_url('tools.php?page=bbp-security-checklist')); ?>" class="button button-secondary"><?php esc_html_e('Refresh', 'barebones'); ?></a></h1>

        <?php if (!empty($errors)) : ?>
            <div class="notice notice-error">
                <?php foreach ($errors as $error) : ?>
                    <p><?php echo esc_html($error); ?></p>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>

        <p>
            <span style="color:#00a32a;font-weight:bold;"><?php printf(esc_html__('%d Passed', 'barebones'), $pass_count); ?></span> &nbsp;|&nbsp;
            <span style="color:#d63638;font-weight:bold;"><?php printf(esc_html__('%d Failed', 'barebones'), $fail_count); ?></span> &nbsp;|&nbsp;
            <span style="color:#dba617;font-weight:bold;"><?php printf(esc_html__('%d Warnings', 'barebones'), $warn_count); ?></span>
        </p>

        <table class="wp-list-table widefat fixed striped">
            <thead>
                <tr>
                    <th style="width:5%;"><?php esc_html_e('#', 'barebones'); ?></th>
                    <th style="width:20%;"><?php esc_html_e('Check', 'barebones'); ?></th>
                    <th style="width:10%;"><?php esc_html_e('Status', 'barebones'); ?></th>
                    <th style="width:35%;"><?php esc_html_e('Description', 'barebones'); ?></th>
                    <th style="width:30%;"><?php esc_html_e('How to Resolve', 'barebones'); ?></th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($checks as $i => $check) : ?>
                <tr>
                    <td><?php echo $i + 1; ?></td>
                    <td><strong><?php echo esc_html($check['label']); ?></strong></td>
                    <td>
                        <?php if ($check['status'] === 'pass') : ?>
                            <span class="bbp-tooltip" style="color:#00a32a;font-weight:bold;" data-bbp-tooltip="<?php esc_attr_e('This check is satisfied. No action needed.', 'barebones'); ?>"><?php esc_html_e('Pass', 'barebones'); ?></span>
                        <?php elseif ($check['status'] === 'fail') : ?>
                            <span class="bbp-tooltip" style="color:#d63638;font-weight:bold;" data-bbp-tooltip="<?php esc_attr_e('Your site is actively vulnerable. An attacker could exploit this right now. Fix immediately.', 'barebones'); ?>"><?php esc_html_e('Fail', 'barebones'); ?></span>
                        <?php else : ?>
                            <span class="bbp-tooltip" style="color:#dba617;font-weight:bold;" data-bbp-tooltip="<?php esc_attr_e('Recommended hardening. Not an immediate exploit path, but should be addressed when possible.', 'barebones'); ?>"><?php esc_html_e('Warning', 'barebones'); ?></span>
                        <?php endif; ?>
                    </td>
                    <td><?php echo esc_html($check['description']); ?></td>
                    <td><?php echo wp_kses_post($check['resolution']); ?></td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>

        <style>
            .bbp-tooltip {
                position: relative;
                cursor: pointer;
            }
            .bbp-tooltip::after {
                content: attr(data-bbp-tooltip);
                position: absolute;
                bottom: 125%;
                left: 50%;
                transform: translateX(-50%);
                background: #1d2327;
                color: #fff;
                padding: 8px 12px;
                border-radius: 4px;
                font-size: 12px;
                font-weight: normal;
                line-height: 1.4;
                white-space: nowrap;
                z-index: 10000;
                opacity: 0;
                pointer-events: none;
                transition: opacity 0.2s;
            }
            .bbp-tooltip:hover::after {
                opacity: 1;
            }
        </style>
    </div>
    <?php
}

function bbp_plugin_active($plugin_path)
{
    if (!function_exists('is_plugin_active')) {
        require_once ABSPATH . 'wp-admin/includes/plugin.php';
    }
    return is_plugin_active($plugin_path);
}

function bbp_get_security_checks()
{
    global $table_prefix;
    $checks = [];

    $checks[] = [
        'label'       => __('Database Table Prefix', 'barebones'),
        'status'      => ($table_prefix !== 'wp_') ? 'pass' : 'fail',
        'description' => __('The database table prefix should not be the default "wp_". A custom prefix makes SQL injection attacks harder to target.', 'barebones'),
        'resolution'  => __('Change <code>$table_prefix</code> in <code>wp-config.php</code> to a unique value like <code>wp_s4lt_</code>. Note: this requires renaming existing database tables if the site is already installed.', 'barebones'),
    ];

    $checks[] = [
        'label'       => __('DISALLOW_FILE_EDIT', 'barebones'),
        'status'      => (defined('DISALLOW_FILE_EDIT') && DISALLOW_FILE_EDIT) ? 'pass' : 'fail',
        'description' => __('The theme/plugin file editor should be disabled to prevent admins from editing code directly in the dashboard, which is a security risk.', 'barebones'),
        'resolution'  => __('Add <code>define(\'DISALLOW_FILE_EDIT\', true);</code> to <code>wp-config.php</code>.', 'barebones'),
    ];

    $checks[] = [
        'label'       => __('FORCE_SSL_ADMIN', 'barebones'),
        'status'      => (defined('FORCE_SSL_ADMIN') && FORCE_SSL_ADMIN) ? 'pass' : 'warning',
        'description' => __('Admin area and login pages should be forced to use HTTPS to prevent credential interception.', 'barebones'),
        'resolution'  => __('Add <code>define(\'FORCE_SSL_ADMIN\', true);</code> to <code>wp-config.php</code>. Ensure SSL certificate is properly configured first.', 'barebones'),
    ];

    $checks[] = [
        'label'       => __('WP_AUTO_UPDATE_CORE', 'barebones'),
        'status'      => defined('WP_AUTO_UPDATE_CORE') ? 'pass' : 'warning',
        'description' => __('WordPress core should be set to auto-update to ensure security patches are applied promptly.', 'barebones'),
        'resolution'  => __('Add <code>define(\'WP_AUTO_UPDATE_CORE\', true);</code> to <code>wp-config.php</code> for all updates, or <code>\'minor\'</code> for minor and security only.', 'barebones'),
    ];

    $checks[] = [
        'label'       => __('ALLOW_UNFILTERED_UPLOADS', 'barebones'),
        'status'      => (defined('ALLOW_UNFILTERED_UPLOADS') && ALLOW_UNFILTERED_UPLOADS) ? 'fail' : 'pass',
        'description' => __('Unfiltered uploads allows uploading any file type including .php and .exe, which is a critical security risk.', 'barebones'),
        'resolution'  => __('Remove or set <code>define(\'ALLOW_UNFILTERED_UPLOADS\', false);</code> in <code>wp-config.php</code>.', 'barebones'),
    ];

    $checks[] = [
        'label'       => __('XML-RPC Disabled', 'barebones'),
        'status'      => (has_filter('xmlrpc_enabled', '__return_false') !== false) ? 'pass' : 'fail',
        'description' => __('XML-RPC is a common attack vector for brute force and DDoS attacks. It should be disabled unless explicitly needed.', 'barebones'),
        'resolution'  => __('Ensure the theme\'s <code>includes/security.php</code> is loaded, which disables XML-RPC.', 'barebones'),
    ];

    $checks[] = [
        'label'       => __('Custom Login URL', 'barebones'),
        'status'      => (defined('BBP_LOGIN_SLUG') || function_exists('bbp_login_url')) ? 'pass' : 'fail',
        'description' => __('The default wp-login.php URL is a well-known target for brute force attacks. A custom login URL hides the login endpoint.', 'barebones'),
        'resolution'  => __('Ensure the theme\'s <code>includes/security.php</code> is loaded, which implements custom login URL rewriting.', 'barebones'),
    ];

    $checks[] = [
        'label'       => __('wp-login.php Blocked', 'barebones'),
        'status'      => function_exists('bbp_block_wp_login') ? 'pass' : 'fail',
        'description' => __('Direct access to wp-login.php should return 404 for unauthenticated users, preventing bots from finding the default login page.', 'barebones'),
        'resolution'  => __('Ensure the theme\'s <code>includes/security.php</code> is loaded, which blocks direct wp-login.php access.', 'barebones'),
    ];

    $checks[] = [
        'label'       => __('wp-admin Blocked for Visitors', 'barebones'),
        'status'      => function_exists('bbp_block_admin_access') ? 'pass' : 'fail',
        'description' => __('Unauthenticated users accessing /wp-admin/ or /admin/ should receive a 404 response instead of being redirected to the login page.', 'barebones'),
        'resolution'  => __('Ensure the theme\'s <code>includes/security.php</code> is loaded, which blocks admin access for visitors.', 'barebones'),
    ];

    $checks[] = [
        'label'       => __('Strong Password Enforcement', 'barebones'),
        'status'      => function_exists('bbp_validate_strong_password') ? 'pass' : 'fail',
        'description' => __('Passwords should require a minimum of 12 characters with uppercase, lowercase, numbers, and symbols to prevent brute force attacks.', 'barebones'),
        'resolution'  => __('Ensure the theme\'s <code>includes/security.php</code> is loaded, which enforces strong passwords.', 'barebones'),
    ];

    $checks[] = [
        'label'       => __('Wordfence Plugin Active', 'barebones'),
        'status'      => bbp_plugin_active('wordfence/wordfence.php') ? 'pass' : 'fail',
        'description' => __('Wordfence provides a Web Application Firewall, malware scanning, and login security which is required by this theme.', 'barebones'),
        'resolution'  => __('Install and activate the Wordfence Security plugin from the admin Plugins page.', 'barebones'),
    ];

    $checks[] = [
        'label'       => __('Wordfence WAF Enabled', 'barebones'),
        'status'      => bbp_check_wordfence_waf_status(),
        'description' => __('The Wordfence Web Application Firewall should be in enabled mode (not learning mode) to actively block attacks.', 'barebones'),
        'resolution'  => __('Go to Wordfence > Firewall and switch from Learning Mode to Enabled. Flush the server cache after enabling.', 'barebones'),
    ];

    $checks[] = [
        'label'       => __('No Redundant Login Plugin', 'barebones'),
        'status'      => !bbp_plugin_active('admin-login-url-change/admin-login-url-change.php') ? 'pass' : 'warning',
        'description' => __('The "Admin Login URL Change" plugin is redundant because the theme already implements custom login URL rewriting. Running both may cause conflicts.', 'barebones'),
        'resolution'  => __('Deactivate and remove the "Admin Login URL Change" plugin since the theme handles this natively.', 'barebones'),
    ];

    $checks[] = [
        'label'       => __('WordPress Version Hidden', 'barebones'),
        'status'      => (has_filter('wp_head', 'wp_generator') === false) ? 'pass' : 'warning',
        'description' => __('The WordPress version number should be hidden from the HTML source to prevent targeted attacks against known version vulnerabilities.', 'barebones'),
        'resolution'  => __('The theme\'s <code>functions.php</code> should already remove <code>wp_generator</code> from <code>wp_head</code>. Verify it is not re-added by plugins.', 'barebones'),
    ];

    $checks[] = [
        'label'       => __('wp-config.php Permissions', 'barebones'),
        'status'      => bbp_check_wp_config_permissions(),
        'description' => __('wp-config.php should have restrictive file permissions (440 or 444) to prevent unauthorized reads or writes.', 'barebones'),
        'resolution'  => __('Set file permissions: <code>chmod 440 wp-config.php</code>. If that causes issues, use <code>chmod 444</code>.', 'barebones'),
    ];

    $checks[] = [
        'label'       => __('WP_DEBUG Disabled', 'barebones'),
        'status'      => (defined('WP_DEBUG') && WP_DEBUG) ? 'fail' : 'pass',
        'description' => __('WP_DEBUG should be disabled in production to prevent leaking sensitive information like file paths, queries, and configuration details.', 'barebones'),
        'resolution'  => __('Set <code>define(\'WP_DEBUG\', false);</code> in <code>wp-config.php</code>. If debugging is needed, use <code>WP_DEBUG_LOG</code> with <code>WP_DEBUG_DISPLAY</code> set to false.', 'barebones'),
    ];

    $checks[] = [
        'label'       => __('Directory Indexing Disabled', 'barebones'),
        'status'      => bbp_check_directory_indexing(),
        'description' => __('Directory browsing should be disabled to prevent visitors from viewing the file structure of your site, which reveals plugin versions and file paths.', 'barebones'),
        'resolution'  => __('Add <code>Options -Indexes</code> to your root <code>.htaccess</code> file, or configure your web server to disable directory listing.', 'barebones'),
    ];

    $checks[] = [
        'label'       => __('REST API Restricted', 'barebones'),
        'status'      => bbp_check_rest_api_restriction(),
        'description' => __('The WordPress REST API exposes user data and site information by default. Public endpoints should be restricted for non-logged-in users.', 'barebones'),
        'resolution'  => __('Add a filter to restrict REST API access to authenticated users, or use Wordfence\'s REST API blocking feature.', 'barebones'),
    ];

    return $checks;
}

function bbp_check_wordfence_waf_status()
{
    if (!bbp_plugin_active('wordfence/wordfence.php')) {
        return 'fail';
    }

    if (defined('WFWAF_ENABLED') && WFWAF_ENABLED) {
        if (defined('WFWAF_ATTACK_DATA_ONLY')) {
            return 'pass';
        }
        return 'warning';
    }

    return 'warning';
}

function bbp_check_wp_config_permissions()
{
    $config_path = ABSPATH . 'wp-config.php';
    if (!file_exists($config_path)) {
        $config_path = dirname(ABSPATH) . '/wp-config.php';
    }
    if (!file_exists($config_path)) {
        return 'warning';
    }

    clearstatcache(true, $config_path);
    $perms = @fileperms($config_path);

    if ($perms === false) {
        return 'warning';
    }

    $perms = $perms & 0777;

    if ($perms <= 0444) {
        return 'pass';
    }

    return 'warning';
}

function bbp_check_directory_indexing()
{
    $htaccess_path = ABSPATH . '.htaccess';
    if (!file_exists($htaccess_path)) {
        return 'fail';
    }

    $htaccess = @file_get_contents($htaccess_path);
    if ($htaccess === false) {
        return 'warning';
    }

    if (strpos($htaccess, 'Options -Indexes') !== false || strpos($htaccess, 'Options All -Indexes') !== false) {
        return 'pass';
    }

    return 'fail';
}

function bbp_check_rest_api_restriction()
{
    if (has_filter('rest_pre_dispatch', 'bbp_restrict_rest_api')) {
        return 'pass';
    }

    if (bbp_plugin_active('wordfence/wordfence.php')) {
        return 'warning';
    }

    return 'warning';
}