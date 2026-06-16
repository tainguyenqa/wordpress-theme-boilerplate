<?php

/**
 * Security enforcement for WordPress Boilerplate
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    die;
}

/**
 * Force strong passwords for admin accounts.
 * Removes the "Confirm use of weak password" bypass checkbox.
 */
function bbp_enforce_strong_passwords()
{
    if (!wp_script_is('user-profile', 'enqueued') && !wp_script_is('user-edit', 'enqueued')) {
        return;
    }
    ?>
    <script type="text/javascript">
        document.addEventListener('DOMContentLoaded', function () {
            var pwWeak = document.querySelector('.pw-weak');
            if (pwWeak) {
                pwWeak.style.display = 'none';
            }

            var pwCheckbox = document.querySelector('#pw-checkbox');
            if (pwCheckbox) {
                pwCheckbox.checked = false;
                pwCheckbox.disabled = true;
                pwCheckbox.closest('label').style.display = 'none';
            }

            var submitBtn = document.querySelector('#submit, input[type="submit"]');
            if (submitBtn && typeof wp !== 'undefined' && wp.passwordStrength) {
                var origClick = submitBtn.onclick;
                submitBtn.addEventListener('click', function (e) {
                    var pass1 = document.querySelector('#pass1') || document.querySelector('#password');
                    if (pass1) {
                        var strength = wp.passwordStrength.meter(pass1.value, wp.passwordStrength.userInputDisallowedList());
                        if (strength < 3 && document.querySelector('#pw-checkbox') && !document.querySelector('#pw-checkbox').checked) {
                            e.preventDefault();
                            alert('<?php echo esc_js(__('Strong password required. Please use at least 12 characters with a mix of upper and lowercase letters, numbers, and symbols.', 'barebones')); ?>');
                            return false;
                        }
                    }
                });
            }
        });
    </script>
    <?php
}
add_action('admin_print_footer_scripts', 'bbp_enforce_strong_passwords');
add_action('admin_print_footer_scripts-profile.php', 'bbp_enforce_strong_passwords');
add_action('admin_print_footer_scripts-user-new.php', 'bbp_enforce_strong_passwords');

/**
 * Server-side password strength validation for admin users.
 */
function bbp_validate_strong_password($errors, $update, $user)
{
    if (!$update && !empty($_POST['pass1'])) {
        $password = $_POST['pass1'];
        $min_length = 12;

        if (strlen($password) < $min_length) {
            $errors->add('weak_password', __('Password must be at least 12 characters long.', 'barebones'));
        }
        if (!preg_match('/[A-Z]/', $password)) {
            $errors->add('weak_password', __('Password must contain at least one uppercase letter.', 'barebones'));
        }
        if (!preg_match('/[a-z]/', $password)) {
            $errors->add('weak_password', __('Password must contain at least one lowercase letter.', 'barebones'));
        }
        if (!preg_match('/[0-9]/', $password)) {
            $errors->add('weak_password', __('Password must contain at least one number.', 'barebones'));
        }
        if (!preg_match('/[^A-Za-z0-9]/', $password)) {
            $errors->add('weak_password', __('Password must contain at least one special character.', 'barebones'));
        }
    }
    return $errors;
}
add_filter('user_profile_update_errors', 'bbp_validate_strong_password', 10, 3);

/**
 * Custom login slug.
 * Override by defining BBP_LOGIN_SLUG in wp-config.php before theme loads.
 */
if (!defined('BBP_LOGIN_SLUG')) {
    define('BBP_LOGIN_SLUG', 'portal');
}

/**
 * Filter the login URL to use the custom slug.
 */
function bbp_login_url($login_url, $redirect, $force_reauth)
{
    $login_url = home_url(BBP_LOGIN_SLUG . '/');
    if (!empty($redirect)) {
        $login_url = add_query_arg('redirect_to', urlencode($redirect), $login_url);
    }
    if ($force_reauth) {
        $login_url = add_query_arg('reauth', '1', $login_url);
    }
    return $login_url;
}
add_filter('login_url', 'bbp_login_url', 10, 3);

/**
 * Filter site_url to replace wp-login.php with the custom slug.
 */
function bbp_site_url($url, $path, $scheme, $blog_id)
{
    if ($path === 'wp-login.php' || strpos($path, 'wp-login.php?') === 0) {
        $url = preg_replace('/wp-login\.php/', BBP_LOGIN_SLUG . '/', $url, 1);
    }
    return $url;
}
add_filter('site_url', 'bbp_site_url', 10, 4);

/**
 * Register rewrite rule for custom login slug.
 */
function bbp_register_login_rewrite()
{
    add_rewrite_rule('^' . BBP_LOGIN_SLUG . '/?$', 'index.php?bbp_login=1', 'top');
}
add_action('init', 'bbp_register_login_rewrite');

/**
 * Add custom query var.
 */
function bbp_add_query_vars($vars)
{
    $vars[] = 'bbp_login';
    return $vars;
}
add_filter('query_vars', 'bbp_add_query_vars');

/**
 * Load custom login template via rewrite rule.
 */
function bbp_load_custom_login_template()
{
    if (get_query_var('bbp_login')) {
        nocache_headers();
        header('X-Robots-Tag: noindex, nofollow, noarchive', true);
        global $pagenow, $user_login, $error;
        $pagenow = 'wp-login.php';
        require_once ABSPATH . 'wp-login.php';
        exit;
    }
}
add_action('template_redirect', 'bbp_load_custom_login_template', 0);

/**
 * Block direct access to wp-login.php.
 */
function bbp_block_wp_login()
{
    global $pagenow;
    if ($pagenow === 'wp-login.php') {
        if (strtoupper($_SERVER['REQUEST_METHOD']) === 'GET' && !is_user_logged_in()) {
            status_header(404);
            exit;
        }
    }
}
add_action('init', 'bbp_block_wp_login', 0);

/**
 * Redirect after logout.
 */
function bbp_logout_redirect()
{
    wp_safe_redirect(home_url('/'));
    exit;
}
add_action('wp_logout', 'bbp_logout_redirect');

/**
 * Filter logout URL to use the custom slug.
 */
function bbp_logout_url($logout_url, $redirect)
{
    $url = home_url('/' . BBP_LOGIN_SLUG . '/?action=logout');
    if ($redirect) {
        $url = add_query_arg('redirect_to', urlencode($redirect), $url);
    }
    return wp_nonce_url($url, 'log-out');
}
add_filter('logout_url', 'bbp_logout_url', 10, 2);

/**
 * Block wp-admin and /admin access for non-logged-in users.
 */
function bbp_block_admin_access()
{
    if (is_user_logged_in()) {
        return;
    }
    $req = isset($_SERVER['REQUEST_URI']) ? wp_unslash($_SERVER['REQUEST_URI']) : '';
    $path = trim(wp_parse_url($req, PHP_URL_PATH), '/');
    if ((preg_match('#(^|/)wp-admin(/|$)#i', $path) || preg_match('#(^|/)admin(/|$)#i', $path)) &&
        !preg_match('#admin-ajax\.php$#i', $path)) {
        status_header(404);
        exit;
    }
}
add_action('init', 'bbp_block_admin_access', 0);

remove_action('template_redirect', 'wp_redirect_admin_locations', 1000);

/**
 * Disable XML-RPC to prevent brute force and DDoS attacks via xmlrpc.php.
 */
add_filter('xmlrpc_enabled', '__return_false');

function bbp_block_xmlrpc()
{
    if (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST) {
        status_header(403);
        exit;
    }
}
add_action('init', 'bbp_block_xmlrpc', 0);

/**
 * Remove XML-RPC and RSD link from <head>.
 */
remove_action('wp_head', 'rsd_link');
remove_action('wp_head', 'wlwmanifest_link');

/**
 * Require Wordfence plugin to be active.
 * Displays an admin notice and will not fully load the theme's security features without it.
 */
function bbp_require_wordfence()
{
    if (is_admin() && current_user_can('install_plugins')) {
        if (!is_plugin_active('wordfence/wordfence.php')) {
            add_action('admin_notices', function () {
                ?>
                <div class="notice notice-error">
                    <p>
                        <strong><?php esc_html_e('Wordfence Security Required:', 'barebones'); ?></strong>
                        <?php esc_html_e('This theme requires the Wordfence Security plugin to be installed and activated for full security enforcement.', 'barebones'); ?>
                        <?php
                        $install_url = wp_nonce_url(
                            self_admin_url('update.php?action=install-plugin&plugin=wordfence'),
                            'install-plugin_wordfence'
                        );
                        ?>
                        <a href="<?php echo esc_url($install_url); ?>" class="button button-primary" style="margin-left:10px;">
                            <?php esc_html_e('Install Wordfence', 'barebones'); ?>
                        </a>
                    </p>
                </div>
                <?php
            });
        }
    }
}
add_action('admin_init', 'bbp_require_wordfence');
