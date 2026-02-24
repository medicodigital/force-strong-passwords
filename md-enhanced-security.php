<?php
/**
 * Plugin Name:  Medico Digital - Enhanced Security
 * Plugin URI:   https://github.com/MedicoDigital/medico-digital-enhanced-security/
 * Description:  Forces users to set a strong password.
 * Version:      1.9.0
 * Author:       Medico Digital
 * Author URI:   http://www.medicodigital.co.uk/
 * License:      GPLv3
 * License URI:  https://www.gnu.org/licenses/gpl-3.0.txt
 * Text Domain:  medico-digital-enhanced-security
 * Domain Path:  /languages
 *
 * @link         https://www.medicodigital.co.uk/
 * @package      WordPress
 * @author       Medico Digital
 * @version      1.9.0
 */

global $wp_version;


// Make sure we don't expose any info if called directly.
if ( ! function_exists( 'add_action' ) ) {
	esc_html_e( "Hi there! I'm just a plugin, not much I can do when called directly.", 'mdes-force-strong-passwords' );
	exit;
}


/**
 * Initialize constants.
 */

// Our plugin.
define( 'MDES_PLUGIN_BASE', __FILE__ );

// Allow changing the version number in only one place (the header above).
$plugin_data = get_file_data( MDES_PLUGIN_BASE, array( 'Version' => 'Version' ) );
define( 'MDES_PLUGIN_VERSION', $plugin_data['Version'] );

/**
 * Use zxcvbn for versions 3.7 and above
 *
 * @since       1.3
 */
define( 'MDES_USE_ZXCVBN', version_compare( $wp_version, '3.7' ) >= 0 );

if ( ! defined( 'MDES_CAPS_CHECK' ) ) {
	/**
	 * The default capabilities that will be checked for to trigger strong password enforcement
	 *
	 * @deprecated  Please use the mdes_caps_check filter to customize the capabilities check for enforcement
	 * @since       1.1
	 */
	define( 'MDES_CAPS_CHECK', 'publish_posts,upload_files,edit_published_posts' );
}

if ( ! defined( 'MDES_PASSWORD_HISTORY_COUNT' ) ) {
	/**
	 * Number of previous passwords to store and check against for reuse prevention.
	 *
	 * @since 1.9.0
	 */
	define( 'MDES_PASSWORD_HISTORY_COUNT', 13 );
}

if ( ! defined( 'MDES_PASSWORD_EXPIRY_DAYS' ) ) {
	/**
	 * Number of days before a password expires and must be changed.
	 *
	 * @since 1.9.0
	 */
	define( 'MDES_PASSWORD_EXPIRY_DAYS', 30 );
}

if ( ! defined( 'MDES_PASSWORD_MIN_AGE_DAYS' ) ) {
	/**
	 * Minimum number of days before a password can be changed again.
	 * Prevents users from rapidly cycling through passwords to circumvent history.
	 *
	 * @since 1.9.0
	 */
	define( 'MDES_PASSWORD_MIN_AGE_DAYS', 1 );
}


/**
 * Retrieve a plugin setting. Priority: database option > PHP constant > default.
 *
 * @since 1.9.0
 * @param string $key     The setting key (without the mdes_ prefix used in the DB).
 * @param mixed  $default Fallback value if nothing else is set.
 * @return mixed
 */
function mdes_get_option( $key, $default = false ) {
	$options = get_option( 'mdes_settings', array() );
	if ( isset( $options[ $key ] ) && '' !== $options[ $key ] ) {
		return $options[ $key ];
	}

	$constant_map = array(
		'min_password_length'    => 'MDES_MIN_PASSWORD_LENGTH',
		'password_history_count' => 'MDES_PASSWORD_HISTORY_COUNT',
		'password_expiry_days'   => 'MDES_PASSWORD_EXPIRY_DAYS',
		'password_min_age_days'  => 'MDES_PASSWORD_MIN_AGE_DAYS',
	);

	if ( isset( $constant_map[ $key ] ) && defined( $constant_map[ $key ] ) ) {
		return constant( $constant_map[ $key ] );
	}

	return $default;
}


// Initialize other stuff.
add_action( 'plugins_loaded', 'mdes_init' );
function mdes_init() {

	// Text domain for translation.
	load_plugin_textdomain( 'mdes-force-strong-passwords', false, dirname( plugin_basename( __FILE__ ) ) . '/languages/' );

	// Hooks.
	add_action( 'user_profile_update_errors', 'mdes_validate_profile_update', 0, 3 );
	add_action( 'validate_password_reset', 'mdes_validate_strong_password', 10, 2 );
	add_action( 'resetpass_form', 'mdes_validate_resetpass_form', 10 );

	// Settings page.
	add_action( 'admin_menu', 'mdes_add_settings_page' );
	add_action( 'admin_init', 'mdes_register_settings' );

	// Password history and expiry hooks.
	add_action( 'after_password_reset', 'mdes_after_password_reset', 10, 2 );
	add_action( 'profile_update', 'mdes_after_profile_update', 10, 2 );
	add_action( 'user_register', 'mdes_on_user_register' );
	add_action( 'wp_login', 'mdes_on_login', 10, 2 );
	add_action( 'admin_init', 'mdes_check_password_expiry' );
	add_action( 'admin_notices', 'mdes_password_expiry_notice' );

	if ( MDES_USE_ZXCVBN ) {

		// Enforce zxcvbn check with JS by passing strength check through to server.
		add_action( 'admin_enqueue_scripts', 'mdes_enqueue_force_zxcvbn_script' );
		add_action( 'login_enqueue_scripts', 'mdes_enqueue_force_zxcvbn_script' );

	}

	// Security hardening hooks.
	mdes_maybe_sanitise_inputs();
	add_action( 'wp_head', 'mdes_inject_js_safe_data', 1 );
	add_action( 'init', 'mdes_add_security_headers' );

}

/**
 * Enqueue `force-zxcvbn` check script.
 * Gives you the unminified version if `SCRIPT_DEBUG` is set to 'true'.
 */
function mdes_enqueue_force_zxcvbn_script() {
	$suffix = ( defined( 'SCRIPT_DEBUG' ) && SCRIPT_DEBUG ) ? '' : '.min';
	wp_enqueue_script( 'mdes-force-zxcvbn', plugin_dir_url( __FILE__ ) . 'force-zxcvbn' . $suffix . '.js', array( 'jquery' ), MDES_PLUGIN_VERSION );
	wp_enqueue_script( 'mdes-admin-js', plugin_dir_url( __FILE__ ) . 'js-admin' . $suffix . '.js', array( 'jquery' ), MDES_PLUGIN_VERSION );
}

/**
 * Check user profile update and throw an error if the password isn't strong.
 */
function mdes_validate_profile_update( $errors, $update, $user_data ) {
	return mdes_validate_strong_password( $errors, $user_data );
}

/**
 * Check password reset form and throw an error if the password isn't strong.
 */
function mdes_validate_resetpass_form( $user_data ) {
	return mdes_validate_strong_password( false, $user_data );
}


/**
 * Functionality used by both user profile and reset password validation.
 */
function mdes_validate_strong_password( $errors, $user_data ) {
	$password_ok = true;
	$enforce     = true;
	$password    = ( isset( $_POST['pass1'] ) && trim( $_POST['pass1'] ) ) ? sanitize_text_field( $_POST['pass1'] ) : false;
	$role        = isset( $_POST['role'] ) ? sanitize_text_field( $_POST['role'] ) : false;
	$user_id     = isset( $user_data->ID ) ? sanitize_text_field( $user_data->ID ) : false;
	$username    = isset( $_POST['user_login'] ) ? sanitize_text_field( $_POST['user_login'] ) : $user_data->user_login;

	// No password set?
	// Already got a password error?
	if ( ( false === $password ) || ( is_wp_error( $errors ) && $errors->get_error_data( 'pass' ) ) ) {
		return $errors;
	}

	// Should a strong password be enforced for this user?
	if ( $user_id ) {

		// User ID specified.
		$enforce = mdes_enforce_for_user( $user_id );

	} else {

		// No ID yet, adding new user - omit check for "weaker" roles unless enforcing for all.
		if ( ! (int) mdes_get_option( 'enforce_for_all_users', 1 ) ) {
			if ( $role && in_array( $role, apply_filters( 'mdes_weak_roles', array( 'subscriber', 'contributor' ) ) ) ) {
				$enforce = false;
			}
		}
	}

	// Enforce?
	if ( $enforce ) {

		$min_length = apply_filters( 'mdes_min_password_length', (int) mdes_get_option( 'min_password_length', 15 ) );

		if ( strlen( $password ) < $min_length ) {
			$password_ok = false;
			if ( is_wp_error( $errors ) ) {
				$errors->add( 'pass', sprintf(
					__( '<strong>ERROR</strong>: Password must be at least %d characters long.', 'mdes-force-strong-passwords' ),
					$min_length
				) );
			}
			return $errors;
		}

		// Enforce minimum password age to prevent rapid cycling.
		if ( $user_id ) {
			$min_age_days  = apply_filters( 'mdes_password_min_age_days', (int) mdes_get_option( 'password_min_age_days', MDES_PASSWORD_MIN_AGE_DAYS ) );
			$last_changed  = get_user_meta( $user_id, 'mdes_password_last_changed', true );
			if ( $last_changed && $min_age_days > 0 ) {
				$earliest_change = $last_changed + ( $min_age_days * DAY_IN_SECONDS );
				if ( time() < $earliest_change ) {
					if ( is_wp_error( $errors ) ) {
						$errors->add( 'pass', sprintf(
							/* translators: %d: minimum number of days between password changes */
							__( '<strong>ERROR</strong>: You must wait at least %d day(s) before changing your password again.', 'mdes-force-strong-passwords' ),
							$min_age_days
						) );
					}
					return $errors;
				}
			}
		}

		// Check password reuse against current password and history.
		if ( $user_id ) {
			$current_user = get_userdata( $user_id );
			if ( $current_user && wp_check_password( $password, $current_user->user_pass, $user_id ) ) {
				if ( is_wp_error( $errors ) ) {
					$errors->add( 'pass', __( '<strong>ERROR</strong>: You cannot reuse your current password. Please choose a different one.', 'mdes-force-strong-passwords' ) );
				}
				return $errors;
			}
			if ( mdes_is_password_in_history( $password, $user_id ) ) {
				$max_history = apply_filters( 'mdes_password_history_count', (int) mdes_get_option( 'password_history_count', MDES_PASSWORD_HISTORY_COUNT ) );
				if ( is_wp_error( $errors ) ) {
					$errors->add( 'pass', sprintf(
						/* translators: %d: number of previous passwords stored */
						__( '<strong>ERROR</strong>: This password has been used recently. Please choose a password you haven\'t used in the last %d changes.', 'mdes-force-strong-passwords' ),
						$max_history
					) );
				}
				return $errors;
			}
		}

		// Using zxcvbn?
		if ( MDES_USE_ZXCVBN ) {

			// Check the strength passed from the zxcvbn meter.
			$compare_strong       = html_entity_decode( __( 'strong' ), ENT_QUOTES, 'UTF-8' );
			$compare_strong_reset = html_entity_decode( __( 'hide-if-no-js strong' ), ENT_QUOTES, 'UTF-8' );
			if ( ! in_array( $_POST['mdes-pass-strength-result'], array( null, $compare_strong, $compare_strong_reset ), true ) ) {
				$password_ok = false;
			}
		} else {

			// Old-style check.
			if ( mdes_password_strength( $password, $username ) !== 4 ) {
				$password_ok = false;
			}
		}
	}

	// Error?
	if ( ! $password_ok && is_wp_error( $errors ) ) { // Is this a WP error object?
		$errors->add( 'pass', apply_filters( 'mdes_error_message', __( '<strong>ERROR</strong>: Please make the password a strong one.', 'mdes-force-strong-passwords' ) ) );
	}

	return $errors;
}


/**
 * Add the plugin settings page under Settings.
 *
 * @since 1.9.0
 */
function mdes_add_settings_page() {
	add_options_page(
		__( 'MD Enhanced Security', 'mdes-force-strong-passwords' ),
		__( 'MD Security', 'mdes-force-strong-passwords' ),
		'manage_options',
		'mdes-force-strong-passwords',
		'mdes_render_settings_page'
	);
}


/**
 * Register plugin settings, sections, and fields.
 *
 * @since 1.9.0
 */
function mdes_register_settings() {
	register_setting( 'mdes_settings_group', 'mdes_settings', 'mdes_sanitize_settings' );

	add_settings_section(
		'mdes_password_policy',
		__( 'Password Policy', 'mdes-force-strong-passwords' ),
		'mdes_policy_section_cb',
		'mdes-force-strong-passwords'
	);

	add_settings_field(
		'enforce_for_all_users',
		__( 'Enforce for All Users', 'mdes-force-strong-passwords' ),
		'mdes_field_checkbox_cb',
		'mdes-force-strong-passwords',
		'mdes_password_policy',
		array(
			'key'         => 'enforce_for_all_users',
			'default'     => 1,
			'label'       => __( 'Apply password policy to every user role, including subscribers and contributors.', 'mdes-force-strong-passwords' ),
		)
	);

	add_settings_field(
		'min_password_length',
		__( 'Minimum Password Length', 'mdes-force-strong-passwords' ),
		'mdes_field_number_cb',
		'mdes-force-strong-passwords',
		'mdes_password_policy',
		array(
			'key'         => 'min_password_length',
			'default'     => 15,
			'min'         => 8,
			'max'         => 128,
			'description' => __( 'Minimum number of characters required for a password.', 'mdes-force-strong-passwords' ),
		)
	);

	add_settings_field(
		'password_history_count',
		__( 'Password History Count', 'mdes-force-strong-passwords' ),
		'mdes_field_number_cb',
		'mdes-force-strong-passwords',
		'mdes_password_policy',
		array(
			'key'         => 'password_history_count',
			'default'     => MDES_PASSWORD_HISTORY_COUNT,
			'min'         => 0,
			'max'         => 50,
			'description' => __( 'Number of previous passwords remembered. Users cannot reuse any of these.', 'mdes-force-strong-passwords' ),
		)
	);

	add_settings_field(
		'password_expiry_days',
		__( 'Password Maximum Age (days)', 'mdes-force-strong-passwords' ),
		'mdes_field_number_cb',
		'mdes-force-strong-passwords',
		'mdes_password_policy',
		array(
			'key'         => 'password_expiry_days',
			'default'     => MDES_PASSWORD_EXPIRY_DAYS,
			'min'         => 0,
			'max'         => 365,
			'description' => __( 'Days before a password expires. Set to 0 to disable expiry.', 'mdes-force-strong-passwords' ),
		)
	);

	add_settings_field(
		'password_min_age_days',
		__( 'Password Minimum Age (days)', 'mdes-force-strong-passwords' ),
		'mdes_field_number_cb',
		'mdes-force-strong-passwords',
		'mdes_password_policy',
		array(
			'key'         => 'password_min_age_days',
			'default'     => MDES_PASSWORD_MIN_AGE_DAYS,
			'min'         => 0,
			'max'         => 30,
			'description' => __( 'Minimum days a user must wait before changing their password again. Prevents rapid cycling.', 'mdes-force-strong-passwords' ),
		)
	);

	// --- Security Hardening section ---
	add_settings_section(
		'mdes_security_hardening',
		__( 'Security Hardening', 'mdes-force-strong-passwords' ),
		'mdes_hardening_section_cb',
		'mdes-force-strong-passwords'
	);

	add_settings_field(
		'enable_input_sanitise',
		__( 'Enable Input Sanitisation', 'mdes-force-strong-passwords' ),
		'mdes_field_checkbox_cb',
		'mdes-force-strong-passwords',
		'mdes_security_hardening',
		array(
			'key'     => 'enable_input_sanitise',
			'default' => 0,
			'label'   => __( 'Sanitize incoming $_GET and $_POST values early (recommended). Output escaping is still required in templates.', 'mdes-force-strong-passwords' ),
		)
	);

	add_settings_field(
		'expose_safe_request_uri',
		__( 'Expose Safe Request URI', 'mdes-force-strong-passwords' ),
		'mdes_field_checkbox_cb',
		'mdes-force-strong-passwords',
		'mdes_security_hardening',
		array(
			'key'     => 'expose_safe_request_uri',
			'default' => 0,
			'label'   => __( 'Output a JSON-encoded window.fspSiteData.safeRequestUri in the head for templates to use instead of echoing raw $_SERVER[\'REQUEST_URI\'].', 'mdes-force-strong-passwords' ),
		)
	);

	add_settings_field(
		'add_security_headers',
		__( 'Add Security Headers', 'mdes-force-strong-passwords' ),
		'mdes_field_checkbox_cb',
		'mdes-force-strong-passwords',
		'mdes_security_hardening',
		array(
			'key'     => 'add_security_headers',
			'default' => 0,
			'label'   => __( 'Add modern HTTP security headers (HSTS, CSP frame-ancestors, X-Content-Type-Options, etc.) and disable the deprecated X-XSS-Protection header.', 'mdes-force-strong-passwords' ),
		)
	);
}


/**
 * Settings section description callback.
 *
 * @since 1.9.0
 */
function mdes_policy_section_cb() {
	echo '<p>' . esc_html__( 'Configure password strength and lifecycle requirements.', 'mdes-force-strong-passwords' ) . '</p>';
}


/**
 * Security hardening section description callback.
 *
 * @since 1.9.0
 */
function mdes_hardening_section_cb() {
	echo '<p>' . esc_html__( 'Configure input sanitisation, safe data exposure, and HTTP security headers.', 'mdes-force-strong-passwords' ) . '</p>';
}


/**
 * Render a numeric input field for a setting.
 *
 * @since 1.9.0
 * @param array $args Field arguments (key, default, min, max, description).
 */
function mdes_field_number_cb( $args ) {
	$value = mdes_get_option( $args['key'], $args['default'] );
	printf(
		'<input type="number" name="mdes_settings[%s]" value="%s" min="%d" max="%d" class="small-text" />',
		esc_attr( $args['key'] ),
		esc_attr( $value ),
		(int) $args['min'],
		(int) $args['max']
	);
	if ( ! empty( $args['description'] ) ) {
		printf( '<p class="description">%s</p>', esc_html( $args['description'] ) );
	}
}


/**
 * Render a checkbox input field for a setting.
 *
 * @since 1.9.0
 * @param array $args Field arguments (key, default, label).
 */
function mdes_field_checkbox_cb( $args ) {
	$value = (int) mdes_get_option( $args['key'], $args['default'] );
	printf(
		'<label><input type="checkbox" name="mdes_settings[%s]" value="1" %s /> %s</label>',
		esc_attr( $args['key'] ),
		checked( $value, 1, false ),
		esc_html( $args['label'] )
	);
}


/**
 * Sanitize settings before saving.
 *
 * @since 1.9.0
 * @param array $input Raw form input.
 * @return array Sanitized values.
 */
function mdes_sanitize_settings( $input ) {
	$sanitized = array();

	$checkboxes = array(
		'enforce_for_all_users',
		'enable_input_sanitise',
		'expose_safe_request_uri',
		'add_security_headers',
	);
	foreach ( $checkboxes as $cb ) {
		$sanitized[ $cb ] = ! empty( $input[ $cb ] ) ? 1 : 0;
	}

	$fields = array(
		'min_password_length'    => array( 'min' => 8,  'max' => 128, 'default' => 15 ),
		'password_history_count' => array( 'min' => 0,  'max' => 50,  'default' => MDES_PASSWORD_HISTORY_COUNT ),
		'password_expiry_days'   => array( 'min' => 0,  'max' => 365, 'default' => MDES_PASSWORD_EXPIRY_DAYS ),
		'password_min_age_days'  => array( 'min' => 0,  'max' => 30,  'default' => MDES_PASSWORD_MIN_AGE_DAYS ),
	);

	foreach ( $fields as $key => $rules ) {
		if ( isset( $input[ $key ] ) && is_numeric( $input[ $key ] ) ) {
			$val = (int) $input[ $key ];
			$sanitized[ $key ] = max( $rules['min'], min( $rules['max'], $val ) );
		} else {
			$sanitized[ $key ] = $rules['default'];
		}
	}

	if ( $sanitized['password_min_age_days'] >= $sanitized['password_expiry_days'] && $sanitized['password_expiry_days'] > 0 ) {
		$sanitized['password_min_age_days'] = max( 0, $sanitized['password_expiry_days'] - 1 );
		add_settings_error(
			'mdes_settings',
			'min_age_adjusted',
			__( 'Minimum age was reduced to be less than the maximum age.', 'mdes-force-strong-passwords' ),
			'warning'
		);
	}

	return $sanitized;
}


/**
 * Render the plugin settings page.
 *
 * @since 1.9.0
 */
function mdes_render_settings_page() {
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}
	?>
	<div class="wrap">
		<h1><?php echo esc_html( get_admin_page_title() ); ?></h1>
		<form action="options.php" method="post">
			<?php
			settings_fields( 'mdes_settings_group' );
			do_settings_sections( 'mdes-force-strong-passwords' );
			submit_button();
			?>
		</form>
	</div>
	<?php
}


/**
 * Check whether the given WP user should be forced to have a strong password
 *
 * Tests on basic capabilities that can compromise a site. Doesn't check on higher capabilities.
 * It's assumed the someone who can't publish_posts won't be able to update_core!
 *
 * @since   1.1
 * @uses    MDES_CAPS_CHECK
 * @uses    apply_filters()
 * @uses    user_can()
 * @param   int $user_id A user ID.
 * @return  boolean
 */
function mdes_enforce_for_user( $user_id ) {
	$enforce = true;

	if ( (int) mdes_get_option( 'enforce_for_all_users', 1 ) ) {
		return $enforce;
	}

	// Force strong passwords from network admin screens.
	if ( is_network_admin() ) {
		return $enforce;
	}

	$check_caps = explode( ',', MDES_CAPS_CHECK );
	$check_caps = apply_filters( 'mdes_caps_check', $check_caps );
	$check_caps = (array) $check_caps;
	if ( ! empty( $check_caps ) ) {
		$enforce = false; // Now we won't enforce unless the user has one of the caps specified.
		foreach ( $check_caps as $cap ) {
			if ( user_can( $user_id, $cap ) ) {
				$enforce = true;
				break;
			}
		}
	}
	return $enforce;
}


/**
 * Store the current password hash in the user's password history.
 *
 * @since 1.9.0
 * @param int $user_id The user ID.
 */
function mdes_store_password_history( $user_id ) {
	$user = get_userdata( $user_id );
	if ( ! $user ) {
		return;
	}

	$history = get_user_meta( $user_id, 'mdes_password_history', true );
	if ( ! is_array( $history ) ) {
		$history = array();
	}

	$history[] = $user->user_pass;

	$max_history = apply_filters( 'mdes_password_history_count', (int) mdes_get_option( 'password_history_count', MDES_PASSWORD_HISTORY_COUNT ) );
	if ( count( $history ) > $max_history ) {
		$history = array_slice( $history, -$max_history );
	}

	update_user_meta( $user_id, 'mdes_password_history', $history );
}


/**
 * Check if a password matches any entry in the user's password history.
 *
 * @since 1.9.0
 * @param string $password  The plain-text password to check.
 * @param int    $user_id   The user ID.
 * @return boolean True if the password was found in history.
 */
function mdes_is_password_in_history( $password, $user_id ) {
	$history = get_user_meta( $user_id, 'mdes_password_history', true );
	if ( ! is_array( $history ) || empty( $history ) ) {
		return false;
	}

	foreach ( $history as $old_hash ) {
		if ( wp_check_password( $password, $old_hash, $user_id ) ) {
			return true;
		}
	}

	return false;
}


/**
 * Record password change after a password reset.
 *
 * @since 1.9.0
 * @param WP_User $user     The user whose password was reset.
 * @param string  $new_pass The new password (not used directly; hash is read from DB).
 */
function mdes_after_password_reset( $user, $new_pass ) {
	mdes_store_password_history( $user->ID );
	update_user_meta( $user->ID, 'mdes_password_last_changed', time() );
}


/**
 * Record password change after a profile update (only if password actually changed).
 *
 * @since 1.9.0
 * @param int     $user_id       The user ID.
 * @param WP_User $old_user_data The user data before the update.
 */
function mdes_after_profile_update( $user_id, $old_user_data ) {
	$user = get_userdata( $user_id );
	if ( $user && $user->user_pass !== $old_user_data->user_pass ) {
		mdes_store_password_history( $user_id );
		update_user_meta( $user_id, 'mdes_password_last_changed', time() );
	}
}


/**
 * Initialize password tracking metadata when a new user is registered.
 *
 * @since 1.9.0
 * @param int $user_id The newly registered user ID.
 */
function mdes_on_user_register( $user_id ) {
	update_user_meta( $user_id, 'mdes_password_last_changed', time() );
	mdes_store_password_history( $user_id );
}


/**
 * On login, set the password-last-changed timestamp if it doesn't exist yet.
 * Handles existing users who were created before the plugin was activated.
 *
 * @since 1.9.0
 * @param string  $user_login The username.
 * @param WP_User $user       The authenticated user object.
 */
function mdes_on_login( $user_login, $user ) {
	$last_changed = get_user_meta( $user->ID, 'mdes_password_last_changed', true );
	if ( ! $last_changed ) {
		update_user_meta( $user->ID, 'mdes_password_last_changed', time() );
	}
}


/**
 * Check if a user's password has expired.
 *
 * @since 1.9.0
 * @param int $user_id The user ID.
 * @return boolean True if the password is expired.
 */
function mdes_is_password_expired( $user_id ) {
	if ( ! mdes_enforce_for_user( $user_id ) ) {
		return false;
	}

	$last_changed = get_user_meta( $user_id, 'mdes_password_last_changed', true );
	if ( ! $last_changed ) {
		return false;
	}

	$expiry_days = apply_filters( 'mdes_password_expiry_days', (int) mdes_get_option( 'password_expiry_days', MDES_PASSWORD_EXPIRY_DAYS ) );
	if ( $expiry_days <= 0 ) {
		return false;
	}
	return time() > ( $last_changed + ( $expiry_days * DAY_IN_SECONDS ) );
}


/**
 * Redirect users with expired passwords to their profile page.
 *
 * @since 1.9.0
 */
function mdes_check_password_expiry() {
	if ( ! is_user_logged_in() ) {
		return;
	}

	$user_id = get_current_user_id();
	if ( ! mdes_is_password_expired( $user_id ) ) {
		return;
	}

	global $pagenow;
	$allowed_pages = array( 'profile.php', 'admin-ajax.php', 'admin-post.php', 'options-general.php' );
	if ( in_array( $pagenow, $allowed_pages, true ) ) {
		return;
	}

	if ( isset( $_GET['action'] ) && 'logout' === $_GET['action'] ) {
		return;
	}

	wp_redirect( admin_url( 'profile.php?password_expired=1' ) );
	exit;
}


/**
 * Display an admin notice when the user's password has expired.
 *
 * @since 1.9.0
 */
function mdes_password_expiry_notice() {
	if ( ! isset( $_GET['password_expired'] ) && ! mdes_is_password_expired( get_current_user_id() ) ) {
		return;
	}

	echo '<div class="notice notice-error"><p>';
	esc_html_e( 'Your password has expired. Please set a new password below.', 'mdes-force-strong-passwords' );
	echo '</p></div>';
}


/**
 * Sanitize incoming $_GET and $_POST arrays early.
 *
 * Output-context escaping is still required when rendering data.
 *
 * @since 1.9.0
 */
function mdes_maybe_sanitise_inputs() {
	if ( ! (int) mdes_get_option( 'enable_input_sanitise', 0 ) ) {
		return;
	}

	$_GET  = mdes_recursive_sanitize_input( $_GET );
	$_POST = mdes_recursive_sanitize_input( $_POST );
}


/**
 * Recursively sanitize an input array.
 *
 * @since 1.9.0
 * @param mixed $data Input data.
 * @return mixed Sanitized data.
 */
function mdes_recursive_sanitize_input( $data ) {
	if ( is_array( $data ) ) {
		$out = array();
		foreach ( $data as $k => $v ) {
			$safe_k        = is_string( $k ) ? sanitize_key( $k ) : $k;
			$out[ $safe_k ] = mdes_recursive_sanitize_input( $v );
		}
		return $out;
	}

	if ( is_scalar( $data ) ) {
		return sanitize_text_field( trim( (string) $data ) );
	}

	return $data;
}


/**
 * Inject a JSON-encoded JS object into the page head so themes can safely
 * reference the request URI without echoing raw $_SERVER values.
 *
 * @since 1.9.0
 */
function mdes_inject_js_safe_data() {
	if ( ! (int) mdes_get_option( 'expose_safe_request_uri', 0 ) ) {
		return;
	}

	$data = array(
		'safeRequestUri' => isset( $_SERVER['REQUEST_URI'] ) ? (string) $_SERVER['REQUEST_URI'] : '',
		'homeUrl'        => home_url(),
	);

	$json = wp_json_encode( $data );
	if ( false === $json ) {
		$json = '{}';
	}

	echo "<script id=\"fsp-site-data\">window.fspSiteData = {$json};</script>\n";
}


/**
 * Add modern HTTP security headers.
 *
 * Explicitly disables the deprecated X-XSS-Protection header and sets
 * best-practice headers for content-type sniffing, framing, referrer
 * policy, HSTS, and a minimal CSP frame-ancestors directive.
 *
 * @since 1.9.0
 */
function mdes_add_security_headers() {
	if ( ! (int) mdes_get_option( 'add_security_headers', 0 ) ) {
		return;
	}

	if ( function_exists( 'header_remove' ) ) {
		header_remove( 'X-XSS-Protection' );
	}
	header( 'X-XSS-Protection: 0' );
	header( 'X-Content-Type-Options: nosniff' );
	header( 'X-Frame-Options: SAMEORIGIN' );
	header( 'Referrer-Policy: strict-origin' );
	header( 'Cross-Origin-Opener-Policy: same-origin' );
	header( 'Cross-Origin-Resource-Policy: same-origin' );
	header( 'Permissions-Policy: accelerometer=(), camera=(), microphone=(), geolocation=(), usb=()' );
	header( 'Strict-Transport-Security: max-age=31536000; includeSubDomains' );
	header( "Content-Security-Policy: frame-ancestors 'self'" );
}


/**
 * Check for password strength - based on JS function in pre-3.7 WP core: /wp-admin/js/password-strength-meter.js
 *
 * @since   1.0
 * @param   string $i   The password.
 * @param   string $f   The user's username.
 * @return  integer 1 = very weak; 2 = weak; 3 = medium; 4 = strong
 */
function mdes_password_strength( $i, $f ) {
	$h = 1;
	$e = 2;
	$b = 3;
	$a = 4;
	$d = 0;
	$g = null;
	$c = null;
	if ( strlen( $i ) < 4 ) {
		return $h;
	}
	if ( strtolower( $i ) === strtolower( $f ) ) {
		return $e;
	}
	if ( preg_match( '/[0-9]/', $i ) ) {
		$d += 10;
	}
	if ( preg_match( '/[a-z]/', $i ) ) {
		$d += 26;
	}
	if ( preg_match( '/[A-Z]/', $i ) ) {
		$d += 26;
	}
	if ( preg_match( '/[^a-zA-Z0-9]/', $i ) ) {
		$d += 31;
	}
	$g = log( pow( $d, strlen( $i ) ) );
	$c = $g / log( 2 );
	if ( $c < 40 ) {
		return $e;
	}
	if ( $c < 56 ) {
		return $b;
	}
	return $a;
}
