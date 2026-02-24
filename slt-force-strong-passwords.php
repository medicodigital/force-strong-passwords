<?php
/**
 * Plugin Name:  Force Strong Passwords
 * Plugin URI:   https://github.com/boogah/force-strong-passwords/
 * Description:  Forces privileged users to set a strong password.
 * Version:      1.8.0
 * Author:       Jason Cosper
 * Author URI:   http://jasoncosper.com/
 * License:      GPLv3
 * License URI:  https://www.gnu.org/licenses/gpl-3.0.txt
 * Text Domain:  force-strong-passwords
 * Domain Path:  /languages
 *
 * @link         https://jasoncosper.com/
 * @package      WordPress
 * @author       Jason Cosper
 * @version      1.8.0
 */

global $wp_version;


// Make sure we don't expose any info if called directly.
if ( ! function_exists( 'add_action' ) ) {
	esc_html_e( "Hi there! I'm just a plugin, not much I can do when called directly.", 'slt-force-strong-passwords' );
	exit;
}


/**
 * Initialize constants.
 */

// Our plugin.
define( 'FSP_PLUGIN_BASE', __FILE__ );

// Allow changing the version number in only one place (the header above).
$plugin_data = get_file_data( FSP_PLUGIN_BASE, array( 'Version' => 'Version' ) );
define( 'FSP_PLUGIN_VERSION', $plugin_data['Version'] );

/**
 * Use zxcvbn for versions 3.7 and above
 *
 * @since       1.3
 */
define( 'SLT_FSP_USE_ZXCVBN', version_compare( round( $wp_version, 1 ), '3.7' ) >= 0 );

if ( ! defined( 'SLT_FSP_CAPS_CHECK' ) ) {
	/**
	 * The default capabilities that will be checked for to trigger strong password enforcement
	 *
	 * @deprecated  Please use the slt_fsp_caps_check filter to customize the capabilities check for enforcement
	 * @since       1.1
	 */
	define( 'SLT_FSP_CAPS_CHECK', 'publish_posts,upload_files,edit_published_posts' );
}

if ( ! defined( 'SLT_FSP_PASSWORD_HISTORY_COUNT' ) ) {
	/**
	 * Number of previous passwords to store and check against for reuse prevention.
	 *
	 * @since 1.9.0
	 */
	define( 'SLT_FSP_PASSWORD_HISTORY_COUNT', 13 );
}

if ( ! defined( 'SLT_FSP_PASSWORD_EXPIRY_DAYS' ) ) {
	/**
	 * Number of days before a password expires and must be changed.
	 *
	 * @since 1.9.0
	 */
	define( 'SLT_FSP_PASSWORD_EXPIRY_DAYS', 30 );
}

if ( ! defined( 'SLT_FSP_PASSWORD_MIN_AGE_DAYS' ) ) {
	/**
	 * Minimum number of days before a password can be changed again.
	 * Prevents users from rapidly cycling through passwords to circumvent history.
	 *
	 * @since 1.9.0
	 */
	define( 'SLT_FSP_PASSWORD_MIN_AGE_DAYS', 1 );
}


/**
 * Retrieve a plugin setting. Priority: database option > PHP constant > default.
 *
 * @since 1.9.0
 * @param string $key     The setting key (without the slt_fsp_ prefix used in the DB).
 * @param mixed  $default Fallback value if nothing else is set.
 * @return mixed
 */
function slt_fsp_get_option( $key, $default = false ) {
	$options = get_option( 'slt_fsp_settings', array() );
	if ( isset( $options[ $key ] ) && '' !== $options[ $key ] ) {
		return $options[ $key ];
	}

	$constant_map = array(
		'min_password_length'    => 'SLT_FSP_MIN_PASSWORD_LENGTH',
		'password_history_count' => 'SLT_FSP_PASSWORD_HISTORY_COUNT',
		'password_expiry_days'   => 'SLT_FSP_PASSWORD_EXPIRY_DAYS',
		'password_min_age_days'  => 'SLT_FSP_PASSWORD_MIN_AGE_DAYS',
	);

	if ( isset( $constant_map[ $key ] ) && defined( $constant_map[ $key ] ) ) {
		return constant( $constant_map[ $key ] );
	}

	return $default;
}


// Initialize other stuff.
add_action( 'plugins_loaded', 'slt_fsp_init' );
function slt_fsp_init() {

	// Text domain for translation.
	load_plugin_textdomain( 'slt-force-strong-passwords', false, dirname( plugin_basename( __FILE__ ) ) . '/languages/' );

	// Hooks.
	add_action( 'user_profile_update_errors', 'slt_fsp_validate_profile_update', 0, 3 );
	add_action( 'validate_password_reset', 'slt_fsp_validate_strong_password', 10, 2 );
	add_action( 'resetpass_form', 'slt_fsp_validate_resetpass_form', 10 );

	// Settings page.
	add_action( 'admin_menu', 'slt_fsp_add_settings_page' );
	add_action( 'admin_init', 'slt_fsp_register_settings' );

	// Password history and expiry hooks.
	add_action( 'after_password_reset', 'slt_fsp_after_password_reset', 10, 2 );
	add_action( 'profile_update', 'slt_fsp_after_profile_update', 10, 2 );
	add_action( 'user_register', 'slt_fsp_on_user_register' );
	add_action( 'wp_login', 'slt_fsp_on_login', 10, 2 );
	add_action( 'admin_init', 'slt_fsp_check_password_expiry' );
	add_action( 'admin_notices', 'slt_fsp_password_expiry_notice' );

	if ( SLT_FSP_USE_ZXCVBN ) {

		// Enforce zxcvbn check with JS by passing strength check through to server.
		add_action( 'admin_enqueue_scripts', 'slt_fsp_enqueue_force_zxcvbn_script' );
		add_action( 'login_enqueue_scripts', 'slt_fsp_enqueue_force_zxcvbn_script' );

	}

}

/**
 * Enqueue `force-zxcvbn` check script.
 * Gives you the unminified version if `SCRIPT_DEBUG` is set to 'true'.
 */
function slt_fsp_enqueue_force_zxcvbn_script() {
	$suffix = ( defined( 'SCRIPT_DEBUG' ) && SCRIPT_DEBUG ) ? '' : '.min';
	wp_enqueue_script( 'slt-fsp-force-zxcvbn', plugin_dir_url( __FILE__ ) . 'force-zxcvbn' . $suffix . '.js', array( 'jquery' ), FSP_PLUGIN_VERSION );
	wp_enqueue_script( 'slt-fsp-admin-js', plugin_dir_url( __FILE__ ) . 'js-admin' . $suffix . '.js', array( 'jquery' ), FSP_PLUGIN_VERSION );
}

/**
 * Check user profile update and throw an error if the password isn't strong.
 */
function slt_fsp_validate_profile_update( $errors, $update, $user_data ) {
	return slt_fsp_validate_strong_password( $errors, $user_data );
}

/**
 * Check password reset form and throw an error if the password isn't strong.
 */
function slt_fsp_validate_resetpass_form( $user_data ) {
	return slt_fsp_validate_strong_password( false, $user_data );
}


/**
 * Functionality used by both user profile and reset password validation.
 */
function slt_fsp_validate_strong_password( $errors, $user_data ) {
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
		$enforce = slt_fsp_enforce_for_user( $user_id );

	} else {

		// No ID yet, adding new user - omit check for "weaker" roles unless enforcing for all.
		if ( ! (int) slt_fsp_get_option( 'enforce_for_all_users', 1 ) ) {
			if ( $role && in_array( $role, apply_filters( 'slt_fsp_weak_roles', array( 'subscriber', 'contributor' ) ) ) ) {
				$enforce = false;
			}
		}
	}

	// Enforce?
	if ( $enforce ) {

		$min_length = apply_filters( 'slt_fsp_min_password_length', (int) slt_fsp_get_option( 'min_password_length', 15 ) );

		if ( strlen( $password ) < $min_length ) {
			$password_ok = false;
			if ( is_wp_error( $errors ) ) {
				$errors->add( 'pass', sprintf(
					__( '<strong>ERROR</strong>: Password must be at least %d characters long.', 'slt-force-strong-passwords' ),
					$min_length
				) );
			}
			return $errors;
		}

		// Enforce minimum password age to prevent rapid cycling.
		if ( $user_id ) {
			$min_age_days  = apply_filters( 'slt_fsp_password_min_age_days', (int) slt_fsp_get_option( 'password_min_age_days', SLT_FSP_PASSWORD_MIN_AGE_DAYS ) );
			$last_changed  = get_user_meta( $user_id, 'slt_fsp_password_last_changed', true );
			if ( $last_changed && $min_age_days > 0 ) {
				$earliest_change = $last_changed + ( $min_age_days * DAY_IN_SECONDS );
				if ( time() < $earliest_change ) {
					if ( is_wp_error( $errors ) ) {
						$errors->add( 'pass', sprintf(
							/* translators: %d: minimum number of days between password changes */
							__( '<strong>ERROR</strong>: You must wait at least %d day(s) before changing your password again.', 'slt-force-strong-passwords' ),
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
					$errors->add( 'pass', __( '<strong>ERROR</strong>: You cannot reuse your current password. Please choose a different one.', 'slt-force-strong-passwords' ) );
				}
				return $errors;
			}
			if ( slt_fsp_is_password_in_history( $password, $user_id ) ) {
				$max_history = apply_filters( 'slt_fsp_password_history_count', (int) slt_fsp_get_option( 'password_history_count', SLT_FSP_PASSWORD_HISTORY_COUNT ) );
				if ( is_wp_error( $errors ) ) {
					$errors->add( 'pass', sprintf(
						/* translators: %d: number of previous passwords stored */
						__( '<strong>ERROR</strong>: This password has been used recently. Please choose a password you haven\'t used in the last %d changes.', 'slt-force-strong-passwords' ),
						$max_history
					) );
				}
				return $errors;
			}
		}

		// Using zxcvbn?
		if ( SLT_FSP_USE_ZXCVBN ) {

			// Check the strength passed from the zxcvbn meter.
			$compare_strong       = html_entity_decode( __( 'strong' ), ENT_QUOTES, 'UTF-8' );
			$compare_strong_reset = html_entity_decode( __( 'hide-if-no-js strong' ), ENT_QUOTES, 'UTF-8' );
			if ( ! in_array( $_POST['slt-fsp-pass-strength-result'], array( null, $compare_strong, $compare_strong_reset ), true ) ) {
				$password_ok = false;
			}
		} else {

			// Old-style check.
			if ( slt_fsp_password_strength( $password, $username ) !== 4 ) {
				$password_ok = false;
			}
		}
	}

	// Error?
	if ( ! $password_ok && is_wp_error( $errors ) ) { // Is this a WP error object?
		$errors->add( 'pass', apply_filters( 'slt_fsp_error_message', __( '<strong>ERROR</strong>: Please make the password a strong one.', 'slt-force-strong-passwords' ) ) );
	}

	return $errors;
}


/**
 * Add the plugin settings page under Settings.
 *
 * @since 1.9.0
 */
function slt_fsp_add_settings_page() {
	add_options_page(
		__( 'Force Strong Passwords', 'slt-force-strong-passwords' ),
		__( 'Strong Passwords', 'slt-force-strong-passwords' ),
		'manage_options',
		'slt-force-strong-passwords',
		'slt_fsp_render_settings_page'
	);
}


/**
 * Register plugin settings, sections, and fields.
 *
 * @since 1.9.0
 */
function slt_fsp_register_settings() {
	register_setting( 'slt_fsp_settings_group', 'slt_fsp_settings', 'slt_fsp_sanitize_settings' );

	add_settings_section(
		'slt_fsp_password_policy',
		__( 'Password Policy', 'slt-force-strong-passwords' ),
		'slt_fsp_policy_section_cb',
		'slt-force-strong-passwords'
	);

	add_settings_field(
		'enforce_for_all_users',
		__( 'Enforce for All Users', 'slt-force-strong-passwords' ),
		'slt_fsp_field_checkbox_cb',
		'slt-force-strong-passwords',
		'slt_fsp_password_policy',
		array(
			'key'         => 'enforce_for_all_users',
			'default'     => 1,
			'label'       => __( 'Apply password policy to every user role, including subscribers and contributors.', 'slt-force-strong-passwords' ),
		)
	);

	add_settings_field(
		'min_password_length',
		__( 'Minimum Password Length', 'slt-force-strong-passwords' ),
		'slt_fsp_field_number_cb',
		'slt-force-strong-passwords',
		'slt_fsp_password_policy',
		array(
			'key'         => 'min_password_length',
			'default'     => 15,
			'min'         => 8,
			'max'         => 128,
			'description' => __( 'Minimum number of characters required for a password.', 'slt-force-strong-passwords' ),
		)
	);

	add_settings_field(
		'password_history_count',
		__( 'Password History Count', 'slt-force-strong-passwords' ),
		'slt_fsp_field_number_cb',
		'slt-force-strong-passwords',
		'slt_fsp_password_policy',
		array(
			'key'         => 'password_history_count',
			'default'     => SLT_FSP_PASSWORD_HISTORY_COUNT,
			'min'         => 0,
			'max'         => 50,
			'description' => __( 'Number of previous passwords remembered. Users cannot reuse any of these.', 'slt-force-strong-passwords' ),
		)
	);

	add_settings_field(
		'password_expiry_days',
		__( 'Password Maximum Age (days)', 'slt-force-strong-passwords' ),
		'slt_fsp_field_number_cb',
		'slt-force-strong-passwords',
		'slt_fsp_password_policy',
		array(
			'key'         => 'password_expiry_days',
			'default'     => SLT_FSP_PASSWORD_EXPIRY_DAYS,
			'min'         => 0,
			'max'         => 365,
			'description' => __( 'Days before a password expires. Set to 0 to disable expiry.', 'slt-force-strong-passwords' ),
		)
	);

	add_settings_field(
		'password_min_age_days',
		__( 'Password Minimum Age (days)', 'slt-force-strong-passwords' ),
		'slt_fsp_field_number_cb',
		'slt-force-strong-passwords',
		'slt_fsp_password_policy',
		array(
			'key'         => 'password_min_age_days',
			'default'     => SLT_FSP_PASSWORD_MIN_AGE_DAYS,
			'min'         => 0,
			'max'         => 30,
			'description' => __( 'Minimum days a user must wait before changing their password again. Prevents rapid cycling.', 'slt-force-strong-passwords' ),
		)
	);
}


/**
 * Settings section description callback.
 *
 * @since 1.9.0
 */
function slt_fsp_policy_section_cb() {
	echo '<p>' . esc_html__( 'Configure password strength and lifecycle requirements.', 'slt-force-strong-passwords' ) . '</p>';
}


/**
 * Render a numeric input field for a setting.
 *
 * @since 1.9.0
 * @param array $args Field arguments (key, default, min, max, description).
 */
function slt_fsp_field_number_cb( $args ) {
	$value = slt_fsp_get_option( $args['key'], $args['default'] );
	printf(
		'<input type="number" name="slt_fsp_settings[%s]" value="%s" min="%d" max="%d" class="small-text" />',
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
function slt_fsp_field_checkbox_cb( $args ) {
	$value = (int) slt_fsp_get_option( $args['key'], $args['default'] );
	printf(
		'<label><input type="checkbox" name="slt_fsp_settings[%s]" value="1" %s /> %s</label>',
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
function slt_fsp_sanitize_settings( $input ) {
	$sanitized = array();

	$sanitized['enforce_for_all_users'] = ! empty( $input['enforce_for_all_users'] ) ? 1 : 0;

	$fields = array(
		'min_password_length'    => array( 'min' => 8,  'max' => 128, 'default' => 15 ),
		'password_history_count' => array( 'min' => 0,  'max' => 50,  'default' => SLT_FSP_PASSWORD_HISTORY_COUNT ),
		'password_expiry_days'   => array( 'min' => 0,  'max' => 365, 'default' => SLT_FSP_PASSWORD_EXPIRY_DAYS ),
		'password_min_age_days'  => array( 'min' => 0,  'max' => 30,  'default' => SLT_FSP_PASSWORD_MIN_AGE_DAYS ),
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
			'slt_fsp_settings',
			'min_age_adjusted',
			__( 'Minimum age was reduced to be less than the maximum age.', 'slt-force-strong-passwords' ),
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
function slt_fsp_render_settings_page() {
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}
	?>
	<div class="wrap">
		<h1><?php echo esc_html( get_admin_page_title() ); ?></h1>
		<form action="options.php" method="post">
			<?php
			settings_fields( 'slt_fsp_settings_group' );
			do_settings_sections( 'slt-force-strong-passwords' );
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
 * @uses    SLT_FSP_CAPS_CHECK
 * @uses    apply_filters()
 * @uses    user_can()
 * @param   int $user_id A user ID.
 * @return  boolean
 */
function slt_fsp_enforce_for_user( $user_id ) {
	$enforce = true;

	if ( (int) slt_fsp_get_option( 'enforce_for_all_users', 1 ) ) {
		return $enforce;
	}

	// Force strong passwords from network admin screens.
	if ( is_network_admin() ) {
		return $enforce;
	}

	$check_caps = explode( ',', SLT_FSP_CAPS_CHECK );
	$check_caps = apply_filters( 'slt_fsp_caps_check', $check_caps );
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
function slt_fsp_store_password_history( $user_id ) {
	$user = get_userdata( $user_id );
	if ( ! $user ) {
		return;
	}

	$history = get_user_meta( $user_id, 'slt_fsp_password_history', true );
	if ( ! is_array( $history ) ) {
		$history = array();
	}

	$history[] = $user->user_pass;

	$max_history = apply_filters( 'slt_fsp_password_history_count', (int) slt_fsp_get_option( 'password_history_count', SLT_FSP_PASSWORD_HISTORY_COUNT ) );
	if ( count( $history ) > $max_history ) {
		$history = array_slice( $history, -$max_history );
	}

	update_user_meta( $user_id, 'slt_fsp_password_history', $history );
}


/**
 * Check if a password matches any entry in the user's password history.
 *
 * @since 1.9.0
 * @param string $password  The plain-text password to check.
 * @param int    $user_id   The user ID.
 * @return boolean True if the password was found in history.
 */
function slt_fsp_is_password_in_history( $password, $user_id ) {
	$history = get_user_meta( $user_id, 'slt_fsp_password_history', true );
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
function slt_fsp_after_password_reset( $user, $new_pass ) {
	slt_fsp_store_password_history( $user->ID );
	update_user_meta( $user->ID, 'slt_fsp_password_last_changed', time() );
}


/**
 * Record password change after a profile update (only if password actually changed).
 *
 * @since 1.9.0
 * @param int     $user_id       The user ID.
 * @param WP_User $old_user_data The user data before the update.
 */
function slt_fsp_after_profile_update( $user_id, $old_user_data ) {
	$user = get_userdata( $user_id );
	if ( $user && $user->user_pass !== $old_user_data->user_pass ) {
		slt_fsp_store_password_history( $user_id );
		update_user_meta( $user_id, 'slt_fsp_password_last_changed', time() );
	}
}


/**
 * Initialize password tracking metadata when a new user is registered.
 *
 * @since 1.9.0
 * @param int $user_id The newly registered user ID.
 */
function slt_fsp_on_user_register( $user_id ) {
	update_user_meta( $user_id, 'slt_fsp_password_last_changed', time() );
	slt_fsp_store_password_history( $user_id );
}


/**
 * On login, set the password-last-changed timestamp if it doesn't exist yet.
 * Handles existing users who were created before the plugin was activated.
 *
 * @since 1.9.0
 * @param string  $user_login The username.
 * @param WP_User $user       The authenticated user object.
 */
function slt_fsp_on_login( $user_login, $user ) {
	$last_changed = get_user_meta( $user->ID, 'slt_fsp_password_last_changed', true );
	if ( ! $last_changed ) {
		update_user_meta( $user->ID, 'slt_fsp_password_last_changed', time() );
	}
}


/**
 * Check if a user's password has expired.
 *
 * @since 1.9.0
 * @param int $user_id The user ID.
 * @return boolean True if the password is expired.
 */
function slt_fsp_is_password_expired( $user_id ) {
	if ( ! slt_fsp_enforce_for_user( $user_id ) ) {
		return false;
	}

	$last_changed = get_user_meta( $user_id, 'slt_fsp_password_last_changed', true );
	if ( ! $last_changed ) {
		return false;
	}

	$expiry_days = apply_filters( 'slt_fsp_password_expiry_days', (int) slt_fsp_get_option( 'password_expiry_days', SLT_FSP_PASSWORD_EXPIRY_DAYS ) );
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
function slt_fsp_check_password_expiry() {
	if ( ! is_user_logged_in() ) {
		return;
	}

	$user_id = get_current_user_id();
	if ( ! slt_fsp_is_password_expired( $user_id ) ) {
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
function slt_fsp_password_expiry_notice() {
	if ( ! isset( $_GET['password_expired'] ) && ! slt_fsp_is_password_expired( get_current_user_id() ) ) {
		return;
	}

	echo '<div class="notice notice-error"><p>';
	esc_html_e( 'Your password has expired. Please set a new password below.', 'slt-force-strong-passwords' );
	echo '</p></div>';
}


/**
 * Check for password strength - based on JS function in pre-3.7 WP core: /wp-admin/js/password-strength-meter.js
 *
 * @since   1.0
 * @param   string $i   The password.
 * @param   string $f   The user's username.
 * @return  integer 1 = very weak; 2 = weak; 3 = medium; 4 = strong
 */
function slt_fsp_password_strength( $i, $f ) {
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
