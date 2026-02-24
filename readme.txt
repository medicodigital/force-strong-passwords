=== Force Strong Passwords ===
Contributors: boogah, gyrus, simonwheatley, sparanoid, jpry, zyphonic, Medico Digital
Tags: passwords, security, users, profile
Requires at least: 3.7
Tested up to: 4.9
Stable tag: 1.8

Forces users to set a strong password.

== Description ==
The user profile editor includes a JavaScript-powered password strength indicator. However, there is nothing currently built into WordPress core to prevent users from entering weak passwords. Users changing their password to something weak is one of the most vulnerable aspects of a WordPress installation.

With Force Strong Passwords activated, strong passwords are enforced for users with `publish_posts`, `upload_files` & `edit_published_posts` capabilities. Should a user with these capabilities (normally an Author, Editor or Administrator) attempt to change their password, the strong password enforcement will be triggered.

To customize the list of [capabilities](http://codex.wordpress.org/Roles_and_Capabilities) Force Strong Passwords checks for, use the `slt_fsp_caps_check` filter.

**IMPORTANT:** As of WordPress 3.7, the password strength meter in core is based on the [`zxcvbn` JavaScript library](https://tech.dropbox.com/2012/04/zxcvbn-realistic-password-strength-estimation/) from Dropbox. Force Strong Passwords simply passes the results of the client-side `zxcvbn` check along for the server to decide if an error should be thrown. Be aware that a technically savvy user *could* disable this check in the browser.

Development code & issue tracking is hosted at [GitHub](https://github.com/boogah/Force-Strong-Passwords). Pull requests are encouraged!

= Filters =

**`slt_fsp_caps_check` (should return an array)**

Modifies the array of capabilities so that strong password enforcement will be triggered for any matching users.

**Ex:** To make sure users who can update WordPress core require strong passwords:

	add_filter( 'slt_fsp_caps_check', 'my_caps_check' );
	function my_caps_check( $caps ) {
		$caps[] = 'update_core';
		return $caps;
	}

**Ex:** To trigger strong password enforcement for *all* users:

	if ( function_exists( 'slt_fsp_init' ) ) {
		//plugin is activated
		add_filter( 'slt_fsp_caps_check', '__return_empty_array' );
	}

**`slt_fsp_error_message` (should return a string)**

Modifies the default error message.

**`slt_fsp_weak_roles` (should return an array)**

Modifies the array of roles that are considered "weak", and for which strong password enforcement is skipped *when creating a new user*. In this situation, the user object has yet to be created. This means that there are no capabilities to go by. Because of this, Force Strong Passwords has to use the role that has been set on the Add New User form.

The default array includes: `subscriber` and `contributor`.

== Installation ==
1. Upload the `force-strong-passwords` directory into the `/wp-content/plugins/` directory.
2. Activate the plugin through the 'Plugins' menu in WordPress.