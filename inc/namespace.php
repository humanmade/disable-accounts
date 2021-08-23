<?php

namespace DisableAccounts;

use WP_Error;
use WP_Http;
use WP_Session_Tokens;
use WP_User;

const DISABLE_ACTION = 'hm_disableaccounts_disable';
const DISABLE_ACTION_BULK = 'hm_disableaccounts_disable_bulk';
const ENABLE_ACTION = 'hm_disableaccounts_enable';
const ENABLE_ACTION_BULK = 'hm_disableaccounts_enable_bulk';
const DISABLED_META_KEY = '_hm_disableaccounts_disabled';
const SINGLE_ACTION_NONCE = 'hm_disableaccounts';
const STATUS_KEY = 'hm_disableaccounts_success';

/**
 * Bootstrap.
 *
 * @return void
 */
function bootstrap() : void {
	add_filter( 'allow_password_reset', __NAMESPACE__ . '\\maybe_disable_password_reset', 10, 2 );
	add_action( 'authenticate', __NAMESPACE__ . '\\maybe_prevent_login', 100, 2 );
	add_filter( 'user_has_cap', __NAMESPACE__ . '\\maybe_wipe_caps', 100, 4 );
	add_filter( 'wp_is_application_passwords_available_for_user', __NAMESPACE__ . '\\maybe_disable_application_passwords_for_user', 10, 2 );

	// UI for the actions.
	add_action( 'network_admin_notices', __NAMESPACE__ . '\\render_messages' );
	add_filter( 'ms_user_row_actions', __NAMESPACE__ . '\\register_row_action', 10, 2 );
	add_action( 'admin_action_' . DISABLE_ACTION, __NAMESPACE__ . '\\handle_single_action' );
	add_action( 'admin_action_' . ENABLE_ACTION, __NAMESPACE__ . '\\handle_single_action' );
	add_filter( 'bulk_actions-users-network', __NAMESPACE__ . '\\register_bulk_action' );
	add_filter( 'handle_network_bulk_actions-users-network', __NAMESPACE__ . '\\handle_bulk_action', 10, 3 );
}

/**
 * Prevent users with disabled accounts from resetting their password.
 *
 * @param bool $allow Whether to allow the password to be reset. Default true.
 * @param int $user_id The ID of the user attempting to reset a password.
 * @return bool|WP_Error Error if the user is disabled, otherwise passes $allow through.
 */
function maybe_disable_password_reset( $allow, $user_id ) {
	$user = get_user_by( 'ID', $user_id );
	if ( is_disabled( $user ) ) {
		return new WP_Error(
			'hm.disableaccounts.disabled',
			__( 'This account has been disabled, and the password cannot be reset.', 'hm_disableaccounts' )
		);
	}

	return $allow;
}

/**
 * Prevent users with disabled accounts to use application passwords.
 *
 * @param bool $allow Whether to enable application passwords for the user. Default true.
 * @param WP_User $user user that is trying to access application passwords.
 *
 * @return bool true if application passwords should be enabled, false if it should be disabled.
 */
function maybe_disable_application_passwords_for_user( $allow, $user ) {
	if ( is_disabled( $user ) ) {
		return false;
	}

	return $allow;
}

/**
 * Prevent logging in for users whose account is disabled.
 *
 * User passwords are reset to a random string when accounts are disabled, but
 * as a backup, we also want to prevent them from logging in entirely.
 *
 * @param null|WP_User|WP_Error $user WP_User if the user is authenticated. WP_Error or null otherwise.
 * @return null|WP_User|WP_Error Error if the account is disabled, otherwise passes through $user.
 */
function maybe_prevent_login( $user ) {
	if ( $user instanceof WP_User && is_disabled( $user ) ) {
		return new WP_Error(
			'hm.disableaccounts.disabled',
			__( '<strong>Error</strong>: Your account has been disabled.', 'hm_disableaccounts' )
		);
	}

	return $user;
}

/**
 * Disable all user's capabilities if they are disabled.
 *
 * @param bool[] $allcaps Map of cap name => bool of whether they have the cap.
 * @param string[] $caps Primitive capabilities being checked.
 * @param array $args Other arguments.
 * @param WP_User $user User being checked.
 * @return array Caps the user has.
 */
function maybe_wipe_caps( array $allcaps, array $caps, array $args, WP_User $user ) : array {
	if ( is_disabled( $user ) ) {
		// Wipe their caps out.
		return [
			'read' => false,
		];
	}

	return $allcaps;
}

/**
 * Is a user disabled?
 *
 * @param WP_User $user User to check.
 * @return bool True if the user is disabled, false otherwise.
 */
function is_disabled( WP_User $user ) : bool {
	$is_disabled = get_user_meta( $user->ID, DISABLED_META_KEY, true );
	return $is_disabled === 'yes';
}

/**
 * Disable a specific user.
 *
 * @param WP_User $user User account to disable.
 * @return void
 */
function disable_user( WP_User $user ) : void {
	// Set the disabled flag.
	update_user_meta( $user->ID, DISABLED_META_KEY, 'yes' );

	// Change the user's password to a random one. This will immediately halt
	// access for that user.
	$random_password = wp_generate_password( 40, true, true );
	wp_set_password( $random_password, $user->ID );

	// Destroy all logged in sessions for the user.
	$sessions = WP_Session_Tokens::get_instance( $user->ID );
	$sessions->destroy_all();
}

/**
 * Re-enable a specific user.
 *
 * Does not change their password; they will need to reset their password
 * directly via the regular UI and process.
 *
 * @param WP_User $user User account to re-enable.
 * @return void
 */
function reenable_user( WP_User $user ) : void {
	delete_user_meta( $user->ID, DISABLED_META_KEY );
}

/**
 * Render any status messages.
 *
 * @return void Renders any error messages.
 */
function render_messages() : void {
	if ( ! isset( $_GET[ STATUS_KEY ] ) ) {
		return;
	}

	switch ( $_GET[ STATUS_KEY ] ) {
		case 'enabled':
			$message = __( 'User re-enabled.', 'hm_disableaccounts' );
			break;

		case 'enabled_bulk':
			$message = __( 'Users re-enabled.', 'hm_disableaccounts' );
			break;

		case 'disabled':
			$message = __( 'User disabled.', 'hm_disableaccounts' );
			break;

		case 'disabled_bulk':
			$message = __( 'Users disabled.', 'hm_disableaccounts' );
			break;
	}

	if ( empty( $message ) ) {
		return;
	}

	printf(
		'<div id="message" class="updated notice is-dismissible"><p>%s</p></div>',
		$message
	);
}

/**
 * Register the Network Admin users row action.
 *
 * @param array<string, string> Map of action ID => HTML action.
 * @param WP_User $user User for the row.
 * @return array<string, string> Updated action map.
 */
function register_row_action( array $actions, WP_User $user ) : array {
	$current_user = wp_get_current_user();
	if ( $user->ID === $current_user->ID ) {
		// Don't allow the user to action themselves.
		return $actions;
	}

	$is_disabled = is_disabled( $user );
	if ( $is_disabled ) {
		// **Echo** an indicator, to escape the default actions handling.
		// (There's really no other great way to do this.)
		printf(
			'<strong> &mdash; %s</strong>',
			__( 'Disabled', 'hm_disableaccounts' )
		);
	}

	$args = [
		'_wp_http_referer' => urlencode( wp_unslash( $_SERVER['REQUEST_URI'] ) ),
		'action' => urlencode( $is_disabled ? ENABLE_ACTION : DISABLE_ACTION ),
		'id' => urlencode( $user->ID ),
	];
	$url = add_query_arg( $args, wp_nonce_url( network_admin_url( 'users.php' ), SINGLE_ACTION_NONCE ) );
	$actions['hm_disableaccounts'] = sprintf(
		'<a href="%s" class="delete">%s</a>',
		esc_url( $url ),
		$is_disabled ? __( 'Re-enable', 'hm_disableaccounts' ) : __( 'Disable', 'hm_disableaccounts' )
	);

	return $actions;
}

/**
 * Handle the enable/disable action for one user.
 * @return void Redirects to the users screen, or exits.
 */
function handle_single_action()  : void {
	if ( ! is_network_admin() ) {
		return;
	}

	if ( empty( $_GET['_wpnonce'] ) || empty( $_GET['id'] ) ) {
		return;
	}

	check_admin_referer( SINGLE_ACTION_NONCE );

	if ( ! current_user_can( 'manage_network_users' ) ) {
		wp_die( __( 'Sorry, you are not allowed to access this page.', 'hm_disableaccounts' ), WP_Http::FORBIDDEN );
	}

	$user = get_user_by( 'ID', absint( wp_unslash( $_GET['id'] ) ) );
	if ( empty( $user ) || ! $user->exists() || is_wp_error( $user ) ) {
		wp_die( __( 'Invalid user ID.', 'hm_disableaccounts' ), WP_Http::BAD_REQUEST );
	}

	if ( ! current_user_can( 'edit_user', $user->ID ) ) {
		wp_die( __( 'Sorry, you are not allowed to access this page.', 'hm_disableaccounts' ), WP_Http::FORBIDDEN );
	}

	$current_user = wp_get_current_user();
	if ( $user->ID === $current_user->ID ) {
		wp_die( __( 'Sorry, you cannot disable your own account.', 'hm_disableaccounts' ), WP_Http::FORBIDDEN );
	}

	$action = sanitize_key( wp_unslash( $_REQUEST['action'] ?? '' ) );
	$status = '';
	switch ( $action ) {
		case DISABLE_ACTION:
			disable_user( $user );
			$status = 'disabled';
			break;

		case ENABLE_ACTION:
			reenable_user( $user );
			$status = 'enabled';
			break;

		default:
			wp_die( __( 'Sorry, you are not allowed to access this page.', 'hm_disableaccounts' ), WP_Http::FORBIDDEN );
	}

	$sendback = wp_get_referer();
	$redirect = add_query_arg( STATUS_KEY, $status, $sendback );
	wp_safe_redirect( $redirect );
	exit;
}

/**
 * Register the bulk user actions.
 *
 * @param array<string, string> $actions Registered actions.
 * @return array<string, string> Updated bulk actions.
 */
function register_bulk_action( array $actions ) : array {
	if ( current_user_can( 'manage_network_users' ) ) {
		$actions[ DISABLE_ACTION_BULK ] = __( 'Disable users', 'hm_disableaccounts' );
		$actions[ ENABLE_ACTION_BULK ] = __( 'Re-enable users', 'hm_disableaccounts' );
	}

	return $actions;
}

/**
 * Handle bulk enable/disable actions.
 *
 * @param string $sendback URL to send the user back to.
 * @param string $action Action ID being requested.
 * @param string[] $user_ids User IDs to apply action to.
 */
function handle_bulk_action( string $sendback, string $action, array $user_ids ) {
	if ( ! current_user_can( 'manage_network_users' ) ) {
		return $sendback;
	}

	// Note: nonces are already checked by the calling code.

	/** @var WP_User[] $users */
	$users = array_map( function ( string $id ) {
		return get_user_by( 'ID', $id );
	}, $user_ids );

	switch ( $action ) {
		case DISABLE_ACTION_BULK:
			foreach ( $users as $user ) {
				disable_user( $user );
			}

			$status = 'disabled_bulk';
			break;

		case ENABLE_ACTION_BULK:
			foreach ( $users as $user ) {
				reenable_user( $user );
			}

			$status = 'enabled_bulk';
			break;

		default:
			// Not our action, pass it through.
			return $sendback;
	}

	return add_query_arg( STATUS_KEY, $status, $sendback );
}
