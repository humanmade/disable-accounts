<?php
/**
 * Plugin Name: Disable Accounts
 * Description: Adds the ability to disable user accounts across WordPress.
 * Author Name: Human Made
 * Author URI: https://humanmade.com/
 * Network: true
 */

namespace DisableAccounts;

\Altis\register_class_path( __NAMESPACE__, __DIR__ . '/inc' );

require __DIR__ . '/inc/namespace.php';

bootstrap();
