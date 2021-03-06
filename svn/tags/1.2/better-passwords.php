<?php
/*
Plugin Name:  Better Passwords
Description:  Stop use of a bad passwords, including those in the Have I Been Pwned breached password database
Version:      1.2
Author:       Better Security
Author URI:   https://bettersecurity.co
License:      GPL3
License URI:  https://www.gnu.org/licenses/gpl-3.0.en.html
Text Domain:  better-pass-text
Domain Path:  /languages
*/

//prevent direct access
defined('ABSPATH') or die('Forbidden');

/*
------------------------- Password valdation --------------------------
*/

//validate password
function better_pass_validate($errors) {

  //check password is set
  if(isset($_POST['pass1']) && !empty($_POST['pass1'])) {

    //get minimum password length
    $min = 10;
    $settings = get_option('better-passwords-settings');
  	if($settings['better-passwords-min-length']) {
      $min = $settings['better-passwords-min-length']*1;
    }

    //check password length
    $pass1 = $_POST['pass1'];
    if(strlen($pass1)<$min) {

      //add error if less than minimum
      $errors->add('pass',__(
        "<img src='" . WP_PLUGIN_URL . "/better-passwords/icon-36x36.png' align='left' style='margin-right:8px'>
        <strong>Please choose a better password</strong>: This password is less than <strong>" . $min . "</strong> characters long.<br>
        This means that this password is vulnerable to brute force attacks as it could be relatively easily guessed.",'better-pass-text')
      );
    }
    else {

      //calculate hash and hit API
      $hash = sha1($pass1);
      $prefix = substr($hash,0,5);
      $suffix = substr($hash,5);
      $resp = wp_remote_get("https://api.pwnedpasswords.com/range/" . $prefix);
      if(!is_wp_error($resp)) {

        //find hash and extract count
        $regex = "/" . $suffix . ":(\d+)/i";
        if(preg_match($regex,$resp["body"],$matches)) {
          $count = intval($matches[1]);
          if($count>0) {

            //add error if count is positive
  	        $errors->add('pass',__(
              "<img src='" . WP_PLUGIN_URL . "/better-passwords/icon-36x36.png' align='left' style='margin-right:8px'>
              <strong>Please choose a better password</strong>: This password has been found in at least <strong>" . $count . "</strong> data breaches.<br>
              This means that this password is vulnerable to credential stuffing attacks. <a href='" . esc_url("https://haveibeenpwned.com/Passwords") . "' target='_blank'>Learn More</a>.",'better-pass-text')
            );
          }
        }
      }
    }
  }
}

//add actions
add_action('validate_password_reset', 'better_pass_validate');
add_action("user_profile_update_errors", 'better_pass_validate');

/*
----------------------------- Settings ------------------------------
*/

//add settings page
function better_pass_menus() {
	add_options_page(__('Better Passwords','better-pass-text'), __('Better Passwords','better-pass-text'), 'manage_options', 'better-passwords-settings', 'better_pass_show_settings');
}

//add the settings
function better_pass_settings() {
	register_setting('better-passwords','better-passwords-settings');
	add_settings_section('better-passwords-section', __('Password Settings', 'better-pass-text'), 'better_pass_section', 'better-passwords');
	add_settings_field('better-passwords-min-length', __('Minimum Password Length', 'better-pass-text'), 'better_pass_min_length', 'better-passwords', 'better-passwords-section');
	add_settings_field('better-passwords-algorithm', __('Hashing Algorithm', 'better-pass-text'), 'better_pass_algorithm', 'better-passwords', 'better-passwords-section');
}

//allow the settings to be stored
add_filter('whitelist_options', function($whitelist_options) {
  $whitelist_options['better-passwords'][] = 'better-passwords-min-length';
  $whitelist_options['better-passwords'][] = 'better-passwords-algorithm';
  return $whitelist_options;
});

//define output for settings page
function better_pass_show_settings() {
  echo '<div class="wrap">';
  echo '  <div style="padding:12px;background-color:white;margin:24px 0;">';
  echo '    <a href="https://bettersecurity.co" target="_blank" style="display:inline-block;width:100%;">';
  echo '      <img src="' . WP_PLUGIN_URL . '/better-passwords/header.png" style="height:64px;">';
  echo '    </a>';
  echo '  </div>';
  echo '  <div style="margin:0 0 24px 0;">';
  echo '    <a href="https://www.php.net/supported-versions.php" target="_blank"><img src="' . better_pass_badge_php() . '"></a>';
  echo '  </div>';
  echo '  <h1>' . __('Better Passwords', 'better-pass-text') . '</h1>';
  echo '  <form action="options.php" method="post">';
	settings_fields('better-passwords');
  do_settings_sections('better-passwords');
	submit_button();
  echo '  </form>';
  echo '</div>';
}

function better_pass_badge_php() {
  $ver = phpversion();
  $col = "critical";
  if(version_compare($ver,'7.1','>=')) {
    $col = "important";
  }
  if(version_compare($ver,'7.2','>=')) {
    $col = "success";
  }
  return 'https://img.shields.io/badge/PHP-' . $ver . '-' . $col . '.svg?logo=php&style=for-the-badge';
}

//define output for settings section
function better_pass_section() {
  // No output required for section
}

//defined output for settings
function better_pass_min_length() {
	$settings = get_option('better-passwords-settings');
	$value = ($settings['better-passwords-min-length'] ?: "10");
  echo '<input id="better-passwords-min-length" name="' . 'better-passwords-settings[better-passwords-min-length]" type="number" value="' . $value . '" min="1">';
}

//defined output for settings
function better_pass_algorithm() {
	$settings = get_option('better-passwords-settings');
	$value = ($settings['better-passwords-algorithm'] ?: "BCRYPT");
  echo '<select id="better-passwords-algorithm" name="' . 'better-passwords-settings[better-passwords-algorithm]">';
  better_pass_create_option($value,"BCRYPT","Good (Bcrypt) - default",true);
  better_pass_create_option($value,"ARGON2I","Better (Argon2i) - requires PHP 7.2+",better_pass_check_algorithm(PASSWORD_ARGON2I));
  better_pass_create_option($value,"ARGON2ID","Best (Argon2id) - requires PHP 7.3+",better_pass_check_algorithm(PASSWORD_ARGON2ID));
  echo '</select> <em style="font-size:.8em;padding-left:8px;">Please note: This takes affect when a user next logs in or changes their password</em>';
}

function better_pass_create_option($def,$val,$rep,$boo) {
  echo '  <option value="' . $val . '"' . ($def===$val ? ' selected' : '') . ($boo ? '' : ' disabled') . '>' . $rep . '</option>';
}

function better_pass_check_algorithm($alg) {
  return !!password_hash('test',$alg);
}

//add actions
add_action('admin_menu','better_pass_menus');
add_action('admin_init','better_pass_settings');

/*
------------------------- Password Hashing ------------------------
*/

//verify a user's entered password
function wp_check_password($password, $hash, $user_id = '') {

  //check user is specified and hash starts with default prefix
  if($user_id && strpos($hash, '$P$') === 0) {

    //get/set global varible
    global $wp_hasher;
    if(empty($wp_hasher)) {
      require_once(ABSPATH . WPINC . '/class-phpass.php');
      $wp_hasher = new PasswordHash(8, true);
    }

    //check the password hash matches with default algorithm
    if($wp_hasher->CheckPassword($password, $hash)) {

      //generate new hash and update user record
      $hash = wp_set_password($password, $user_id);
    }
  }

  //check the password hash matches
  $check = password_verify($password, $hash);
  if($check && better_pass_needs_rehash($hash)) {
    $hash = wp_set_password($password, $user_id);
  }
  return apply_filters('check_password', $check, $password, $hash, $user_id);
}

function better_pass_needs_rehash($hash) {
  $alg = better_pass_get_algorithm();
  return password_needs_rehash($hash,$alg);
}

//update user record with generated hash
function wp_set_password($password, $user_id) {
  //generate new hash
  $hash = wp_hash_password($password);

  //update user record
  global $wpdb;
  $wpdb->update($wpdb->users, ['user_pass' => $hash, 'user_activation_key' => ''], ['ID' => $user_id]);
  wp_cache_delete($user_id, 'users');

  return $hash;
}

//generate new hash
function wp_hash_password($password) {
  $alg = better_pass_get_algorithm();
  return password_hash($password,$alg);
}

function better_pass_get_algorithm() {
  $settings = get_option('better-passwords-settings');
  switch($settings['better-passwords-algorithm']) {
    case "ARGON2I":
      return PASSWORD_ARGON2I;
    case "ARGON2ID":
      return PASSWORD_ARGON2ID;
  }
  return PASSWORD_BCRYPT;
}

/*
--------------------- Add links to plugins page ---------------------
*/

//show settings link
function better_pass_links($links) {
	$links[] = sprintf('<a href="%s">%s</a>',admin_url('options-general.php?page=better-passwords-settings'),'Settings');
	return $links;
}

//add actions
add_filter('plugin_action_links_'.plugin_basename(__FILE__),'better_pass_links');

/*
----------------------------- The End ------------------------------
*/
