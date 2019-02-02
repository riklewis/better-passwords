<?php
/*
Plugin Name:  Better Passwords
Description:  Stop use of a bad passwords, including those in the Have I Been Pwned breached password database
Version:      1.0
Author:       Better Security
Author URI:   https://bettersecurity.co
License:      GPL3
License URI:  https://www.gnu.org/licenses/gpl-3.0.en.html
Text Domain:  bp-text
Domain Path:  /languages
*/

//prevent direct access
defined('ABSPATH') or die('Forbidden');

/*
------------------------- Password valdation --------------------------
*/

//validate password
function bp_validate($errors) {

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
        "<img src='/wp-content/plugins/better-passwords/assets/icon-36x36.png' align='left' style='margin-right:8px'>
        <strong>Please choose a better password</strong>: This password is less than <strong>" . $min . "</strong> characters long.<br>
        This means that this password is vulnerable to brute force attacks as it could be relatively easily guessed.",'bp-text')
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
              "<img src='/wp-content/plugins/better-passwords/assets/icon-36x36.png' align='left' style='margin-right:8px'>
              <strong>Please choose a better password</strong>: This password has been found in at least <strong>" . $count . "</strong> data breaches.<br>
              This means that this password is vulnerable to credential stuffing attacks. <a href='" . esc_url("https://haveibeenpwned.com/Passwords") . "' target='_blank'>Learn More</a>.",'bp-text')
            );
          }
        }
      }
    }
  }
}

//add actions
add_action('validate_password_reset', 'bp_validate');
add_action("user_profile_update_errors", 'bp_validate');

/*
----------------------------- Settings ------------------------------
*/

//add settings page
function bp_menus() {
	add_options_page(__('Better Passwords','bp-text'), __('Better Passwords','bp-text'), 'manage_options', 'better-passwords-settings', 'bp_show_settings');
}

//add the settings
function bp_settings() {
	register_setting('better-passwords','better-passwords-settings');
	add_settings_section('better-passwords-section', __('Password Settings', 'bp-text'), 'bp_section', 'better-passwords');
	add_settings_field('better-passwords-min-length', __('Minimum Password Length', 'bp-text'), 'bp_min_length', 'better-passwords', 'better-passwords-section');
}

//allow the settings to be stored
add_filter('whitelist_options', function($whitelist_options) {
  $whitelist_options['better-passwords'][] = 'better-passwords-min-length';
  return $whitelist_options;
});

//define output for settings page
function bp_show_settings() {
  echo '<div class="wrap">';
  echo '  <div style="padding:12px;background-color:white;margin:24px 0;">';
  echo '    <a href="https://bettersecurity.co" style="display:inline-block;width:100%;">';
  echo '      <img src="/wp-content/plugins/better-passwords/assets/header.png" style="height:64px;">';
  echo '    </a>';
  echo '  </div>';
  echo '  <h1>' . __('Better Passwords', 'bp-text') . '</h1>';
  echo '  <form action="options.php" method="post">';
	settings_fields('better-passwords');
  do_settings_sections('better-passwords');
	submit_button();
  echo '  </form>';
  echo '</div>';
}

//define output for settings section
function bp_section() {
  // No output required for section
}

//defined output for settings
function bp_min_length() {
	$settings = get_option('better-passwords-settings');
	$value = ($settings['better-passwords-min-length'] ?: "10");
  echo '<input id="better-passwords-min-length" name="' . 'better-passwords-settings[better-passwords-min-length]" type="number" value="' . $value . '" min="1">';
}

//add actions
add_action('admin_menu','bp_menus');
add_action('admin_init','bp_settings');

/*
----------------------------- The End ------------------------------
*/
