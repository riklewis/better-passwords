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

//validate passwor
function bp_validate($errors) {

  //check password is set
  if(isset($_POST['pass1']) && !empty($_POST['pass1'])) {

    //check password length
    $pass1 = $_POST['pass1'];
    $min = 10; //todo: make this a setting
    if(strlen($pass1)<$min) {

      //add error if less than minimum
      $errors->add('pass',__(
        "<strong>Please choose a better password</strong>: This password is less than <strong>" . $min . "</strong> characters long.<br>
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
              "<strong>Please choose a better password</strong>: This password has been found in at least <strong>" . $count . "</strong> data breaches.<br>
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
