=== Better Passwords ===
Contributors: bettersecurity, riklewis
Tags: better, security, passwords, haveibeenpwned, pwned, hibp
Requires at least: 3.5
Tested up to: 5.0
Stable tag: trunk
Requires PHP: 5.6
License: GPLv3
License URI: https://www.gnu.org/licenses/gpl-3.0.html

Stop use of a bad passwords, including those in the Have I Been Pwned? (https://haveibeenpwned.com) breached password database

== Description ==

This plugin sets a default minimum password length of 10 characters, to ensure that passwords are suitably long that they are hard to guess.  However, it does not insist on any complexity rules, such as digits and special characters, as length is the most important thing when making a password hard to guess.

This plugin uses Troy Hunt's Pwned Passwords API (https://haveibeenpwned.com/Passwords) in order to check a user's potential password against a corpus of breached passwords.

The password itself is never sent to any third party, only a partial hash is sent. This means that the password entered will always be private.

As an added bonus, this plugin also upgrades the hashing algorithm used when storing your password in the database. This is a secure one-way hash created using the [Bcrypt](https://en.wikipedia.org/wiki/Bcrypt) algorithm.
