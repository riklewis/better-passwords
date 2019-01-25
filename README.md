# Better Passwords
This is a Wordpress plugin that stops the use of a bad passwords, including those in the Have I Been Pwned breached password database.

This plugin sets a default minimum password length of 10 characters, to ensure that passwords are suitably long that they are hard to guess.  However, it does not insist on any complexity rules, such as digits and special characters, as length is the most important thing when making a password hard to guess.

This also plugin uses Troy Hunt's [Have I Been Pwned?](https://haveibeenpwned.com/Passwords) Passwords API in order to check a user's potential password against a corpus of breached passwords.

The password itself is never sent to any third party, only a partial hash is sent. This means that the password entered will always be private.
