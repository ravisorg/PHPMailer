![PHPMailer](https://raw.github.com/PHPMailer/PHPMailer/master/examples/images/phpmailer.png)

# PHPMailerPGP - A full-featured email creation and transfer class for PHP with support for PGP/GPG email signing and encryption.

Build status: [![Build Status](https://travis-ci.org/PHPMailer/PHPMailer.svg)](https://travis-ci.org/PHPMailer/PHPMailer)
[![Scrutinizer Quality Score](https://scrutinizer-ci.com/g/PHPMailer/PHPMailer/badges/quality-score.png?s=3758e21d279becdf847a557a56a3ed16dfec9d5d)](https://scrutinizer-ci.com/g/PHPMailer/PHPMailer/)
[![Code Coverage](https://scrutinizer-ci.com/g/PHPMailer/PHPMailer/badges/coverage.png?s=3fe6ca5fe8cd2cdf96285756e42932f7ca256962)](https://scrutinizer-ci.com/g/PHPMailer/PHPMailer/)

[![Latest Stable Version](https://poser.pugx.org/phpmailer/phpmailer/v/stable.svg)](https://packagist.org/packages/phpmailer/phpmailer) [![Total Downloads](https://poser.pugx.org/phpmailer/phpmailer/downloads)](https://packagist.org/packages/phpmailer/phpmailer) [![Latest Unstable Version](https://poser.pugx.org/phpmailer/phpmailer/v/unstable.svg)](https://packagist.org/packages/phpmailer/phpmailer) [![License](https://poser.pugx.org/phpmailer/phpmailer/license.svg)](https://packagist.org/packages/phpmailer/phpmailer) [![API Docs](https://github.com/phpmailer/phpmailer/workflows/Docs/badge.svg)](http://phpmailer.github.io/PHPMailer/)

See the main [PHPMailer](https://www.github.com/PHPMailer/PHPMailer) page for all the features PHPMailer supports. This page will document only the PGP additions.

## Class Features

- Uses the [PHP GnuPG extension](https://secure.php.net/manual/en/ref.gnupg.php) for encryption / signing
- Encrypt and/or sign outgoing emails with PGP to one or multiple recipients (signs first, then encrypts when both are enabled)
- Automatically selects the proper keys based on sender / recipients (or manually specify them)
- Use keys in the GPG keychain or from a specified file
- Supports file attachments (and encrypts/signs them)
- Builds PGP/MIME emails so that attachments are encrypted (and signed) as well as the email bodies
- Supports optional [Memory Hole protected email headers](https://github.com/autocrypt/memoryhole) (for verified/encrypted subjects, and verified from, to, and cc recipients)
- Uses standard PHPMailer functions so that, in theory, any email you can create with PHPMailer can be encrypted/signed with PHPMailerPGP
- (Mostly) built generically so that other encryption systems (S/MIME) could use the same syntax in their classes

## Why you might need it

In an ideal world, users would provide you with their PGP keys and you could use this to send secure emails to them. More realistically: because your server sends emails with lots of sensitive information in them, and you should be encrypting it.

## License

This software is distributed under the [LGPL 2.1](http://www.gnu.org/licenses/lgpl-2.1.html) license. Please read LICENSE for information on the
software availability and distribution.

## A Simple Example

Set up your PHPMailer like you would normally:

```php
<?php
require_once 'src/Exception.php';
require_once 'src/OAuth.php';
require_once 'src/PHPMailer.php';
require_once 'src/POP3.php';
require_once 'src/SMTP.php';
require_once 'class.phpmailerpgp.php';

use PHPMailer\PHPMailer\PHPMailerPGP;

$mail = new PHPMailerPGP;

//$mail->SMTPDebug = 3;                               // Enable verbose debug output

$mail->isSMTP();                                      // Set mailer to use SMTP
$mail->Host = 'smtp1.example.com;smtp2.example.com';  // Specify main and backup SMTP servers
$mail->SMTPAuth = true;                               // Enable SMTP authentication
$mail->Username = 'user@example.com';                 // SMTP username
$mail->Password = 'secret';                           // SMTP password
$mail->SMTPSecure = 'tls';                            // Enable TLS encryption, `ssl` also accepted
$mail->Port = 587;                                    // TCP port to connect to

$mail->setFrom('from@example.com', 'Mailer');
$mail->addAddress('joe@example.net', 'Joe User');     // Add a recipient
$mail->addAddress('ellen@example.com');               // Name is optional
$mail->addReplyTo('info@example.com', 'Information');
$mail->addCC('cc@example.com');
$mail->addBCC('bcc@example.com');

$mail->addAttachment('/var/tmp/file.tar.gz');         // Add attachments
$mail->addAttachment('/tmp/image.jpg', 'new.jpg');    // Optional name
$mail->isHTML(true);                                  // Set email format to HTML

$mail->Subject = 'Here is the subject';
$mail->Body    = 'This is the HTML message body <b>in bold!</b>';
$mail->AltBody = 'This is the body in plain text for non-HTML mail clients';
```

...but then before sending, specify a file with the keys you want to use (optional) and the encryption / signing options you want to use:

```php

// Optionally specify a file that contains the keys you want to use
$mail->importKeyFile('/path/to/my-gpg-keyring.asc');

// Turn on encryption for your email
$mail->encrypt(true);

// Turn on signing for your email
$mail->pgpSign(true);

// Turn on protected headers for your email
$mail->protectHeaders(true);

<<<<<<< HEAD
// Send!
if(!$mail->send()) {
    echo 'Message could not be sent.';
    echo 'Mailer Error: ' . $mail->ErrorInfo;
} else {
    echo 'Message has been sent';
}
```
