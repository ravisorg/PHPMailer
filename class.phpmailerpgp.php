<?php

/**
 * PHPMailerPGP - PHPMailer subclass adding PGP/MIME signing and encryption.
 * @package PHPMailer
 * @author Travis Richardson (@ravisorg)
 */
class PHPMailerPGP extends PHPMailer
{

    /**
     * The signing hash algorithm. 'MD5', SHA1, or SHA256. SHA256 (the default) is highly recommended
     * unless you need to deal with an old client that doesn't support it. SHA1 and MD5 are 
     * currently considered cryptographically weak.
     * @type string
     */
    protected $micalg = 'SHA256';

    /**
     * The path to the public PGP key that we will use to encrypt the message. Generally this is the
     * key of the person in the email's "To" line. If this is not set, the message will not be 
     * encrypted.
     * @type string
     * @access protected
     */
    protected $pgp_encrypt_key_file = '';

    /**
     * The path to the private PGP key that we will use to sign the message. Generally this is the
     * key of the person in the email's "From" line. If this is not set, the message will not be
     * signed.
     * @type string
     * @access protected
     */
    protected $pgp_signature_key_file = '';

    /**
     * The password to use to decrypt pgp_signature_key_file, if required.
     * @type string
     * @access protected
     */
    protected $pgp_signature_key_pass = '';

    public function signPGP($pgp_signature_key_file,$pgp_signature_key_pass = '') {
        $this->pgp_signature_key_file = $pgp_signature_key_file;
        $this->pgp_signature_key_pass = $pgp_signature_key_pass;
    }

    public function encryptPGP($pgp_recipient_key_file) {
        $this->pgp_encrypt_key_file = $pgp_recipient_key_file;
    }

    public function getMailMIME()
    {
        $result = '';
        switch ($this->message_type) {
            case 'signed':
                $result .= $this->headerLine('Content-Type', 'multipart/signed; micalg="pgp-' . strtolower($this->micalg) . '";');
                $result .= $this->textLine("\tprotocol=\"application/pgp-signature\";");
                $result .= $this->textLine("\tboundary=\"" . $this->boundary[1] . '"');
                if ($this->Mailer != 'mail') {
                    $result .= $this->LE;
                }
                break;
            case 'encrypted':
                $result .= $this->headerLine('Content-Type', 'multipart/encrypted;');
                $result .= $this->textLine("\tprotocol=\"application/pgp-encrypted\";");
                $result .= $this->textLine("\tboundary=\"" . $this->boundary[1] . '"');
                if ($this->Mailer != 'mail') {
                    $result .= $this->LE;
                }
                break;
            default:
                $result = parent::getMailMIME();
                break;
        }

        return $result;
    }

    /**
     * Assemble the message body, signs it (if a signing key is provided) and encrypts it (if 
     * an encryption key is provided).
     * Returns an empty string on failure.
     * @access public
     * @throws phpmailerException
     * @return string The assembled message body
     */
    public function createBody()
    {

        if ($this->pgp_signature_key_file) {
            // PGP/Mime requires line endings that are CRLF (RFC3156 section 5)
            $this->LE = "\r\n";

            // PGP/Mime requires 7 bit encoding (RFC3156 section 3, 5.1)
            $this->Encoding = 'quoted-printable';
        }

        // Get the "normal" (unsigned / unencrypted) body from the parent class.
        $body = parent::createBody();

        // If the parent returned an empty body, then there's no need to encrypt / sign anything.
        if (!$body) {
            return $body;
        }

        // If we're using PGP to sign the message, do that before encrypting.
        if ($this->pgp_signature_key_file) {
            // Generate a new "body" that contains all the mime parts of the existing body, encrypt
            // it, then replace the body with the encrypted content.

            // Add in headers so when the encrypted chunk is decoded, it looks like a message block
            // (RFC3156 section 5.3)
            $signedBody = $this->getMailMIME() . $body;

            // Remove trailing whitespace from all lines and convert line all endings to CRLF
            // (RFC3156 section 5.1)
            $lines = preg_split('/(\r\n|\r|\n)/',rtrim($signedBody));
            for ($i=0; $i<count($lines); $i++) {
                $lines[$i] = rtrim($lines[$i])."\r\n";
            }

            // Remove excess trailing newlines (RFC3156 section 5.4)
            $signedBody = rtrim(implode('',$lines))."\r\n";

            // Sign it
            $signature = $this->pgp_sign_string($signedBody);

            // The main email MIME type is no longer what the developer specified, it's now 
            // multipart/signed
            $this->message_type = 'signed';

            // We calculated the content hash using SHA1, so note that.
            $this->micalg = 'SHA256';

            // Generate new boundaries, and make sure they're not the same as the old ones (because 
            // it's possible that generating, signing, and encrypting the body takes less than a 
            // second, we prepend some text unique to this instance).
            $boundary = md5('pgpsign'.uniqid(time()));
            $this->boundary[1] = 'b1_'.$boundary;
            $this->boundary[2] = 'b2_'.$boundary;
            $this->boundary[3] = 'b3_'.$boundary;

            // The body of the email is pretty simple, so instead of modifying all the various 
            // functions to support PGP/Mime, we'll just build it here
            $body = '';
            $body .= $this->textLine('This is an OpenPGP/MIME signed message (RFC 4880 and 3156)');
            $body .= $this->LE;
            $body .= $this->textLine('--b1_' . $boundary);
            $body .= $signedBody; // will already have a CRLF at the end, don't add another one
            $body .= $this->LE;
            $body .= $this->textLine('--b1_' . $boundary);
            $body .= $this->textLine('Content-Type: application/pgp-signature; name="signature.asc"');
            $body .= $this->textLine('Content-Description: OpenPGP digital signature');
            $body .= $this->textLine('Content-Disposition: attachment; filename="signature.asc"');
            $body .= $this->LE;
            $body .= $signature;
            $body .= $this->LE;
            $body .= $this->LE;
            $body .= $this->textLine('--b1_' . $boundary . '--');
        }

        // If we're using PGP to encrypt the message, do that now.
        if ($this->pgp_encrypt_key_file) {
            // Generate a new "body" that contains all the mime parts of the existing body, encrypt
            // it, then replace the body with the encrypted content.
            // Note that this body may be inherited from the signing code above, which inherited it
            // from the parent object.

            // Add in headers so when the encrypted chunk is decoded, it looks like a message block
            $encryptedBody = $this->getMailMIME() . $body;

            // Encrypt it
            $encryptedBody = $this->pgp_encrypt_string($encryptedBody,$this->pgp_encrypt_key_file);

            // Replace the email the developer built with an encrypted version
            $this->message_type = 'encrypted';
            $this->Encoding = '7bit';

            // Generate new boundaries, and make sure they're not the same as the old ones (because 
            // it's possible that generating, signing, and encrypting the body takes less than a 
            // second, we prepend some text unique to this instance).
            $boundary = md5('pgpencrypt'.uniqid(time()));
            $this->boundary[1] = 'b1_'.$boundary;
            $this->boundary[2] = 'b2_'.$boundary;
            $this->boundary[3] = 'b3_'.$boundary;

            // The body of the email is pretty simple, so instead of modifying all the various 
            // functions to support PGP/Mime, we'll just build it here
            $body = '';
            $body .= $this->textLine('This is an OpenPGP/MIME encrypted message (RFC 4880 and 3156)');
            $body .= $this->LE;
            $body .= $this->textLine('--b1_' . $boundary);
            $body .= $this->textLine('Content-Type: application/pgp-encrypted');
            $body .= $this->textLine('Content-Description: PGP/MIME version identification');
            $body .= $this->LE;
            $body .= $this->textLine('Version: 1');
            $body .= $this->LE;
            $body .= $this->textLine('--b1_' . $boundary);
            $body .= $this->textLine('Content-Type: application/octet-stream; name="encrypted.asc"');
            $body .= $this->textLine('Content-Description: OpenPGP encrypted message');
            $body .= $this->textLine('Content-Disposition: inline; filename="encrypted.asc"');
            $body .= $this->LE;
            $body .= $encryptedBody;
            $body .= $this->LE;
            $body .= $this->LE;
            $body .= $this->textLine('--b1_' . $boundary . '--');
        }

        return $body;

    }

    protected function pgp_sign_string($plaintext,$signature_key=null,$signature_key_pass=null) {
        $signed = $this->pgp_sign_string_gpgcli($plaintext,$signature_key,$signature_key_pass);
        if (!is_null($signed)) {
            return $signed;
        }

        // We were unable to find a method to encrypt data
        return null;
    }

    /**
     * Signs a string using the GPG command line client, if it's installed on the system and in
     * the path (or specified with phpmailerpgp::GPGPath).
     * Returns NULL if the system could not find an executable named gpg.
     * @access public
     * @param $recipient_key string The email address of the recipient. When using this function the 
     * recipient's key MUST already exists in the user's keychain. Also be aware that the user 
     * running this code may be different from the user you upload as (eg: apache often runs as 
     * 'apache' or 'nobody'). In addition, that user may not have a keychain at all, and may not 
     * have the proper permissions to create one. You can get around most of these problems by 
     * calling phpmailerphp::keychainPath() and specifying a path to an existing keychain before 
     * sending your message.
     * @param  $string string The string to encrypt
     * @return string An ASCII armored encrypted string
     * @throws phpmailerException If the GPG command line client was unable to encrypt the string.
     * @see https://gnupg.org/ GnuPG web site
     * @see phpmailerphp::keychainPath()
     */
    protected function pgp_sign_string_gpgcli($plaintext,$signature_key=null,$signature_key_pass=null) {

        // Pull in defaults from the object settings, if not specified above.
        if (is_null($signature_key)) {
            $signature_key = $this->pgp_signature_key_file;
        }
        if (is_null($signature_key_pass)) {
            $signature_key_pass = $this->pgp_signature_key_pass;
        }

        // Set up the command to run GPG
        $command = "/usr/bin/gpg --quiet --no-tty --local-user ".escapeshellarg($signature_key)." --detach-sign --armor --digest-algo ".escapeshellarg($this->micalg);

        // Set up the ways we're going to communicate with the GPG process.
        $descriptorspec = array(
           0 => array("pipe", "r"), // stdin
           1 => array("pipe", "w"), // stdout
           2 => array("pipe", "r"), // stderr
        );

        // Safely pass the key passphrase to GPG
        // "Safely" because presumably you have the passphrase hardcoded somewhere :/
        if ($signature_key_pass) {
            $command .= " --batch --passphrase-fd 3";
            $descriptorspec[3] = array("pipe", "r");  // where we'll write the password to
        }

        // Start the process and open the io pipes.
        $process = proc_open($command, $descriptorspec, $pipes);

        // if the command wasn't available, return null
        if (!is_resource($process)) {
            return null;
        }

        // Send our password to unlock the signing key, if needed
        if ($signature_key_pass) {
            fwrite($pipes[3], $signature_key_pass);
            fclose($pipes[3]);
        }

        // Send our string to encrypt to the process, and then close the pipe so the process knows
        // we're done sending input.
        fwrite($pipes[0], $plaintext);
        fclose($pipes[0]);

        // Read all the output from the process, and then close the pipe (we don't need it anymore).
        $result = trim(stream_get_contents($pipes[1]));
        fclose($pipes[1]);

        // If there was data sent to stderr, we want to know what it was. Read it all and then close
        // the pipe.
        $error = stream_get_contents($pipes[2]);
        fclose($pipes[2]);

        // It is important that you close any pipes before calling
        // proc_close in order to avoid a deadlock
        $return_value = proc_close($process);

        if ($return_value!==0) {
            throw new phpmailerException($error);
        }
        return $result;

    }

    /**
     * Encrypts a string using the specified recipient key.
     * This function calls each of the pgp_encrypt_string_* functions (in order of efficiency) to
     * try and find an implementation of PGP that we can use. Returns NULL if we were unable to find
     * any workable implementation of PGP or GPG.
     * @param $recipient_key string The email address or path to file containing the recipient's 
     * public key. This is complex. Clarify.
     * @param $plaintext string The string to encrypt
     * @todo Clarify recipient key
     * @access public
     * @return string An ASCII armored encrypted string, or NULL if no method of encryption was 
     * available.
     */
    protected function pgp_encrypt_string($plaintext,$recipient_key) {
        $encrypted = $this->pgp_encrypt_string_gpgcli($plaintext,$recipient_key);
        if (!is_null($encrypted)) {
            return $encrypted;
        }

        // We were unable to find a method to encrypt data
        return null;
    }

    /**
     * Encrypts a string using the GPG command line client, if it's installed on the system and in
     * the path (or specified with phpmailerpgp::GPGPath).
     * Returns NULL if the system could not find an executable named gpg.
     * @access public
     * @param $recipient_key string The email address of the recipient. When using this function the 
     * recipient's key MUST already exists in the user's keychain. Also be aware that the user 
     * running this code may be different from the user you upload as (eg: apache often runs as 
     * 'apache' or 'nobody'). In addition, that user may not have a keychain at all, and may not 
     * have the proper permissions to create one. You can get around most of these problems by 
     * calling phpmailerphp::keychainPath() and specifying a path to an existing keychain before 
     * sending your message.
     * @param  $string string The string to encrypt
     * @return string An ASCII armored encrypted string
     * @throws phpmailerException If the GPG command line client was unable to encrypt the string.
     * @see https://gnupg.org/ GnuPG web site
     * @see phpmailerphp::keychainPath()
     */
    protected function pgp_encrypt_string_gpgcli($plaintext,$recipient_key) {
        $command = "gpg --yes --batch --quiet --recipient ".escapeshellarg($recipient_key)." --encrypt --armor";
        $descriptorspec = array(
           0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
           1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
           2 => array("pipe", "r"),  // stderr is a pipe that the child will read from
        );
        $process = proc_open($command, $descriptorspec, $pipes);

        // if the command wasn't available, return null
        if (!is_resource($process)) {
            return null;
        }

        // Send our string to encrypt to the process, and then close the pipe so the process knows
        // we're done sending input.
        fwrite($pipes[0], $plaintext);
        fclose($pipes[0]);

        // Read all the output from the process, and then close the pipe (we don't need it anymore).
        $result = trim(stream_get_contents($pipes[1]));
        fclose($pipes[1]);

        // If there was data sent to stderr, we want to know what it was. Read it all and then close
        // the pipe.
        $error = stream_get_contents($pipes[2]);
        fclose($pipes[2]);

        // It is important that you close any pipes before calling
        // proc_close in order to avoid a deadlock
        $return_value = proc_close($process);

        if ($return_value!==0) {
            throw new phpmailerException($error);
        }
        return $result;

    }

}
