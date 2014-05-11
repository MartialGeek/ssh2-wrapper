<?php

namespace Martial\Components\Network\SSH;

/**
 * Class Ssh2Wrapper.
 * A stateless wrapper object for the SSH2 PHP extension.
 */
class Ssh2Wrapper
{
    /**
     * Authenticate over SSH using the ssh agent.
     *
     * @param resource $session
     * @param string $username
     * @throws \BadFunctionCallException
     * @return mixed
     */
    public function authAgent($session, $username)
    {
        if (!function_exists('ssh2_auth_agent')) {
            throw new \BadFunctionCallException('The function ssh2_auth_agent does not exist.');
        }

        return ssh2_auth_agent($session, $username);
    }

    /**
     * Authenticate using a public hostkey.
     *
     * @param resource $session
     * @param string $username
     * @param string $hostname
     * @param string $pubKeyFile
     * @param string $privKeyFile
     * @param string $passphrase
     * @param string $localUsername
     * @return bool
     */
    public function authBasedHostFile(
        $session,
        $username,
        $hostname,
        $pubKeyFile,
        $privKeyFile,
        $passphrase = '',
        $localUsername = ''
    ) {
        return ssh2_auth_hostbased_file(
            $session,
            $username,
            $hostname,
            $pubKeyFile,
            $privKeyFile,
            $passphrase,
            $localUsername
        );
    }

    /**
     * Authenticate as "none".
     *
     * @param resource $session
     * @param string $username
     * @return mixed
     */
    public function authNone($session, $username)
    {
        return ssh2_auth_none($session, $username);
    }

    /**
     * Authenticate over SSH using a plain password.
     *
     * @param resource $session
     * @param string $username
     * @param string $password
     * @return bool
     */
    public function authPassword($session, $username, $password)
    {
        return ssh2_auth_password($session, $username, $password);
    }

    /**
     * Authenticate using a public key.
     *
     * @param resource $session
     * @param string $username
     * @param string $pubKeyFile
     * @param string $privKeyFile
     * @param string $passphrase
     * @return bool
     */
    public function authPubKeyFile($session, $username, $pubKeyFile, $privKeyFile, $passphrase = '')
    {
        return ssh2_auth_pubkey_file($session, $username, $pubKeyFile, $privKeyFile, $passphrase);
    }

    /**
     * Connect to an SSH server.
     *
     * @param string $host
     * @param int $port
     * @param array $methods
     * @param array $callbacks
     * @return resource
     */
    public function connect($host, $port = 22, array $methods = array(), array $callbacks = array())
    {
        return ssh2_connect($host, $port, $methods, $callbacks);
    }

    /**
     * Execute a command on a remote server.
     *
     * @param resource $session
     * @param string $command
     * @param string $pty
     * @param array $env
     * @param int $width
     * @param int $height
     * @param int $widthHeightType
     * @return resource
     */
    public function exec(
        $session,
        $command,
        $pty = '',
        array $env = array(),
        $width = 80,
        $height = 25,
        $widthHeightType = SSH2_TERM_UNIT_CHARS
    ) {
        return ssh2_exec($session, $command, $pty, $env, $width, $height, $widthHeightType);
    }

    /**
     * Fetch an extended data stream.
     *
     * @param resource $channel
     * @param int $streamId
     * @return resource
     */
    public function fetchStream($channel, $streamId)
    {
        return ssh2_fetch_stream($channel, $streamId);
    }

    /**
     * Retrieve fingerprint of remote server.
     *
     * @param resource $session
     * @param int $flags
     * @return string
     */
    public function fingerprint($session, $flags = null)
    {
        return ssh2_fingerprint($session, $flags);
    }

    /**
     * Return list of negotiated methods.
     *
     * @param resource $session
     * @return array
     */
    public function methodsNegociated($session)
    {
        return ssh2_methods_negotiated($session);
    }

    /**
     * Add an authorized publickey.
     *
     * @param resource $publicKey
     * @param string $algoName
     * @param string $blob
     * @param bool $overwrite
     * @param array $attributes
     * @return bool
     */
    public function publicKeyAdd($publicKey, $algoName, $blob, $overwrite = false, array $attributes = array())
    {
        return ssh2_publickey_add($publicKey, $algoName, $blob, $overwrite, $attributes);
    }

    /**
     * Initialize Publickey subsystem.
     *
     * @param resource $session
     * @return resource
     */
    public function publicKeyInit($session)
    {
        return ssh2_publickey_init($session);
    }

    /**
     * List currently authorized publickeys.
     *
     * @param resource $publicKey
     * @return array
     */
    public function publicKeyList($publicKey)
    {
        return ssh2_publickey_list($publicKey);
    }

    /**
     * Remove an authorized publickey.
     *
     * @param resource $publicKey
     * @param string $algoName
     * @param string $blob
     * @return bool
     */
    public function publicKeyRemove($publicKey, $algoName, $blob)
    {
        return ssh2_publickey_remove($publicKey, $algoName, $blob);
    }

    /**
     * Remove an authorized publickey.
     *
     * @param resource $session
     * @param string $remoteFile
     * @param string $localFile
     * @return bool
     */
    public function scpRecv($session, $remoteFile, $localFile)
    {
        return ssh2_scp_recv($session, $remoteFile, $localFile);
    }

    /**
     * Send a file via SCP.
     *
     * @param resource $session
     * @param string $localFile
     * @param string $remoteFile
     * @param int $createMode
     * @return bool
     */
    public function scpSend($session, $localFile, $remoteFile, $createMode = 0644)
    {
        return ssh2_scp_send($session, $localFile, $remoteFile, $createMode);
    }

    /**
     * Changes file mode.
     *
     * @param resource $sftp
     * @param string $filename
     * @param int $mode
     * @throws \BadFunctionCallException
     * @return bool
     */
    public function sftpChmod($sftp, $filename, $mode)
    {
        if (!function_exists('ssh2_sftp_chmod')) {
            throw new \BadFunctionCallException('The function ssh2_sftp_chmod does not exist.');
        }

        return ssh2_sftp_chmod($sftp, $filename, $mode);
    }

    /**
     * Stat a symbolic link.
     *
     * @param resource $sftp
     * @param string $path
     * @return array
     */
    public function sftpLstat($sftp, $path)
    {
        return ssh2_sftp_lstat($sftp, $path);
    }

    /**
     * Create a directory.
     *
     * @param resource $sftp
     * @param string $dirname
     * @param int $mode
     * @param bool $recursive
     * @return bool
     */
    public function sftpMkdir($sftp, $dirname, $mode = 0777, $recursive = false)
    {
        return ssh2_sftp_mkdir($sftp, $dirname, $mode, $recursive);
    }

    /**
     * Return the target of a symbolic link.
     *
     * @param resource $sftp
     * @param string $link
     * @return string
     */
    public function sftpReadLink($sftp, $link)
    {
        return ssh2_sftp_readlink($sftp, $link);
    }

    /**
     * Resolve the realpath of a provided path string.
     *
     * @param resource $sftp
     * @param string $filename
     * @return string
     */
    public function sftpRealPath($sftp, $filename)
    {
        return ssh2_sftp_realpath($sftp, $filename);
    }

    /**
     * Rename a remote file.
     *
     * @param resource $sftp
     * @param string $from
     * @param string $to
     * @return bool
     */
    public function sftpRename($sftp, $from, $to)
    {
        return ssh2_sftp_rename($sftp, $from, $to);
    }

    /**
     * Remove a directory.
     *
     * @param resource $sftp
     * @param string $dirname
     * @return bool
     */
    public function sftpRmdir($sftp, $dirname)
    {
        return ssh2_sftp_rmdir($sftp, $dirname);
    }

    /**
     * Stat a file on a remote filesystem.
     *
     * @param resource $sftp
     * @param string $path
     * @return array
     */
    public function sftpStat($sftp, $path)
    {
        return ssh2_sftp_stat($sftp, $path);
    }

    /**
     * Create a symlink.
     *
     * @param resource $sftp
     * @param string $target
     * @param string $link
     * @return bool
     */
    public function sftpSymlink($sftp, $target, $link)
    {
        return ssh2_sftp_symlink($sftp, $target, $link);
    }

    /**
     * Delete a file.
     *
     * @param resource $sftp
     * @param string $filename
     * @return bool
     */
    public function sftpUnlink($sftp, $filename)
    {
        return ssh2_sftp_unlink($sftp, $filename);
    }

    /**
     * Initialize SFTP subsystem.
     *
     * @param resource $session
     * @return resource
     */
    public function sftp($session)
    {
        return ssh2_sftp($session);
    }

    /**
     * Request an interactive shell.
     *
     * @param resource $session
     * @param string $termType
     * @param array $env
     * @param int $width
     * @param int $height
     * @param int $widthHeightType
     * @return resource
     */
    public function shell(
        $session,
        $termType = 'vanilla',
        array $env = array(),
        $width = 80,
        $height = 25,
        $widthHeightType = SSH2_TERM_UNIT_CHARS
    ) {
        return ssh2_shell($session, $termType, $env, $width, $height, $widthHeightType);
    }

    /**
     * Open a tunnel through a remote server.
     *
     * @param resource $session
     * @param string $host
     * @param int $port
     * @return resource
     */
    public function tunnel($session, $host, $port)
    {
        return ssh2_tunnel($session, $host, $port);
    }
}