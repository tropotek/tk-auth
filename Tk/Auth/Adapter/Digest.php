<?php
namespace Tk\Auth\Adapter;

use Tk\Auth\Result;

/**
 * Digest Authentication adapter
 *
 * This object uses a .htpasswd file or similar generated by the apache tools.
 * 
 * Config options:
 *
 *   $config['system.auth.digest.file']    = '/home/user/.htpasswd';
 *   $config['system.auth.digest.realm']    = '';
 *   $config['system.auth.digest.scheme']    = 'basic';
 *
 * This adapter requires that the data values have been set
 * ```
 * $adapter->replace(array('username' => $value, 'password' => $password));
 * ```
 * 
 * @see https://en.wikipedia.org/wiki/Digest_access_authentication
 * @todo This needs to be checked, this code will not work securely.
 *
 * @author Michael Mifsud <info@tropotek.com>
 * @see http://www.tropotek.com/
 * @license Copyright 2016 Michael Mifsud
 */
class Digest extends Iface
{
    /**
     * @var string
     */
    protected $scheme = 'basic';
    
    /**
     * @var string
     */
    protected $realm = '';

    /**
     * Full path to the digest password file
     * @var string
     */
    protected $file = '';


    /**
     * @param string $file
     * @param string $realm
     * @param $scheme
     * @throws \Tk\Auth\Exception
     */
    public function __construct($file, $realm, $scheme)
    {
        parent::__construct();
        $this->file = $file;
        $this->scheme = $scheme;
        $this->realm = $realm;
        if (!is_file($this->file)) {
            throw new \Tk\Auth\Exception('Cannot locate digest file: ' . $this->file);
        }
        //$this->setHashFunction('md5');
    }


    /**
     * Defined by Tk\Auth\Adapter\Iface
     *
     * @return \Tk\Auth\Result
     * @throws \Tk\Exception
     */
    public function authenticate()
    {
        $username = $this->get('username');
        $password = $this->get('password');
        
        if (false === ($fileHandle = @fopen($this->file, 'r'))) {
            return new Result(Result::FAILURE, $username, 'System authentication error.');
        }
        $id = $username . ':' . $this->realm;
        $idLength = strlen($id);
        while ($line = trim(fgets($fileHandle))) {
            if (substr($line, 0, $idLength) === $id) {
                if ( $this->_secureStringCompare(substr($line, -32), hash('md5', sprintf('%s:%s:%s', $username, $this->realm, $password))) ) {
                    $this->dispatchLoginProcess();
                    if ($this->getLoginProcessEvent()->getResult()) {
                        return $this->getLoginProcessEvent()->getResult();
                    }
                    return new Result(Result::SUCCESS, $username);
                } else {
                    return new Result(Result::FAILURE_CREDENTIAL_INVALID, $username, 'Username or Password incorrect');
                }
            }
        }
        return new Result(Result::FAILURE_IDENTITY_NOT_FOUND, $username, 'Invalid username or password.');
    }

    /**
     * Securely compare two strings for equality while avoided C level memcmp()
     * optimisations capable of leaking timing information useful to an attacker
     * attempting to iteratively guess the unknown string (e.g. password) being
     * compared against.
     *
     * @param string $a
     * @param string $b
     * @return bool
     */
    protected function _secureStringCompare($a, $b)
    {
        if (strlen($a) !== strlen($b)) {
            return false;
        }
        $result = 0;
        for ($i = 0; $i < strlen($a); $i++) {
            $result |= ord($a[$i]) ^ ord($b[$i]);
        }
        return $result == 0;
    }
}

