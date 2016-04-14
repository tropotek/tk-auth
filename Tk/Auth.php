<?php
namespace Tk;

/**
 * This Auth object validates a user and manages a user session/cookie/object
 *
 *
 * @author Michael Mifsud <info@tropotek.com>
 * @link http://www.tropotek.com/
 * @license Copyright 2015 Michael Mifsud
 */
class Auth
{

    /**
     * Persistent storage handler
     *
     * @var Auth\Storage\Iface
     */
    protected $storage = null;

    /**
     * @var Auth\Result
     */
    public $loginResult = null;



    /**
     *
     * @param Auth\Storage\Iface $storage Default storage is Storage\Session()
     */
    public function __construct(Auth\Storage\Iface $storage = null)
    {
        $this->setStorage($storage);
    }

    /**
     * Create a random password
     *
     * @param int $length
     * @return string
     */
    public static function createPassword($length = 8)
    {
        $chars = '234567890abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ';
        $i = 0;
        $password = '';
        while ($i <= $length) {
            $password .= $chars[mt_rand(0, strlen($chars) - 1)];
            $i++;
        }
        return $password;
    }

    /**
     * Create a hash using the config defined function
     * NOTE:
     *   If the has function is changed after the site
     *   is installed major problems can occur to fix
     *   you will have to reset all user passwords.
     *
     *  Find the hash functions available via hash_algos();
     *
     * @param string $str
     * @param string $hashFunc
     * @return string (Hashed string to store or compare)
     */
    public static function hash($str, $hashFunc = 'md5')
    {
        return hash($hashFunc, $str);
    }

    /**
     * Returns true if and only if an identity is available from storage
     *
     * @return bool
     */
    public function hasIdentity()
    {
        return !$this->getStorage()->isEmpty();
    }

    /**
     * Returns the user details from storage or null if non is available
     *
     * @return mixed
     */
    public function getIdentity()
    {
        $storage = $this->getStorage();
        if ($storage->isEmpty()) {
            return null;
        }
        return $storage->read();
    }

    /**
     * Returns the persistent storage handler
     *
     * @return Auth\Storage\Iface
     */
    public function getStorage()
    {
        return $this->storage;
    }

    /**
     * Sets the persistent storage handler
     *
     * @param  Auth\Storage\Iface $storage
     * @return $this
     */
    public function setStorage(Auth\Storage\Iface $storage)
    {
        $this->storage = $storage;
        return $this;
    }

    /**
     * Authenticates against the supplied adapter
     *
     * @param  Auth\Adapter\Iface $adapter
     * @return Auth\Result
     */
    public function authenticate(Auth\Adapter\Iface $adapter)
    {
        // Clear storage
        if ($this->hasIdentity()) {
            $this->clearIdentity();
        }
        $loginResult = $adapter->authenticate();
        if ($loginResult && $loginResult->isValid()) {
            $this->getStorage()->write($loginResult->getIdentity());
        }
        return $loginResult;
    }


    /**
     * Clears the user details from persistent storage
     *
     * @return $this
     */
    public function clearIdentity()
    {
        $this->getStorage()->clear();
        return $this;
    }

}
