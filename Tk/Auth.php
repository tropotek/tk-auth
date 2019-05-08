<?php
namespace Tk;


use Tk\Auth\Result;

/**
 * This Auth object validates a user and manages a user session/cookie/object
 *
 *
 * @author Michael Mifsud <info@tropotek.com>
 * @see http://www.tropotek.com/
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
     * @throws Auth\Exception
     */
    public function authenticate($adapter)
    {
        if ($this->hasIdentity()) {
            $this->clearIdentity();
        }
        $loginResult = new Result(Result::FAILURE_UNKNOWN, '', 'Login Error: Contact Administrator.');
        if ($adapter) {
            $loginResult = $adapter->authenticate();
        }
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
