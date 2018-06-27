<?php
namespace Tk\Auth\Adapter;

use Tk\Auth\Result;

/**
 * A Config admin authenticator adaptor
 *
 * Useful for single user sites, such as admin areas.
 *
 * This system of authentication should not be used for sites that require high security
 * It is ideal for low security sites that do not hold sensitive information.
 * 
 * This adapter requires that the data values have been set
 * ```
 * $adapter->replace(array('username' => $value, 'password' => $password));
 * ```
 * 
 * @author Michael Mifsud <info@tropotek.com>
 * @see http://www.tropotek.com/
 * @license Copyright 2016 Michael Mifsud
 */
class Config extends Iface
{
    /**
     * @var string
     */
    protected $requiredUsername = '';

    /**
     * @var string
     */
    protected $requiredPassword = '';

    /**
     * @var callable
     */
    protected $onHash = null;


    /**
     * Constructor
     *
     * @param string $requiredUsername The username to validate against
     * @param string $requiredPassword The password to validate against
     * @param null|callable $onHash
     */
    public function __construct($requiredUsername, $requiredPassword, $onHash = null)
    {
        parent::__construct();
        $this->requiredUsername = $requiredUsername;
        $this->requiredPassword = $requiredPassword;
        $this->onHash = $onHash;
    }

    /**
     * If a hash function is set then that is used to hash a password.
     *
     * @param $callable
     * @return $this
     */
    public function setOnHash($callable)
    {
        $this->onHash = $callable;
        return $this;
    }

    /**
     * Override this method for more secure password encoding
     *
     * @param $password
     * @param \stdClass $user
     * @return string
     */
    public function hashPassword($password, $user = null)
    {
        if ($this->onHash) {
            return call_user_func_array($this->onHash, array($password, $user));
        }
        return $password;
    }


    /**
     * @return Result
     * @throws \Tk\Exception
     */
    public function authenticate()
    {
        $username = $this->get('username');
        $password = $this->get('password');
        
        if ($this->requiredUsername && $this->requiredPassword) {
            if ($username == $this->requiredUsername && $this->hashPassword($password) == $this->requiredPassword) {
                /** @var \Tk\Event\Dispatcher $dispatcher */
                $dispatcher = $this->getConfig()->getEventDispatcher();
                if ($dispatcher) {
                    $event = new \Tk\Event\AuthAdapterEvent($this);
                    $dispatcher->dispatch(\Tk\Auth\AuthEvents::LOGIN_PROCESS, $event);
                    if ($event->getResult()) {
                        return $event->getResult();
                    }
                }
                return new Result(Result::SUCCESS, $username, 'User Found!');
            }
        }
        return new Result(Result::FAILURE_CREDENTIAL_INVALID, $username, 'Invalid username or password.');
    }
 
}
