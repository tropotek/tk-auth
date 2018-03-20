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

    protected $requiredUsername = '';

    protected $requiredPassword = '';

    /**
     * @var callable
     */
    protected $hashCallback = null;


    /**
     * Constructor
     *
     * @param string $requiredUsername The username to validate against
     * @param string $requiredPassword The password to validate against
     */
    public function __construct($requiredUsername, $requiredPassword)
    {
        parent::__construct();
        $this->requiredUsername = $requiredUsername;
        $this->requiredPassword = $requiredPassword;
    }

    /**
     * If a hash function is set then that is used to has a password.
     * The password and the user stdClass is sent to the function for hashing.
     *
     * @param $callable
     * @return $this
     */
    public function setHashCallback($callable)
    {
        $this->hashCallback = $callable;
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
        if ($this->hashCallback) {
            return call_user_func_array($this->hashCallback, array($password, $user));
        }
        return $password;
    }
    
    
    /**
     *
     * @return Result
     */
    public function authenticate()
    {
        $username = $this->get('username');
        $password = $this->get('password');
        
        if ($this->requiredUsername && $this->requiredPassword) {
            if ($username == $this->requiredUsername && $this->hashPassword($password) == $this->requiredPassword) {
                return new Result(Result::SUCCESS, $username);
            }
        }
        return new Result(Result::FAILURE_CREDENTIAL_INVALID, $username, 'Invalid username or password.');
    }
 
}
