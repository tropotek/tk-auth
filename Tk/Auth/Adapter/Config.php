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
 * @link http://www.tropotek.com/
 * @license Copyright 2016 Michael Mifsud
 */
class Config extends Iface
{

    protected $requiredUsername = '';

    protected $requiredPassword = '';


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
     * Override this method for more secure password encoding
     *
     * @param $password
     * @return string
     */
    public function hashPassword($password)
    {
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
