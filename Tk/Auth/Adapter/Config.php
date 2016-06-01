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
     *
     * @return Result
     */
    public function authenticate()
    {
        if ($this->requiredUsername && $this->requiredPassword) {
            $pwd = $this->get('password');
            if ($this->getHashFunction()) {
                $pwd = $this->hash($pwd);
            }
            if ($this->get('username') == $this->requiredUsername && $pwd == $this->requiredPassword) {
                return new Result(Result::SUCCESS, $this->get('username'));
            }
        }
        return new Result(Result::FAILURE_CREDENTIAL_INVALID, $this->get('username'), 'Invalid username or password.');
    }
 
}
