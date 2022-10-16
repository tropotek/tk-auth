<?php
namespace Tk\Auth\Adapter;

use Tk\Auth\Result;
use Tk\Auth\Auth;

/**
 * A Config admin authenticator adaptor
 *
 * Useful for single user sites, such as admin areas.
 *
 * This system of authentication should not be used for sites that require high security
 * It is ideal for low security sites that do not hold sensitive information.
 *
 * This adaptor requires that the password and username are submitted in a POST/GET request
 * 
 * @author Tropotek <http://www.tropotek.com/>
 */
class Config extends AdapterInterface
{

    protected string $requiredUsername = '';

    /**
     * This should be a md5 hashed value of the password not the actual password.
     */
    protected string $requiredPassword = '';


    public function __construct(string $requiredUsername, string $requiredPassword)
    {
        $this->requiredUsername = $requiredUsername;
        $this->requiredPassword = $requiredPassword;
    }

    public function authenticate(): Result
    {
        // get values from a post or get request
        $username = $this->getFactory()->getRequest()->get('username');
        $password = $this->getFactory()->getRequest()->get('password');
        
        if ($this->requiredUsername && $this->requiredPassword) {
            if ($username == $this->requiredUsername && Auth::hashPassword($password) == $this->requiredPassword) {
                return new Result(Result::SUCCESS, $username);
            }
        }
        return new Result(Result::FAILURE_CREDENTIAL_INVALID, $username, 'Invalid username or password.');
    }
 
}
