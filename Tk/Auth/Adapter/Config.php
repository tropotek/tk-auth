<?php
/*
 * @author Michael Mifsud <info@tropotek.com>
 * @link http://www.tropotek.com/
 * @license Copyright 2007 Michael Mifsud
 */
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
 */
class Config extends Iface
{

    protected $validUsername = '';
    
    protected $validPassword = '';


    /**
     * Constructor
     *
     * @param string $validUsername The username to validate against
     * @param string $validPassword The password to validate against
     */
    public function __construct($validUsername, $validPassword)
    {
        $this->validUsername = $validUsername;
        $this->validPassword = $validPassword;
            vd($this->validUsername, $this->validPassword);
    }

    /**
     *
     * @return Result
     */
    public function authenticate()
    {
        if ($this->validUsername && $this->validPassword) {
            vd($this->getUsername(), $this->validUsername , $this->getPassword(), $this->validPassword);
            if ($this->getUsername() === $this->validUsername && $this->getPassword() === $this->validPassword) {
                return new Result(Result::SUCCESS, $this->getUsername());
            }
        }
        return new Result(Result::FAILURE_CREDENTIAL_INVALID, $this->getUsername(), 'Invalid username or password.');
    }

}
