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
 * Config options:
 *
 *   $config['system.auth.config.username']    = 'admin';
 *   $config['system.auth.config.password']    = 'password';
 *
 * This system of authentication should not be used for sites that require high security
 * It is ideal for low security sites that do not hold sensitive information.
 *
 */
class Config extends Iface
{

    protected $config = null;


    /**
     * Constructor
     *
     * @param  string $username The username of the account being authenticated
     * @param  string $password The password of the account being authenticated
     * @param array|\Tk\Config   $config
     * @throws \Tk\Auth\Exception
     */
    public function __construct($username = null, $password = null, $config = array())
    {
        parent::__construct($username, $password);
        $this->config = $config;
    }

    /**
     * @param array|null $config
     * @return $this
     */
    public function setConfig($config)
    {
        $this->config = $config;
        return $this;
    }

    /**
     *
     * @return Result
     */
    public function authenticate()
    {
        $cUserKey = $this->config['system.auth.config.username'];
        $cPassKey = $this->config['system.auth.config.password'];
        if ($cUserKey && $cPassKey) {
            if ($this->getUsername() === $cUserKey && $this->getPassword() === $cPassKey) {
                return new Result(Result::SUCCESS, $this->getUsername());
            }
        }
        return new Result(Result::FAILURE_CREDENTIAL_INVALID, $this->getUsername(), 'Invalid username or password.');
    }

}
