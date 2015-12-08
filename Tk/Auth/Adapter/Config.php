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

    protected $config = null;

    protected $usernameKey = 'system.auth.username';

    protected $passwordKey = 'system.auth.password';



    /**
     * Constructor
     *
     * @param array|\Tk\Config   $config
     * @param  string $username The username of the account being authenticated
     * @param  string $password The password of the account being authenticated
     * @throws \Tk\Auth\Exception
     */
    public function __construct($config, $username = null, $password = null)
    {
        parent::__construct($username, $password);
        if (!is_array($config) && !$config instanceof \Tk\Util\ArrayObject) {
            throw new \Tk\Auth\Exception('Invalid config object');
        }
        $this->config = $config;
    }

    /**
     * @return array|null
     */
    public function getConfig()
    {
        return $this->config;
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
     * @return string
     */
    public function getUsernameKey()
    {
        return $this->usernameKey;
    }

    /**
     * @param string $usernameKey
     * @return $this
     */
    public function setUsernameKey($usernameKey)
    {
        $this->usernameKey = $usernameKey;
        return $this;
    }

    /**
     * @return string
     */
    public function getPasswordKey()
    {
        return $this->passwordKey;
    }

    /**
     * @param string $passwordKey
     * @return $this
     */
    public function setPasswordKey($passwordKey)
    {
        $this->passwordKey = $passwordKey;
        return $this;
    }

    /**
     *
     * @return Result
     */
    public function authenticate()
    {
        $cUserKey = $this->config[$this->usernameKey];
        $cPassKey = $this->config[$this->passwordKey];
        if ($cUserKey && $cPassKey) {
            if ($this->getUsername() === $cUserKey && $this->getPassword() === $cPassKey) {
                return new Result(Result::SUCCESS, $this->getUsername());
            }
        }
        return new Result(Result::FAILURE_CREDENTIAL_INVALID, $this->getUsername(), 'Invalid username or password.');
    }

}
