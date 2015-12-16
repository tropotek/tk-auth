<?php
/*
 * @author Michael Mifsud <info@tropotek.com>
 * @link http://www.tropotek.com/
 * @license Copyright 2007 Michael Mifsud
 */
namespace Tk\Auth\Adapter;

/**
 * Adapter Interface
 * 
 *
 * @package Tk\Auth\Adapter
 */
abstract class Iface
{

    /**
     * The username of the account being authenticated.
     * @var string
     */
    protected $username = null;

    /**
     * The password of the account being authenticated.
     * @var string
     */
    protected $password = null;



    /**
     * Performs an authentication attempt
     *
     * @return \Tk\Auth\Result
     * @throws \Tk\Auth\Exception If authentication cannot be performed
     */
    abstract public function authenticate();

    /**
     * @param string $username
     * @param string $password
     * @return $this
     */
    public function setCredentials($username, $password) 
    {
        $this->setUsername($username);
        $this->setPassword($password);
        return $this;
    }

    /**
     * Returns the username of the account being authenticated, or
     * NULL if none is set.
     *
     * @return string|null
     */
    public function getUsername()
    {
        return $this->username;
    }

    /**
     * Sets the username for binding
     *
     * @param  string $username The username for binding
     * @return Iface
     */
    public function setUsername($username)
    {
        $this->username = (string) $username;
        return $this;
    }

    /**
     * Returns the password of the account being authenticated, or
     * NULL if none is set.
     *
     * @return string|null
     */
    public function getPassword()
    {
        return $this->password;
    }

    /**
     * Sets the password for the account
     *
     * @param  string $password The password of the account being authenticated
     * @return Iface
     */
    public function setPassword($password)
    {
        $this->password = (string) $password;
        return $this;
    }

}