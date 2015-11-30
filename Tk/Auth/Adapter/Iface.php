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
     * The hash function to use for this adapter
     * @var string
     */
    protected $hashFunction = 'md5';



    /**
     * Constructor
     *
     * @param  string $username The username of the account being authenticated
     * @param  string $password The password of the account being authenticated
     */
    public function __construct($username = null, $password = null)
    {
        if ($username !== null) {
            $this->setUsername($username);
        }
        if ($password !== null) {
            $this->setPassword($password);
        }
    }


    /**
     * Performs an authentication attempt
     *
     * @return \Tk\Auth\Result
     * @throws \Tk\Auth\Exception If authentication cannot be performed
     */
    abstract public function authenticate();


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

    /**
     * @return string
     */
    public function getHashFunction()
    {
        return $this->hashFunction;
    }

    /**
     * Name of selected hashing algorithm (e.g. "md5", "sha256", "haval160,4", etc..)
     *
     * To find out what algorithms are available:
     *
     * <code>
     * $data = "hello";
     * foreach (hash_algos() as $v) {
     *     $r = hash($v, $data, false);
     *     printf("%-12s %3d %s\n", $v, strlen($r), $r);
     * }
     * </code>
     *
     * @param string $hashFunction
     * @return Iface
     */
    public function setHashFunction($hashFunction)
    {
        $this->hashFunction = $hashFunction;
        return $this;
    }

}