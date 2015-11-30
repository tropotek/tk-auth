<?php
/*
 * @author Michael Mifsud <info@tropotek.com>
 * @link http://www.tropotek.com/
 * @license Copyright 2007 Michael Mifsud
 */
namespace Tk\Auth\Adapter;
use Tk\Auth\Result;

/**
 * LDAP Authentication adapter
 *
 *
 */
class Ldap extends Iface
{

    protected $uri = '';
    protected $port = 389;
    protected $baseDn = '';


    /**
     * Constructor
     *
     * @param string  $ldapUri  The LDAP URI
     * @param string  $username The DN username EG: 'CN=user1,DC=foo,DC=net'
     * @param string  $password The password of the account being authenticated
     */
    public function __construct($ldapUri, $username = null, $password = null)
    {
        parent::__construct($username, $password);
        $this->uri = $ldapUri;
    }

    /**
     * @return string
     */
    public function getUri()
    {
        return $this->uri;
    }

    /**
     * @param string $uri
     * @return $this
     */
    public function setUri($uri)
    {
        $this->uri = $uri;
        return $this;
    }

    /**
     * @return int
     */
    public function getPort()
    {
        return $this->port;
    }

    /**
     * @param int $port
     * @return $this
     */
    public function setPort($port)
    {
        $this->port = $port;
        return $this;
    }

    /**
     * @return string
     */
    public function getBaseDn()
    {
        return $this->baseDn;
    }

    /**
     * @param string $baseDn
     * @return $this
     */
    public function setBaseDn($baseDn)
    {
        $this->baseDn = $baseDn;
        return $this;
    }


    /**
     * Authenticate the user
     *
     * @throws \Tk\Auth\Adapter\Exception
     * @return \Tk\Auth\Result
     */
    public function authenticate()
    {
        if (!$this->getPassword()) {
            return new Result(Result::FAILURE_CREDENTIAL_INVALID, 'Invalid account details');
        }
        //$ldapFilter = sprintf('%s=%s', $this->getOption('system.auth.ldap.userattr'), $this->getUsername());
        $ldap = ldap_connect($this->uri, $this->port);
        try {
            ldap_start_tls($ldap);
            $b = ldap_bind($ldap, $this->getUsername() . ',' . $this->baseDn, $this->getPassword());
            if (!$b) throw new \Tk\Auth\Exception('1000: Failed to authenticate in LDAP');
        } catch (\Exception $e) {
            return new Result(Result::FAILURE_CREDENTIAL_INVALID, $this->getUsername(), $e->getMessage());
        }
        return new Result(Result::SUCCESS, $this->getUsername(), 'User Found!');
    }

}