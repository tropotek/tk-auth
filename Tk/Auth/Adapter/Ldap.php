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
 *
 * This adapter requires that the data values have been set
 * ```
 * $adapter->replace(array('username' => $value, 'password' => $password));
 * ```
 * 
 * 
 */
class Ldap extends Iface
{

    protected $host = '';
    protected $port = 389;
    protected $tls = false;
    protected $baseDn = '';
    protected $filter = '';


    /**
     * Constructor
     *
     * @param string $host
     * @param string $baseDn
     * @param string $filter
     * @param int $port
     * @param bool $tls
     */
    public function __construct($host, $baseDn, $filter, $port = 389, $tls = false)
    {
        parent::__construct();
        $this->setHost($host);
        $this->setBaseDn($baseDn);
        $this->setFilter($filter);
        $this->setPort($port);
        $this->setTls($tls);
    }

    /**
     * @return string
     */
    public function getHost()
    {
        return $this->host;
    }

    /**
     * @param string $host
     * @return $this
     */
    public function setHost($host)
    {
        $this->host = $host;
        return $this;
    }

    /**
     * @return int|string
     */
    public function getPort()
    {
        return $this->port;
    }

    /**
     * @param int|string $port
     * @return $this
     */
    public function setPort($port)
    {
        $this->port = $port;
        return $this;
    }

    /**
     * @return bool|string
     */
    public function isTls()
    {
        return $this->tls;
    }

    /**
     * @param bool $tls
     * @return $this
     */
    public function setTls($tls)
    {
        $this->tls = $tls;
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
     * @return string
     */
    public function getFilter()
    {
        return $this->filter;
    }

    /**
     * @param string $filter
     * @return $this
     */
    public function setFilter($filter)
    {
        $this->filter = $filter;
        return $this;
    }
    
    /**
     * Authenticate the user
     *
     * @throws \Tk\Auth\Exception
     * @return Result
     */
    public function authenticate()
    {
        $username = $this->get('username');
        $password = $this->get('password');
        
        if (!$username || !$password) {
            return new Result(Result::FAILURE_CREDENTIAL_INVALID, $username, 'Invalid username or password.');
        }
        $ldap = @ldap_connect($this->getHost(), $this->getPort());
        $data = array();
        try {
            if ($this->isTls())
                @ldap_start_tls($ldap);
            
            $filter = str_replace('{username}', $username, $this->getFilter());
            $b = @ldap_bind($ldap, $filter . ',' . $this->getBaseDn(), $password);
            
            if ($b) {
                $sr = @ldap_search($ldap, $this->getBaseDn(), $filter);
                $data = @ldap_get_entries($ldap, $sr);
            } else {
                throw new \Tk\Auth\Exception('1000: Failed to authenticate user');
            }
        } catch (\Exception $e) {
            return new Result(Result::FAILURE_CREDENTIAL_INVALID, $username, $e->getMessage());
        }
        $r = new Result(Result::SUCCESS, $username, 'User Found!');
        $r->setParam('ldap', $data);
        return $r;
    }

}