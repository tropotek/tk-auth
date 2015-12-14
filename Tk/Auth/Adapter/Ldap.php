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
 * Config options:
 * 
 *   $config['system.auth.ldap.host']    = 'centaur.unimelb.edu.au';
 *   $config['system.auth.ldap.tls']    = true;
 *   $config['system.auth.ldap.port']   = 389;
 *   $config['system.auth.ldap.baseDn'] = 'ou=people,o=unimelb';
 *   $config['system.auth.ldap.filter'] = 'uid={username}';
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
     * @param string $username The DN username EG: 'CN=user1,DC=foo,DC=net'
     * @param string $password The password of the account being authenticated
     * @param array $config
     * @throws \Tk\Auth\Exception
     */
    public function __construct($username = null, $password = null, $config = array())
    {
        parent::__construct($username, $password);
        $p = 'system.auth.ldap.';
        $this->host = !empty($config[$p.'host']) ? $config[$p.'host'] : '';
        $this->port = !empty($config[$p.'port']) ? $config[$p.'port'] : '';
        $this->tls = !empty($config[$p.'tls']) ? $config[$p.'tls'] : '';
        $this->baseDn = !empty($config[$p.'baseDn']) ? $config[$p.'baseDn'] : '';
        $this->filter = !empty($config[$p.'filter']) ? $config[$p.'filter'] : '';
    }

    /**
     * Authenticate the user
     *
     * @throws \Tk\Auth\Exception
     * @return Result
     */
    public function authenticate()
    {
        if (!$this->getPassword()) {
            return new Result(Result::FAILURE_CREDENTIAL_INVALID, 'Invalid username or password.');
        }
        //$ldapFilter = sprintf('%s=%s', $this->getOption('system.auth.ldap.userattr'), $this->getUsername());
        $ldap = ldap_connect($this->host, $this->port);
        try {
            if ($this->tls)
                ldap_start_tls($ldap);
            
            $ufilter = str_replace('{username}', $this->getUsername(), $this->filter);
            $b = ldap_bind($ldap, $ufilter . ',' . $this->baseDn, $this->getPassword());
            
            if (!$b) throw new \Tk\Auth\Exception('1000: Failed to authenticate user');
        } catch (\Exception $e) {
            return new Result(Result::FAILURE_CREDENTIAL_INVALID, $this->getUsername(), $e->getMessage());
        }
        return new Result(Result::SUCCESS, $this->getUsername(), 'User Found!');
    }

}