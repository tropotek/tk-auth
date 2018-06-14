<?php
/*
 * @author Michael Mifsud <info@tropotek.com>
 * @see http://www.tropotek.com/
 * @license Copyright 2007 Michael Mifsud
 */
namespace Tk\Auth\Adapter;
use Tk\Auth\Result;

/**
 * LDAP Authentication adapter
 *
 * This adapter requires that the data values have been set
 *
 * ```
 * $adapter->replace(array('username' => $value, 'password' => $password));
 * ```
 *
 */
class Ldap extends Iface
{
    /**
     * @var string
     */
    protected $host = '';
    /**
     * @var int
     */
    protected $port = 636;
    /**
     * @var bool
     */
    protected $tls = false;
    /**
     * @var string
     */
    protected $baseDn = '';


    /**
     * Constructor
     *
     * @param string $host    ldap://centaur.unimelb.edu.au
     * @param string $baseDn  uid=%s,cn=users,dc=domain,dc=edu
     * @param int $port
     * @param bool $tls
     */
    public function __construct($host, $baseDn, $port = 636, $tls = false)    {
        parent::__construct();
        $this->setHost($host);
        $this->setBaseDn($baseDn);
        $this->setPort($port);
        $this->setTls($tls);
    }

    /**
     * Authenticate the user
     *
     * @return Result
     */
    public function authenticate()
    {
        $username = $this->get('username');
        $password = $this->get('password');
        $data = array();

        if (!$username || !$password) {
            return new Result(Result::FAILURE_CREDENTIAL_INVALID, $username, 'Invalid username or password.');
        }
        try {
            $ldap = @ldap_connect($this->getHost(), $this->getPort());
            if ($this->isTls())
                @ldap_start_tls($ldap);

            $baseDn = sprintf(str_replace('{username}', $username, $this->getBaseDn()), $username);
            $b = @ldap_bind($ldap, $baseDn, $password);

            // TODO: This should be removed from the LDAP authentication and added into the LDAP plugin code as a seperate search query somewhere
            if ($b) {
                // TODO: Check this if it errors then the user is not logged in
                $filter = substr($baseDn, 0, strpos($baseDn, ','));
                if ($filter) {
                    $sr = @ldap_search($ldap, $baseDn, $filter);
                    $data = @ldap_get_entries($ldap, $sr);
                }
            } else {
                throw new \Tk\Auth\Exception('1000: Failed to authenticate user');
            }

            $r = new Result(Result::SUCCESS, $username, 'User Found!');
            $r->set('ldap', $data);

            return $r;
        } catch (\Exception $e) {
            \Tk\Log::warning($e->getMessage());
        }

        return new Result(Result::FAILURE_CREDENTIAL_INVALID, $username, 'Invalid username or password.');
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

}