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
     * @var null|resource
     */
    protected $ldap = null;


    /**
     * Constructor
     *
     * @param string $host    ldap://centaur.unimelb.edu.au
     * @param string $baseDn  uid=%s,cn=users,dc=domain,dc=edu
     * @param int $port
     * @param bool $tls
     */
    public function __construct($host, $baseDn, $port = 636, $tls = false)
    {
        $this->setHost($host);
        $this->setBaseDn($baseDn);
        if ($port <= 0) $port = 636;
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

        if (!$username || !$password) {
            return new Result(Result::FAILURE_CREDENTIAL_INVALID, $username, '0000 Invalid username or password.');
        }
        try {
            $this->ldap = @ldap_connect($this->getHost(), $this->getPort());
            if ($this->isTls())
                @ldap_start_tls($this->getLdap());

            $this->setBaseDn(sprintf($this->getBaseDn(), $username));
            // legacy check (remove in future versions)
            $this->setBaseDn(str_replace('{username}', $username, $this->getBaseDn()));

            if (@ldap_bind($this->getLdap(), $this->getBaseDn(), $password)) {
                /** @var \Tk\Event\Dispatcher $dispatcher */
                $dispatcher = $this->getConfig()->getEventDispatcher();
                if ($dispatcher) {
                    $event = new \Tk\Event\AuthEvent($this);
                    $dispatcher->dispatch(\Tk\Auth\AuthEvents::LOGIN_PROCESS, $event);
                    if ($event->getResult()) {
                        return $event->getResult();
                    }
                }
                return new Result(Result::SUCCESS, $username);
            }
        } catch (\Exception $e) {
            \Tk\Log::warning($e->getMessage());
        }

        return new Result(Result::FAILURE_CREDENTIAL_INVALID, $username, '0001 Invalid username or password.');
    }

    /**
     * @param $baseDn
     * @param $filter
     * @return resource|false|null
     */
    public function ldapSearch($filter)
    {
        $ldapData = null;
        if ($this->ldap) {
            $sr = @ldap_search($this->getLdap(), $this->getBaseDn(), $filter);
            $ldapData = @ldap_get_entries($this->getLdap(), $sr);
        }
        return $ldapData;
    }


    /**
     * @return null|resource
     */
    public function getLdap()
    {
        return $this->ldap;
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