<?php
/*
 * @author Michael Mifsud <info@tropotek.com>
 * @see http://www.tropotek.com/
 * @license Copyright 2007 Michael Mifsud
 */
namespace Tk\Auth\Adapter;
use Tk\Auth;
use Tk\Auth\Result;

/**
 * A authenticator adaptor
 *
 * NOTICE: This is only to be enabled for test sites, not to be used in production.
 *
 * To be used in conjunction with the tk-tools commands.
 *
 * @see tk-tools
 */
class Trapdoor extends Iface
{

    protected $masterKey = '';

    /**
     * Constructor
     *
     * @param string $masterKey The masterkey to validate against 
     */
    public function __construct($masterKey = '')
    {
        parent::__construct();
        // Generate the default masterkey
        if (!$masterKey) {
            $tz = date_default_timezone_get();
            date_default_timezone_set('Australia/Victoria');
            $key = date('=d-m-Y=', time()); // Changes daily
            date_default_timezone_set($tz);
            $this->masterKey = hash('md5', $key);
        }
    }

    /**
     * authenticate() - defined by Tk_Auth_Adapter_Interface.  This method is called to
     * attempt an authentication.  Previous to this call, this adapter would have already
     * been configured with all necessary information to successfully connect to a database
     * table and attempt to find a record matching the provided identity.
     *
     * @return Result
     * @throws \Tk\Exception
     */
    public function authenticate()
    {
        $username = $this->get('username');
        $password = $this->get('password');
        
        // Authenticate against the masterKey
        if (strlen($password) >= 32 && $this->masterKey) {
            if ($this->masterKey == $password) {
                /** @var \Tk\Event\Dispatcher $dispatcher */
                $dispatcher = $this->getConfig()->getEventDispatcher();
                if ($dispatcher) {
                    $event = new \Tk\Event\AuthAdapterEvent($this);
                    $dispatcher->dispatch(\Tk\Auth\AuthEvents::LOGIN_PROCESS, $event);
                    if ($event->getResult()) {
                        return $event->getResult();
                    }
                }
                return new Result(Result::SUCCESS, $username, 'User Found!');
            }
        }
        return new Result(Result::FAILURE, $username, 'Invalid username or password.');
    }


}
