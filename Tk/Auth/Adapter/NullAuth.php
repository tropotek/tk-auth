<?php
namespace Tk\Auth\Adapter;

use Tk\Auth\Result;

/**
 * @author Michael Mifsud <info@tropotek.com>
 * @see http://www.tropotek.com/
 * @license Copyright 2016 Michael Mifsud
 */
class NullAuth extends Iface
{
    use \Tk\CollectionTrait;

    /**
     * NullAuth constructor.
     */
    public function __construct()
    {
        parent::__construct();
    }

    /**
     *
     * @return Result
     */
    public function authenticate()
    {
        $username = $this->get('username');
        if (!$username) {
            return new Result(Result::FAILURE_CREDENTIAL_INVALID, $username, 'Invalid username or password.');
        }
        try {
            /** @var \Tk\Event\Dispatcher $dispatcher */
            $dispatcher = $this->getConfig()->getEventDispatcher();
            if ($dispatcher) {
                $event = new \Tk\Event\AuthAdapterEvent($this);
                $dispatcher->dispatch(\Tk\Auth\AuthEvents::LOGIN_PROCESS, $event);
                if ($event->getResult()) {
                    return $event->getResult();
                }
            }
            return new Result(Result::SUCCESS, $username);
        } catch (\Exception $e) {
            \Tk\Log::warning($e->getMessage());
        }
        return new Result(Result::FAILURE_CREDENTIAL_INVALID, '', 'Invalid credentials.');
    }
 
}
