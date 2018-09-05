<?php
/*
 * @author Michael Mifsud <info@tropotek.com>
 * @see http://www.tropotek.com/
 * @license Copyright 2007 Michael Mifsud
 */
namespace Tk\Auth\Adapter;

/**
 * Adapter Interface
 * 
 *
 */
abstract class Iface
{
    use \Tk\CollectionTrait;

    /**
     * @var \Tk\Event\AuthEvent
     */
    public $event = null;



    /**
     * NullAuth constructor.
     */
    public function __construct()
    {
        $this->event = new \Tk\Event\AuthEvent($this);

    }

    /**
     * Performs an authentication attempt
     *
     * @return \Tk\Auth\Result
     * @throws \Tk\Auth\Exception If authentication cannot be performed
     */
    public abstract function authenticate();


    /**
     * @return \Tk\Event\AuthEvent
     */
    protected function dispatchLoginProcess()
    {
        $config = $this->getConfig();
        if (!method_exists($config, 'getEventDispatcher')) return;
        /** @var \Tk\Event\Dispatcher $dispatcher */
        $dispatcher = $this->getConfig()->getEventDispatcher();
        if ($dispatcher) {
            $dispatcher->dispatch(\Tk\Auth\AuthEvents::LOGIN_PROCESS, $this->event);
        }
        return $this->event;
    }

    /**
     * @return \Tk\Event\AuthEvent
     */
    public function getLoginProcessEvent()
    {
        return $this->event;
    }

    /**
     * @return \Tk\Config
     */
    public function getConfig()
    {
        return \Tk\Config::getInstance();
    }

}