<?php
namespace Tk\Auth\Storage;

use Symfony\Component\HttpFoundation\Session\Session;

/**
 * @author Tropotek <http://www.tropotek.com/>
 */
class SessionStorage implements StorageInterface
{
    /**
     * Default session namespace
     */
    const SID_DEFAULT = '_auth.session';

    /**
     * Session namespace
     */
    protected string $sid = '';

    protected Session $session;


    /**
     * Sets session storage options and initializes session namespace object
     */
    public function __construct(Session $session, string $sid = self::SID_DEFAULT)
    {
        $this->session = $session;
        $this->sid = $sid;
    }

    /**
     * Returns the session namespace for this storage object
     */
    public function getSid(): string
    {
        return $this->sid;
    }

    /**
     * Get the session storage
     */
    public function getSession(): Session
    {
        return $this->session;
    }

    public function isEmpty(): bool
    {
        return !$this->getSession()->has($this->getSid());
    }

    public function read(): mixed
    {
        return $this->getSession()->get($this->getSid());
    }

    public function write(mixed $contents)
    {
        $this->getSession()->set($this->getSid(), $contents);
    }

    public function clear()
    {
        $this->getSession()->remove($this->getSid());
    }

}
