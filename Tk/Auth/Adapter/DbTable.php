<?php
/*
 * @author Michael Mifsud <info@tropotek.com>
 * @see http://www.tropotek.com/
 * @license Copyright 2007 Michael Mifsud
 */
namespace Tk\Auth\Adapter;
use Tk\Auth\Result;

/**
 * A DB table authenticator adaptor
 *
 * This adapter requires that the data values have been set
 * ```
 * $adapter->replace(array('username' => $value, 'password' => $password));
 * ```
 *
 */
class DbTable extends Iface
{

    /**
     * @var string
     */
    protected $tableName = '';

    /**
     * @var string
     */
    protected $usernameColumn = '';

    /**
     * @var string
     */
    protected $passwordColumn = '';

    /**
     * @var string
     */
    protected $activeColumn = '';

    /**
     * @var \Tk\Db\Pdo
     */
    protected $db = null;

    /**
     * @var callable
     */
    protected $hashCallback = null;


    /**
     * Constructor
     * 
     * @param \Tk\Db\Pdo $db
     * @param string $tableName
     * @param string $userColumn
     * @param string $passColumn
     * @param string $activeColumn
     */
    public function __construct(\Tk\Db\Pdo $db, $tableName, $userColumn, $passColumn, $activeColumn = '')
    {
        $this->db = $db;
        $this->tableName = $tableName;
        $this->usernameColumn = $userColumn;
        $this->passwordColumn = $passColumn;
        $this->activeColumn = $activeColumn;
    }

    /**
     * If a hash function is set then that is used to has a password.
     * The password and the user stdClass is sent to the function for hashing.
     *
     * @param $callable
     * @return $this
     */
    public function setHashCallback($callable) 
    {
        $this->hashCallback = $callable;
        return $this;
    }

    /**
     * Override this method for more secure password encoding
     *
     * @param $password
     * @param \stdClass $user
     * @return string
     */
    public function hashPassword($password, $user = null)
    {
        if ($this->hashCallback) {
            return call_user_func_array($this->hashCallback, array($password, $user));
        }
        return hash('md5', $password);
    }

    /**
     * @param $username
     * @return \stdClass
     */
    protected function getUser($username)
    {
        $active = '';
        if ($this->activeColumn) {
            $active = 'AND '.$this->db->quoteParameter($this->activeColumn).' = 1';
        }
        $sql = sprintf('SELECT * FROM %s WHERE %s = %s %s LIMIT 1',
            $this->db->quoteParameter($this->tableName),
            $this->db->quoteParameter($this->usernameColumn),
            $this->db->quote($username),
            $active
        );

        $stmt = $this->db->prepare($sql);
        if (!$stmt->execute()) {
            $errorInfo = $this->db->errorInfo();
            $e = new \Tk\Db\Exception($errorInfo[2], 1000, null, print_r($this->db->getLastLog(), true));
        }

        return $stmt->fetchObject();
    }

    /**
     *
     * @return Result
     * @throws \Tk\Auth\Exception if answering the authentication query is impossible
     */
    public function authenticate()
    {
        $username = $this->get('username');
        $password = $this->get('password');
        
        if (!$username || !$password) {
            return new Result(Result::FAILURE_CREDENTIAL_INVALID, $username, 'No username or password.');
        }

        try {
            $user = $this->getUser($username);
            // TODO: The password should be modified/hashed before it is sent to the adapter for processing ???
            if ($user && $this->hashPassword($password, $user) == $user->{$this->passwordColumn}) {
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
            }
        } catch (\Exception $e) {
            \Tk\Log::warning($e->__toString());
        }
        return new Result(Result::FAILURE_IDENTITY_NOT_FOUND, $username, 'Invalid username or password.');
    }


}
