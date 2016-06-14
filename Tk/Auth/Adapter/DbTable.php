<?php
/*
 * @author Michael Mifsud <info@tropotek.com>
 * @link http://www.tropotek.com/
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
    protected $saltColumn = '';

    /**
     * @var string
     */
    protected $activeColumn = '';

    /**
     * @var \Tk\Db\Pdo
     */
    protected $db = null;


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
        parent::__construct();
        $this->db = $db;
        $this->tableName = $tableName;
        $this->usernameColumn = $userColumn;
        $this->passwordColumn = $passColumn;
        //$this->saltColumn = $saltColumn;
        $this->activeColumn = $activeColumn;
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
            $active = '';
            if ($this->activeColumn) {
                $active = 'AND '.$this->db->quoteParameter($this->activeColumn).' = TRUE';
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
                $e = new \Tk\Db\Exception($errorInfo[2]);
                $e->setDump('Dump: ' . print_r($this->db->getLastLog(), true));
            }
            
            $user = $stmt->fetchObject();
            // TODO: The password should be modified before it is sent to the adapter for processing
            if ($user && $password == $user->{$this->passwordColumn}) {
                return new Result(Result::SUCCESS, $username);
            }
//            if ($user) {
//                $salt = '';
//                if ($this->saltColumn && !empty($user->{$this->saltColumn})) {
//                    $salt = $user->{$this->saltColumn};
//                }
//                $passHash = $this->hash($password.$salt);
//                if ($passHash == $user->{$this->passwordColumn}) {
//                    return new Result(Result::SUCCESS, $username);
//                }
//            }
        } catch (\Exception $e) {
            throw new \Tk\Auth\Exception('The supplied parameters failed to produce a valid sql statement, please check table and column names for validity.', 0, $e);
        }
        return new Result(Result::FAILURE_IDENTITY_NOT_FOUND, $username, 'Invalid username or password.');
    }


}
