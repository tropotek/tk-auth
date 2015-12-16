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
     * The hash function to use for this adapter
     * @var string
     */
    protected $hashFunction = 'md5';

    /**
     * @var \Tk\Db\Pdo
     */
    protected $db = null;


    /**
     * Constructor
     * 
     * @param \tk\Db\Pdo $db
     * @param string $tableName
     * @param string $userColumn
     * @param string $passColumn
     * @param string $saltColumn (optional)
     */
    public function __construct($db, $tableName, $userColumn, $passColumn, $saltColumn = '')
    {
        $this->db = $db;
        $this->tableName = $tableName;
        $this->usernameColumn = $userColumn;
        $this->passwordColumn = $passColumn;
        $this->saltColumn = $saltColumn;
        
    }

    /**
     * @return \Tk\Db\Pdo
     */
    public function getDb()
    {
        return $this->db;
    }

    /**
     * @return string
     */
    public function getHashFunction()
    {
        return $this->hashFunction;
    }

    /**
     * Name of selected hashing algorithm (e.g. "md5", "sha256", "haval160,4", etc..)
     *
     * To find out what algorithms are available:
     *
     * <code>
     * $data = "hello";
     * foreach (hash_algos() as $v) {
     *     $r = hash($v, $data, false);
     *     printf("%-12s %3d %s\n", $v, strlen($r), $r);
     * }
     * </code>
     *
     * @param string $hashFunction
     * @return Iface
     */
    public function setHashFunction($hashFunction)
    {
        $this->hashFunction = $hashFunction;
        return $this;
    }

    /**
     *
     * @return Result
     * @throws \Tk\Auth\Exception if answering the authentication query is impossible
     */
    public function authenticate()
    {
        if (!$this->getUsername() || !$this->getPassword()) {
            return new Result(Result::FAILURE_CREDENTIAL_INVALID, $this->getUsername(), 'Invalid username or password.');
        }
        try {
            $sql = sprintf('SELECT * FROM %s WHERE %s = %s LIMIT 1',
                $this->db->quoteParameter($this->tableName),
                $this->db->quoteParameter($this->usernameColumn),
                $this->db->quote($this->getUsername()));
            $stmt = $this->getDb()->prepare($sql);
            if (!$stmt->execute()) {
                throw new \Tk\Db\Exception('Dump: ' . print_r($this->db->getLastLog(), true));
            }
            
            $user = $stmt->fetchObject();
            if ($user) {
                $salt = '';
                if (!empty($user->{$this->saltColumn})) {
                    $salt = $user->{$this->saltColumn};
                }
                $passHash = \Tk\Auth::hash($this->getPassword().$salt, $this->getHashFunction());
                
                if ($passHash == $user->{$this->passwordColumn}) {
                    return new Result(Result::SUCCESS, $this->getUsername());
                }
            }
        } catch (\Exception $e) {
            throw new \Tk\Auth\Exception('The supplied parameters failed to produce a valid sql statement, please check table and column names for validity.', 0, $e);
        }
        return new Result(Result::FAILURE_IDENTITY_NOT_FOUND, $this->getUsername(), 'Invalid username or password.');
    }


}
