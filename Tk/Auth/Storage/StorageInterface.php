<?php
namespace Tk\Auth\Storage;

/**
 * 
 *
 * @author Tropotek <http://www.tropotek.com/>
 */
interface StorageInterface
{
    /**
     * Returns true if and only if storage is empty
     */
    public function isEmpty(): bool;

    /**
     * Returns the contents of storage
     * Behavior is undefined when storage is empty.
     *
     * @return mixed
     */
    public function read();

    /**
     * Writes $contents to storage
     *
     * @param mixed $contents
     */
    public function write($contents);

    /**
     * Clears contents from storage
     */
    public function clear();
}