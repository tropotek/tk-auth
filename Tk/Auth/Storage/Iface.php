<?php
namespace Tk\Auth\Storage;

/**
 * 
 *
 * @author Michael Mifsud <info@tropotek.com>
 * @see http://www.tropotek.com/
 * @license Copyright 2015 Michael Mifsud
 */
interface Iface
{
    /**
     * Returns true if and only if storage is empty
     *
     * @return bool
     */
    public function isEmpty();

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
     * @param  mixed $contents
     */
    public function write($contents);

    /**
     * Clears contents from storage
     *
     */
    public function clear();
}