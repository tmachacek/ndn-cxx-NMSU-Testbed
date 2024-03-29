ndnsec-export
=============

Usage
-----

::

    ndnsec-export [-h] [-o output] identity

Description
-----------

``ndnsec-export`` exports the default certificate of an identity and its private key as a file. It
will ask for a passphrase to encrypt the private key. The output file can be imported again with
``ndnsec-import`` command.

Options
-------

``-h``
  Print a help message.

``-o output``
  Write to an output file instead of the standard output.

``-P passphrase``
  Passphrase to use for the export. If not specified (or specified an empty passphrase), the
  user is interactively asked to input the passphrase on the terminal. Note that specifying
  passphrase via -P is insecure, as it can potentially end up in shell history, be visible in
  ps output, etc.

``identity``
  The identity name.

Examples
--------

Export an identity's default certificate and private key into a file:

::

    $ ndnsec-export -o alice.ndnkey /ndn/test/alice

Export an identity's default certificate and private key to the standard output:

::

    $ ndnsec-export /ndn/test/alice
