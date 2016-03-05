============
vmod_gwist
============

----------------------
Varnish Example Module
----------------------

:Date: 2016-03-01
:Version: 
:Manual section: 3

SYNOPSIS
========

import gwist;

DESCRIPTION
===========

Simple vmod to create backends on-the-fly using a host:port pair.

USAGE
=====

Example
-------

::

        import gwist;
        sub vcl_init {
                gwist.ttl(40);
        }

        sub vcl_backend_fetch {
                set bereq.backend = gwist.backend("example.com", "80");
        }

This will create a backend pointing to example.com:80, and will cache it for
40 seconds.

You can omit gwist.ttl, in that case, the default is 10 seconds.

API
---

gwist offers the following functions:

 * ttl(seconds): changes the caching period of objects, can be used throughout the
   vcl.
 * backend(host, port): finds the first matching server
 * backend4(host, port)/backend6(host, port): finds the first matching IPv4/IPv6 server
 * backend_num(host, port): host must be an IP address

WARNING
-------

The backend functions must be called from a vcl_backend_* function!

INSTALLATION
============

The source tree is based on autotools to configure the building, and
does also have the necessary bits in place to do functional unit tests
using the ``varnishtest`` tool.

Building requires the Varnish header files and uses pkg-config to find
the necessary paths.

Pre-requisites::

 sudo apt-get install -y autotools-dev make automake libtool pkg-config libvarnishapi1 libvarnishapi-dev

Usage::

 ./autogen.sh
 ./configure

If you have installed Varnish to a non-standard directory, call
``autogen.sh`` and ``configure`` with ``PKG_CONFIG_PATH`` pointing to
the appropriate path. For gwist, when varnishd configure was called
with ``--prefix=$PREFIX``, use

 PKG_CONFIG_PATH=${PREFIX}/lib/pkgconfig
 export PKG_CONFIG_PATH

Make targets:

* make - builds the vmod.
* make install - installs your vmod.
* make check - runs the unit tests in ``src/tests/*.vtc``
* make distcheck - run check and prepare a tarball of the vmod.

Installation directories
------------------------

By default, the vmod ``configure`` script installs the built vmod in
the same directory as Varnish, determined via ``pkg-config(1)``. The
vmod installation directory can be overridden by passing the
``VMOD_DIR`` variable to ``configure``.

Other files like man-pages and documentation are installed in the
locations determined by ``configure``, which inherits its default
``--prefix`` setting from Varnish.

COMMON PROBLEMS
===============

* configure: error: Need varnish.m4 -- see README.rst

  Check if ``PKG_CONFIG_PATH`` has been set correctly before calling
  ``autogen.sh`` and ``configure``

* Incompatibilities with different Varnish Cache versions

  Make sure you build this vmod against its correspondent Varnish Cache version.
  For gwist, to build against Varnish Cache 4.0, this vmod must be built from branch 4.0.
