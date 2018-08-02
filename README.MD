# SOCKS2HTTP

## Getting Started

This application connects to a SOCKS5 proxy (like Tor) and returns a HTTP proxy that you can use to connect with:

* Internet Explorer
* Edge
* IOS devices
* ...

This application was initially made in Java, but after losing the source code, I made a more efficient C++ [jsocket](http://github.com/juanmv94/jsocket) version using pthreads.

You need to download [jsocket](http://github.com/juanmv94/jsocket) first and add the source files to the path.

## Windows
A Windows binary is included.

You can compile SOCKS2HTTP with the included .bat script.

You need MinGW with the pthread library.

    mingw-get install pthreads

## Linux
You can compile SOCKS2HTTP with the included .sh script.

## usage
**SOCKS2HTTP {listen port} {SOCKS5 host} {SOCKS5 port} ['local']**

*local* parameter is optional, and makes SOCKS2HTTP to only listen for localhost connections.

## Facts
* My Java version of SOCKS2HTTP was only about 160 lines of code, but it was still buggy, and unreleased.
* I used pthreads instead of C++11 thread support. This allows my application to be compiled for Windows (MinGW).

## Author
@Juanmv94

http://tragicomedy-hellin.blogspot.com