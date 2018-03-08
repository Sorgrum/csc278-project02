# CSC 278 Project 02
## Marcelo Gheiler & Vasim Patel

### Analysis of Traffic File

* Does using HTTPS obscure the URL being requested?  If so, why?

  * HTTPS does obscure the URL being requested. The data segment of the packet contains the HTTP request, but is also encrypted.

* Does using HTTPS prevent hackers from knowing which web site a user
is browsing?  Why or why not?
 
  * HTTPS does not prevent hackers from knowing which site a user is visiting beause the IP header contains the source and destination IP addresses and is not encrypted. So a couple of l33t h4x0rz can use the IP address to infer the web site the visitor is using.

-------------------------------

License for libpcap Soure Code:
-------------------------------
License: BSD

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.

THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
