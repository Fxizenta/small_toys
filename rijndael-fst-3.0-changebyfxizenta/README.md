## Usage:

```bash
make
./rijndael-test-fst -t <E/D> -k <KEY_HEX> -m <ECB/CBC>
```

eg:

![](https://myimage-1303975616.cos.ap-guangzhou.myqcloud.com/img/202120220106211339.png)



## Follow are api readme

Optimised ANSI C code for the Rijndael cipher (now AES)

Authors:
    Vincent Rijmen <vincent.rijmen@esat.kuleuven.ac.be>
    Antoon Bosselaers <antoon.bosselaers@esat.kuleuven.ac.be>
    Paulo Barreto <paulo.barreto@terra.com.br>

All code contained in this distributed is placed in the public domain.

========================================================================

Disclaimer:

THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS 
OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE 
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR 
BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE 
OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, 
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. 

========================================================================

Acknowledgements:

We are deeply indebted to the following people for their bug reports,
fixes, and improvement suggestions to the API implementation. Though we
tried to list all contributions, we apologise in advance for any
missing reference:

Andrew Bales <Andrew.Bales@Honeywell.com>
Markus Friedl <markus.friedl@informatik.uni-erlangen.de>
John Skodon <skodonj@webquill.com>

========================================================================

Description:

This optimised implementation of Rijndael is noticeably faster than the
previous versions on Intel processors under Win32 w/ MSVC 6.0.  On the
same processor under Linux w/ gcc-2.95.2, the key setup is also
considerably faster, but normal encryption/decryption is only marginally
faster.

To enable full loop unrolling for encryption/decryption, define the
conditional compilation directive FULL_UNROLL.  This may help increase
performance or not, depending on the platform.

To compute the intermediate value tests, define the conditional
compilation directive INTERMEDIATE_VALUE_KAT.  It may be worthwhile to
define the TRACE_KAT_MCT directive too, which provides useful progress
information during the generation of the KAT and MCT sets.

========================================================================

Contents:

README                  This file
rijndael-alg-fst.c      The algorithm implementation.
rijndael-alg-fst.h      The corresponding header file.
rijndael-api-fst.c      NIST's implementation.
rijndael-api-fst.h      The corresponding header file.
rijndael-test-fst.c     A simple program to generate test vectors.
table.128               Data for the table tests and 128-bit keys.
table.192               Data for the table tests and 192-bit keys.
table.256               Data for the table tests and 256-bit keys.
fips-test-vectors.txt   Key schedule and ciphertext intermediate values
                        (reduced set proposed for FIPS inclusion).
Makefile                A sample makefile; may need some changes,
                        depending on the C compiler used.

N.B. Both the API implementation and the provisional reduced set of
test vectors are likely to change, according to NIST's final decision
regarding modes of operation and the FIPS contents. They are therefore
marked as "version 2.9" rather than "version 3.0".

