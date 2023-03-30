# uTor
A >very&lt; small Tor communication library (for windows) with support for HSV3.

This is a private project that took a very. very. long time.. I wanted to see if i could make a Tor hidden service v3 mini library.
Utilizing mostly LoL (living off the land) to mash the size down.

Also, yes the naming conventions are off. This project has gone through some names.

Keep in mind the following:

- This code is not made to be secure or even stable, it is a PoC that needs proof-reading.. that being said i did right tests for it in my CI, and I have used this code extensively in small projects.. that have run for weeks! I even made a Tor wardialer that would scrape various sources for onion links, try them and dump the html, it was 120kb! Pretty cool eh?

- This code unfortunately has had nearly all comments removed by a script i wrote for a jenkins pipeline.

- Yes it is written in C, the reason for this is that C++ is very bloated and not (in my opinion) suited for writing small efficient code to the extent that C is. Also writing it in C allows easier compilation for embedded systems that have no C++ compiler. I understand when OOC or functional code is necessary, in this case I have chosen to go for the functional approach.

Some interesting notes:

- Yes, it would be possible to make this cross-platform. The only issue is all the living off the land (ssl, bcrypt, ntdll) stuff that would need to ported.. in theory however it would be even smaller! Also considering that bsd sockets and etc exists on nearly every linux implementation.

- Yes, the code has functions that are huge, oddly enough, moving them into their own smaller functions results in less optimized code. Also for some parts of the code optimization is disabled! For instance, optimizing often results in ntdll calls failing or BCrypt calls failing. You can understand why by looking at the ASM that VS produces. I have not tried compiling with GCC.

I can explain more about how this works if you want to inquire at: mats.bosson@gmail.com
Or call me at: +46762248626
