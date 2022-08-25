# uTor
A >very&lt; small Tor communication library with support for HSV3.

TO WHOM IT MAY CONCERN: NO LICENSE IS PROVIDED BESIDES THE ONES SPECIFIED IN SPECIFIC SOURCE FILES THAT REQUIRE ME TO REPRODUCE SAID LICENSE FOR THE SPECIFIC SOURCE FILE. ALL FILES ARE TO ASSUMED TO BE COPYRIGHTED TO THE FULLEST EXTENT OF SWEDISH LAW (IMPLIED COPYRIGHT IMPLIES) AND SHALL NOT BE COPIED, MODIFIED OR ACCESSED IN ANY WAY WITHOUT THE EXPRESS GIVEN PERMISSION OF MATS BOSSON (PNO: 001128-4***) RESIDENT OF SWEDEN.

This is a private project that took a very. very. long time.. I wanted to see if i could make a Tor hidden service v3 mini library.
Utilizing only LoL (living off the land) to mash the size down.

The reason I have posted this on github is for you (hopefully my future employer) to be able to see what I am capable of.

Keep in mind the following:

- This code is not made to be secure or even stable, it is a PoC that needs proof-reading.. that being said i did right tests for it in my CI, and I have used this code extensively in small projects.. that have run for weeks! I even made a Tor wardialer that would scrape various sources for onion links, try them and dump the html, it was 120kb! Pretty cool eh?

- This code unfortunately has had nearly all comments removed by a script i wrote for a jenkins pipeline.

- Yes it is written in C, the reason for this is that C++ is very bloated and not (in my opinion) suited for writing small efficient code to the extent that C is. Also writing it in C allows easier compilation for embedded systems that have no C++ compiler. I understand when OOC or functional code is necessary, in this case I have chosen to go for the functional approach.

- If you have any questions about this code you can always call me! +46762248626
