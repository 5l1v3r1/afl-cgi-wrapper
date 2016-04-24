A simple wrapper for the American Fuzzy Lop fuzzer when you want to fuzz CGI binaries that usually run on a web server.

It's important that AFL detects paths inside the binary, for that instrumentation (of the CGI binary) is necessary. There are several options:
1. You recompile the CGI with afl-gcc or afl-clang or whatever. By far the best option if you can.
2. You instrument the CGI with dyninst (see afl-users mailing list for infos about dyninst with AFL, I used that before successfully, but for my last cgi it didn't work)
3. You use QEMU mode (-Q of AFL)

So for option 1 or if you manage to do option 2 you can use the files "open-source*" in this projects. You won't need AFL's -Q option.

If you are stuck with option 3: The "closed-source*" scripts currently *DO NOT* work. There are issues passing environment variables to QEMU. I'll need to invest more time.
