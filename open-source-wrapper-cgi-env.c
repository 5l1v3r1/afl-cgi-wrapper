/*
   american fuzzy lop - simple closed-source cgi elf binary fuzzing example
   ------------------------------------------------

   Written by Tobias Ospelt <floyd@floyd.ch> (I shouldn't write C code)
   using the template for argv fuzzing of Michal Zalewski <lcamtuf@google.com>
 
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This file shows a simple way to fuzz cgi elfs with stock afl-fuzz. 

   This will cause the program to read NUL-delimited input from stdin and
   put it in the appropriate environment vars, stdin (HTTP body) and argv[]. 
   Two subsequent NULs terminate the array. Empty params are encoded as a lone 0x02. 
   Lone 0x02 can't be generated...
   
   Common CGI environment variables:

   Key	Value
   DOCUMENT_ROOT	The root directory of your server
   HTTP_COOKIE	The visitor's cookie, if one is set
   HTTP_HOST	The hostname of the page being attempted
   HTTP_REFERER	The URL of the page that called your program
   HTTP_USER_AGENT	The browser type of the visitor
   HTTPS	"on" if the program is being called through a secure server
   PATH	The system path your server is running under
   QUERY_STRING	The query string (see GET, below)
   REMOTE_ADDR	The IP address of the visitor
   REMOTE_HOST	The hostname of the visitor (if your server has reverse-name-lookups on; otherwise this is the IP address again)
   REMOTE_PORT	The port the visitor is connected to on the web server
   REMOTE_USER	The visitor's username (for .htaccess-protected pages)
   REQUEST_METHOD	GET or POST
   REQUEST_URI	The interpreted pathname of the requested document or CGI (relative to the document root)
   SCRIPT_FILENAME	The full pathname of the current CGI
   SCRIPT_NAME	The interpreted pathname of the current CGI (relative to the document root)
   SERVER_ADMIN	The email address for your server's webmaster
   SERVER_NAME	Your server's fully qualified domain name (e.g. www.cgi101.com)
   SERVER_PORT	The port number your server is listening on
   SERVER_SOFTWARE	The server software you're using (e.g. Apache 1.3)
   CONTENT_LENGTH	Content length header value of HTTP POST requests
   
   There are a couple more http://alvinalexander.com/perl/edu/articles/pl020001.shtml depending on what the client sends:
   
   GATEWAY_INTERFACE = CGI/1.1*/
// HTTP_ACCEPT = */*
/* HTTP_ACCEPT_CHARSET = iso-8859-1,*,utf-8
   HTTP_ACCEPT_LANGUAGE = en
   HTTP_CONNECTION = Keep-Alive
   TZ = :US/Eastern
   
   Of course this means that in some cases different HTTP client/browser headers are set. Here's a list of most of them if
   you want to fuzz these too you can add them in the code (but you should check the disassembly of your cgi binary first
   if it actually looks for them): */
   
// Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
/* Accept-Charset: utf-8
   Accept-Encoding: gzip,deflate
   Accept-Language: en-US
   Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
   Cache-Control: no-cache
   Connection: close
   Cookie: Param=value; otherParam=value; gibberish
   Content-Length: 123
   Content-MD5: Q2hlY2sgSW50ZWdyaXR5IQ==
   Content-Type: application/x-www-form-urlencoded
   Date: Tue, 15 Nov 1994 08:12:31 GMT
   DNT: 1
   Expect: 200-ok
   From: user@example.com
   Front-End-Https: on
   Host: hostname.example.com
   If-Match: "737060cd8c284d8af7ad3082f209582d"
   If-Modified-Since: Sat, 29 Oct 1971 19:43:31 GMT
   If-None-Match: "737060cd8c284d8af7ad3082f209582d"
   If-Range: "737060cd8c284d8af7ad3082f209582d"
   Max-Forwards: 100
   Pragma: no-cache
   Range: bytes=1-999999,999999-1999999
   Referer: http://de.wikipedia.org/wiki/Liste_der_HTTP-Headerfelder
   TE: trailers, deflate
   Upgrade: HTTP/0.9
   User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)
   Via: 1.0 fred, 1.1 example.com (Apache/1.1)
   Warning: 199 Miscellaneous warning please parse this request
   X-Att-Deviceid: MakeModel/Firmware
   X-Do-Not-Track: 1
   X-Forwarded-For: client1, proxy1, proxy2
   X-Forwarded-Proto: https
   X-Requested-With: XMLHttpRequest
   X-Wap-Profile: http://wap.samsungmobile.com/uaprof/SGH-I777.xml
   
   Cold fusion seems to have some more: http://help.adobe.com/en_US/ColdFusion/9.0/CFMLRef/WSc3ff6d0ea77859461172e0811cbec22c24-7785.html
   We are not covering those, but it should be easy to adjust the code below if you ever need it.
   
*/

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define MAX_CMDLINE_LEN 100000
#define MAX_CMDLINE_PAR 1000

/*
OPTIONS:
*/
#define DEBUG
#define FIX_CONTENT_LENGTH
// sets both SCRIPT_FILENAME and SCRIPT_NAME:
#define FIX_SCRIPT_FILENAME
//Also see all the static environment variables below that are hard coded
/*
END OPTIONS
*/

int main(int argc, char **argv){
    
    //command line arguments that need to be filled with fuzzed input
    static char* argv_pass[MAX_CMDLINE_PAR];
    char* binary_path;
    if(argc < 2){
        #ifdef DEBUG
        printf("No binary specified to run. Exiting.\n");
        #endif
        exit(1);
    }
    binary_path = argv[1];
    argv_pass[0] = argv[1];
    char *p = strrchr(argv[0], '/');
    if(p)
        argv_pass[0] = ++p;
    #ifdef DEBUG
    printf("Using %s as binary path for child\n", binary_path);
    printf("Using %s as argv[0] of child\n", argv_pass[0]);
    #endif
    
    //things that are usually fixed in the server configuration, we hard code them:
    setenv("DOCUMENT_ROOT", "/var/www/", 1); //might be important if your cgi read/writes there
    setenv("REMOTE_ADDR", "93.184.216.34", 1); //example.com as a client
    setenv("REMOTE_HOST", "93.184.216.34", 1); //example.com as a client
    setenv("REMOTE_PORT", "65534", 1); //usually random client source port
    setenv("SERVER_ADMIN", "admin@example.com", 1);
    setenv("SERVER_NAME", "www.example.com", 1);
    setenv("SERVER_PORT", "443", 1);
    setenv("SERVER_SOFTWARE", "AFL Apache 0.99b", 1);
    setenv("HTTPS", "on", 1);
    //Not really sure if any cgi will really use these, but a couple of setenv don't cost too much:
    setenv("HTTP_ACCEPT", "*/*", 1);
    setenv("GATEWAY_INTERFACE", "CGI/1.1", 1);
    setenv("HTTP_ACCEPT_CHARSET", "iso-8859-1,*,utf-8", 1);
    setenv("HTTP_ACCEPT_LANGUAGE", "en", 1);
    setenv("HTTP_CONNECTION", "Close", 1);
    setenv("TZ", ":US/Eastern", 1);
    
    //HTTP client/browser supplied things
    //Attention: contrary to an actual webserver these values are neither
    //input validated or encode, nor will it do sanity checks...
    /*
    setenv("HTTP_COOKIE", "/opt/", 1); //HTTP Cookie header
    setenv("HTTP_HOST", "/opt/", 1); //HTTP Host header
    setenv("HTTP_REFERER", "/opt/", 1); //HTTP Referer header
    setenv("HTTP_USER_AGENT", "/opt/", 1); //HTTP User-Agent header
    setenv("PATH", "/opt/", 1); //HTTP URL PATH
    setenv("QUERY_STRING", "/opt/", 1);
    setenv("REMOTE_USER", "/opt/", 1);
    setenv("REQUEST_METHOD", "/opt/", 1); //Usually GET or POST
    setenv("REQUEST_URI", "/opt/", 1);
    setenv("SCRIPT_FILENAME", "/opt/", 1);
    setenv("SCRIPT_NAME", "/opt/", 1);
    */
    
    //environment variables that need to be filled with fuzzed input
    #if defined(FIX_CONTENT_LENGTH) && defined(FIX_SCRIPT_FILENAME)
    static char* env_vars[9] = { "HTTP_COOKIE", "HTTP_HOST", "HTTP_REFERER", "HTTP_USER_AGENT", 
                        "PATH", "QUERY_STRING", "REMOTE_USER", "REQUEST_METHOD", 
                        "REQUEST_URI" };
    #else
    static char* env_vars[12] = { "HTTP_COOKIE", "HTTP_HOST", "HTTP_REFERER", "HTTP_USER_AGENT", 
                        "PATH", "QUERY_STRING", "REMOTE_USER", "REQUEST_METHOD", 
                        "REQUEST_URI", "SCRIPT_FILENAME", "SCRIPT_NAME", "CONTENT_LENGTH" };
    #endif
    static int   num_env_vars = sizeof(env_vars) / sizeof(char*);
    
    //read in the entire buffer that includes all environment vars
    static char  in_buf[MAX_CMDLINE_LEN];
    if (read(0, in_buf, MAX_CMDLINE_LEN - 2) < 0)
        ;
    
    //Stdin is for HTTP body, so let's hack stdin to work like that
    int real_content_length = 0;
    int fds[2];
    pipe(fds);
    close(STDIN_FILENO);
    dup2(fds[0], STDIN_FILENO);

    //temp vars for processing the values in in_buf
    char* saved_ptr;
    char* ptr = in_buf;
    int   rc  = 0;
    
    while (*ptr) {
        saved_ptr = ptr;
        if (saved_ptr[0] == 0x02 && !saved_ptr[1]) 
            saved_ptr++;
        //First fill all environment variables,
        //then write to stdin for the child,
        //if we get even more input use it for argv
        if(rc < num_env_vars){
            #ifdef DEBUG
            printf("Setting %s as %s\n", env_vars[rc], saved_ptr);
            #endif
            setenv(env_vars[rc], saved_ptr, 1);
        }else if(rc == num_env_vars){
            #ifdef DEBUG
            printf("Setting HTTP body (stdin) to %s\n", saved_ptr);
            #endif
            real_content_length = write(fds[1], saved_ptr, strlen(saved_ptr));
        }else{
            #ifdef DEBUG
            printf("Setting argv_pass[%i] as %s\n", rc - num_env_vars, saved_ptr);
            #endif
            argv_pass[rc - num_env_vars] = saved_ptr;
        }
        rc++;
        while (*ptr)
            ptr++;
        ptr++;
    }
    
    //were all environment variables and stdin set?
    if(rc <= num_env_vars){
        //We want all env vars to be set properly, so set them to empty:
        while(rc < num_env_vars){
            setenv(env_vars[rc], "", 1);
            rc++;
        }
        #ifdef DEBUG
        printf("Maybe not all environment variables set?\n");
        printf("Closing argv_pass and setting stdin to empty string\n");
        #endif
        argv_pass[1] = 0x00;
        real_content_length = write(fds[1], "", 1);
    }else{
        #ifdef DEBUG
        printf("Closing argv_pass at %i\n", rc - num_env_vars);
        #endif
        argv_pass[rc - num_env_vars] = 0x00;
    }
    
    #ifdef FIX_CONTENT_LENGTH
        char cl[50];
        sprintf(cl, "%i", real_content_length);
        setenv("CONTENT_LENGTH", cl, 1);
        #ifdef DEBUG
        printf("Fixed CONTENT_LENGTH to %s\n", cl);
        #endif
    #endif
    
    #ifdef FIX_SCRIPT_FILENAME
        //TODO: Check how to set these properly, maybe using DOCUMENT_ROOT
        setenv("SCRIPT_FILENAME", binary_path, 1);
        setenv("SCRIPT_NAME", binary_path, 1);
    #endif
    
    #ifdef DEBUG
    printf("All set, ready to execv\n");
    #endif
    return execv(binary_path, argv_pass);
}
