/*
   american fuzzy lop - simple closed-source cgi elf binary fuzzing example
   ------------------------------------------------

   Written by Tobias Ospelt <floyd@floyd.ch>
   using the template for argv fuzzing of Michal Zalewski <lcamtuf@google.com>
 
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This file shows a simple way to fuzz (closed-source) cgi elfs with stock
   afl-fuzz. 

   This will cause the program to read NUL-delimited input from stdin and
   put it in the appropriate environment vars and argv[]. Two subsequent 
   NULs terminate the array. Empty params are encoded as a lone 0x02. 
   Lone 0x02 can't be generated...
   
   YOU WILL NEED TO REPLACE <YOUR CGI BINARY> (with the appropriate binary to fuzz)

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
*/

#include <unistd.h>
#include <stdlib.h>

#define MAX_CMDLINE_LEN 100000
#define MAX_CMDLINE_PAR 1000

int main(int argc, char **argv){
    //things that are usually fixed in the server configuration
    setenv("DOCUMENT_ROOT", "/var/www/", 1); //might be important if you cgi read/writes there
    setenv("REMOTE_ADDR", "93.184.216.34", 1); //example.com as a client
    setenv("REMOTE_HOST", "93.184.216.34", 1); //example.com as a client
    setenv("REMOTE_PORT", "65534", 1); //usually random client source port
    setenv("SERVER_ADMIN", "admin@example.com", 1);
    setenv("SERVER_NAME", "www.example.com", 1);
    setenv("SERVER_PORT", "443", 1);
    setenv("SERVER_SOFTWARE", "AFL Apache 0.99b", 1);
    setenv("HTTPS", "on", 1);
        
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
    static char* env_vars[12] = { "HTTP_COOKIE", "HTTP_HOST", "HTTP_REFERER", "HTTP_USER_AGENT", 
                        "PATH", "QUERY_STRING", "REMOTE_USER", "REQUEST_METHOD", 
                        "REQUEST_URI", "SCRIPT_FILENAME", "SCRIPT_NAME", "CONTENT_LENGTH" };
    static int   num_env_vars = sizeof(env_vars);
    
    //command line arguments that need to be filled with fuzzed input
    static char* argv_pass[MAX_CMDLINE_PAR];
    argv_pass[0] = "<YOUR CGI BINARY>";
    
    //read in the entire buffer that includes all environment vars
    static char  in_buf[MAX_CMDLINE_LEN];
    if (read(0, in_buf, MAX_CMDLINE_LEN - 2) < 0)
        ;

    //temp vars for processing the values in in_buf
    char* saved_ptr;
    char* ptr = in_buf;
    int   rc  = 0;
    
    while (*ptr) {
        saved_ptr = ptr;
        if (saved_ptr[0] == 0x02 && !saved_ptr[1]) 
            saved_ptr++;
        //First fill all environment variables, 
        //if we get more input use it for argv
        if(rc < num_env_vars)
            setenv(env_vars[rc], saved_ptr, 1);
        else
            argv_pass[rc - num_env_vars + 1] = saved_ptr;
        rc++;
        while (*ptr) 
            ptr++;
        ptr++;
    }
    //were all environment variables set?
    if(rc < num_env_vars)
        exit(1);
    else{
        argv_pass[rc - num_env_vars + 1] = 0x00;
        return execv("/opt/<YOUR CGI BINARY>", argv_pass);
    }
}
