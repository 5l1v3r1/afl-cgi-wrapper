#include <stdio.h>
#include <stdlib.h>
#define MAXLEN 100

int main(void){
    printf("Hello, I'm the simple_print_env.c cgi binary!\n");
    static char* env_vars[12] = { "HTTP_COOKIE", "HTTP_HOST", "HTTP_REFERER", "HTTP_USER_AGENT", 
                        "PATH", "QUERY_STRING", "REMOTE_USER", "REQUEST_METHOD", 
                        "REQUEST_URI", "SCRIPT_FILENAME", "SCRIPT_NAME", "CONTENT_LENGTH" };
    static int   num_env_vars = sizeof(env_vars) / sizeof(char*);
    int i=0;
    while(i < num_env_vars){
         printf("%s: %s\n", env_vars[i], getenv(env_vars[i]));
         i++;
    }
    int stdin_len = 0;
    char* content_length = getenv("CONTENT_LENGTH");
    if(content_length){
        sscanf(content_length, "%i", &stdin_len);
        if(MAXLEN < stdin_len)
            stdin_len = MAXLEN;
        char in_buf[stdin_len];
        if (read(0, in_buf, stdin_len) < 0)
            ;
        printf("STDIN aka HTTP body: %s\n", in_buf);
    }else{
        printf("Nothing in STDIN\n");
    }
}