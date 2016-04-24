/*
   american fuzzy lop - high-performance binary-only instrumentation
   -----------------------------------------------------------------

   Written by Andrew Griffiths <agriffiths@google.com> and
              Michal Zalewski <lcamtuf@google.com>
   Patches for CGI binary fuzzing by Tobias Ospelt <floyd@floyd.ch>

   Idea & design very much by Andrew Griffiths.

   Copyright 2015, 2016 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This code is a shim patched into the separately-distributed source
   code of QEMU 2.2.0. It leverages the built-in QEMU tracing functionality
   to implement AFL-style instrumentation and to take care of the remaining
   parts of the AFL fork server logic.

   The resulting QEMU binary is essentially a standalone instrumentation
   tool; for an example of how to leverage it for other purposes, you can
   have a look at afl-showmap.c.

 */

#include <sys/shm.h>
#include "../../config.h"


/***************************
 * CGI fuzzer mods by Tobias Ospelt <floyd@floyd.ch> *
 ***************************/

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
//Also see all the static environment variables below that are hard coded
/*
END OPTIONS
*/

/***************************
 * VARIOUS AUXILIARY STUFF *
 ***************************/

/* A snippet patched into tb_find_slow to inform the parent process that
   we have hit a new block that hasn't been translated yet, and to tell
   it to translate within its own context, too (this avoids translation
   overhead in the next forked-off copy). */

#define AFL_QEMU_CPU_SNIPPET1 do { \
    afl_request_tsl(pc, cs_base, flags); \
  } while (0)

/* This snippet kicks in when the instruction pointer is positioned at
   _start and does the usual forkserver stuff, not very different from
   regular instrumentation injected via afl-as.h. */

#define AFL_QEMU_CPU_SNIPPET2 do { \
    if(tb->pc == afl_entry_point) { \
      afl_setup(); \
      afl_forkserver(env); \
    } \
    afl_maybe_log(tb->pc); \
  } while (0)

/* We use one additional file descriptor to relay "needs translation"
   messages between the child and the fork server. */

#define TSL_FD (FORKSRV_FD - 1)

/* This is equivalent to afl-as.h: */

static unsigned char *afl_area_ptr;

/* Exported variables populated by the code patched into elfload.c: */

abi_ulong afl_entry_point, /* ELF entry point (_start) */
          afl_start_code,  /* .text start pointer      */
          afl_end_code;    /* .text end pointer        */

/* Set in the child process in forkserver mode: */

static unsigned char afl_fork_child;
unsigned int afl_forksrv_pid;

/* Instrumentation ratio: */

static unsigned int afl_inst_rms = MAP_SIZE;

/* Function declarations. */

static void afl_setup(void);
static void afl_forkserver(CPUArchState*);
static inline void afl_maybe_log(abi_ulong);

static void afl_wait_tsl(CPUArchState*, int);
static void afl_request_tsl(target_ulong, target_ulong, uint64_t);

static TranslationBlock *tb_find_slow(CPUArchState*, target_ulong,
                                      target_ulong, uint64_t);


/* Data structure passed around by the translate handlers: */

struct afl_tsl {
  target_ulong pc;
  target_ulong cs_base;
  uint64_t flags;
};


/*************************
 * ACTUAL IMPLEMENTATION *
 *************************/


/* Set up SHM region and initialize other stuff. */

static void afl_setup(void) {

  char *id_str = getenv(SHM_ENV_VAR),
       *inst_r = getenv("AFL_INST_RATIO");

  int shm_id;

  if (inst_r) {

    unsigned int r;

    r = atoi(inst_r);

    if (r > 100) r = 100;
    if (!r) r = 1;

    afl_inst_rms = MAP_SIZE * r / 100;

  }

  if (id_str) {

    shm_id = atoi(id_str);
    afl_area_ptr = shmat(shm_id, NULL, 0);

    if (afl_area_ptr == (void*)-1) exit(1);

    /* With AFL_INST_RATIO set to a low value, we want to touch the bitmap
       so that the parent doesn't give up on us. */

    if (inst_r) afl_area_ptr[0] = 1;


  }

  if (getenv("AFL_INST_LIBS")) {

    afl_start_code = 0;
    afl_end_code   = (abi_ulong)-1;

  }

}


/* Fork server logic, invoked once we hit _start. */

static void afl_forkserver(CPUArchState *env) {

  static unsigned char tmp[4];

  if (!afl_area_ptr) return;

  /* Tell the parent that we're alive. If the parent doesn't want
     to talk, assume that we're not running in forkserver mode. */

  if (write(FORKSRV_FD + 1, tmp, 4) != 4) return;

  afl_forksrv_pid = getpid();

  /* All right, let's await orders... */

  while (1) {

    pid_t child_pid;
    int status, t_fd[2];

    /* Whoops, parent dead? */

    if (read(FORKSRV_FD, tmp, 4) != 4) exit(2);

    /* Establish a channel with child to grab translation commands. We'll 
       read from t_fd[0], child will write to TSL_FD. */

    if (pipe(t_fd) || dup2(t_fd[1], TSL_FD) < 0) exit(3);
    close(t_fd[1]);

    child_pid = fork();
    if (child_pid < 0) exit(4);

    if (!child_pid) {

      /* Child process. Close descriptors and run free. */

      afl_fork_child = 1;
      close(FORKSRV_FD);
      close(FORKSRV_FD + 1);
      close(t_fd[0]);
      
      /* START added code by Tobias Ospelt <floyd@floyd.ch> for CGI fuzzing*/
      //We're already in the forked child now
      //Therefore we can simply set environment vars and read from stdin etc.
      
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
      #if defined(FIX_CONTENT_LENGTH)
      static char* env_vars[11] = { "HTTP_COOKIE", "HTTP_HOST", "HTTP_REFERER", "HTTP_USER_AGENT", 
                          "PATH", "QUERY_STRING", "REMOTE_USER", "REQUEST_METHOD", 
                          "REQUEST_URI", "SCRIPT_FILENAME", "SCRIPT_NAME" };
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
      int real_content_length = -1;
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
          //then write to stdin for the child
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
          }
          rc++;
          while (*ptr)
              ptr++;
          ptr++;
      }
      if(rc <= num_env_vars){
          #ifdef DEBUG
          printf("STDIN for child was never set. Setting to empty string.\n");
          #endif
          real_content_length = write(fds[1], "", 1);
      }
      #ifdef FIX_CONTENT_LENGTH
          char cl[50];
          sprintf(cl, "%i", real_content_length);
          setenv("CONTENT_LENGTH", cl, 1);
          #ifdef DEBUG
          printf("Fixed CONTENT_LENGTH to %s\n", cl);
          #endif
      #endif

      //were all environment variables and stdin set? Otherwise set them
      while(rc < num_env_vars){
          setenv(env_vars[rc], "", 1);
          rc++;
      }
      #ifdef DEBUG
      printf("All set, ready to run free\n");
      #endif
      /* END added code by Tobias Ospelt <floyd@floyd.ch> for CGI fuzzing*/
      
      return;

    }

    /* Parent. */

    close(TSL_FD);

    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) exit(5);

    /* Collect translation requests until child dies and closes the pipe. */

    afl_wait_tsl(env, t_fd[0]);

    /* Get and relay exit status to parent. */

    if (waitpid(child_pid, &status, 0) < 0) exit(6);
    if (write(FORKSRV_FD + 1, &status, 4) != 4) exit(7);

  }

}


/* The equivalent of the tuple logging routine from afl-as.h. */

static inline void afl_maybe_log(abi_ulong cur_loc) {

  static __thread abi_ulong prev_loc;

  /* Optimize for cur_loc > afl_end_code, which is the most likely case on
     Linux systems. */

  if (cur_loc > afl_end_code || cur_loc < afl_start_code || !afl_area_ptr)
    return;

  /* Looks like QEMU always maps to fixed locations, so ASAN is not a
     concern. Phew. But instruction addresses may be aligned. Let's mangle
     the value to get something quasi-uniform. */

  cur_loc  = (cur_loc >> 4) ^ (cur_loc << 8);
  cur_loc &= MAP_SIZE - 1;

  /* Implement probabilistic instrumentation by looking at scrambled block
     address. This keeps the instrumented locations stable across runs. */

  if (cur_loc >= afl_inst_rms) return;

  afl_area_ptr[cur_loc ^ prev_loc]++;
  prev_loc = cur_loc >> 1;

}


/* This code is invoked whenever QEMU decides that it doesn't have a
   translation of a particular block and needs to compute it. When this happens,
   we tell the parent to mirror the operation, so that the next fork() has a
   cached copy. */

static void afl_request_tsl(target_ulong pc, target_ulong cb, uint64_t flags) {

  struct afl_tsl t;

  if (!afl_fork_child) return;

  t.pc      = pc;
  t.cs_base = cb;
  t.flags   = flags;

  if (write(TSL_FD, &t, sizeof(struct afl_tsl)) != sizeof(struct afl_tsl))
    return;

}


/* This is the other side of the same channel. Since timeouts are handled by
   afl-fuzz simply killing the child, we can just wait until the pipe breaks. */

static void afl_wait_tsl(CPUArchState *env, int fd) {

  struct afl_tsl t;

  while (1) {

    /* Broken pipe means it's time to return to the fork server routine. */

    if (read(fd, &t, sizeof(struct afl_tsl)) != sizeof(struct afl_tsl))
      break;

    tb_find_slow(env, t.pc, t.cs_base, t.flags);

  }

  close(fd);

}

