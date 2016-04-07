AFL_NO_FORKSRV=1 afl-fuzz -i input/ -o output/ -x dict/http.txt -Q ./example-cgis/closed_source_simple_print_env.elf #add -x your_own_dict_from_cgi.txt if you can (extract tokens from disassembly)
