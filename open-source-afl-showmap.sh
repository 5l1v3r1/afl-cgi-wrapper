echo "Testing ./input/1.txt"
AFL_NO_FORKSRV=1 afl-showmap -o showmap.txt ./open-source-wrapper-cgi-env.elf ./example-cgis/open_source_simple_print_env.elf < ./input/1.txt
for f in ./output/crashes/*
do
  echo "Testing $f file..."
  AFL_NO_FORKSRV=1 afl-showmap -o showmap.txt ./open-source-wrapper-cgi-env.elf ./example-cgis/open_source_simple_print_env.elf < $f
done
