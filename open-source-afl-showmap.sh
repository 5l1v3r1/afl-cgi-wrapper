echo "Testing ./input/1.txt"
afl-showmap -o showmap.txt ./open-source-wrapper-cgi-env.elf ./example-cgis/open_source_simple_print_env.elf < ./input/1.txt
for f in ./output/crashes/*
do
  echo "Testing $f file..."
  afl-showmap -o showmap.txt ./open-source-wrapper-cgi-env.elf ./example-cgis/open_source_simple_print_env.elf < $f
done
