#!/bin/sh

if [[ $# -eq 0 ]] ; then
  echo "choose file"
  exit 2
fi

SHELLCODE=$(for op in $(objdump -d "$1" -Mintel | grep "^ " | cut -f2); do echo -n "\x$op" ; done)

echo "$SHELLCODE"
echo -e "\nLength : $(echo "$SHELLCODE" | grep -o "x" | wc -l)"
