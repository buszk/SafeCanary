#!/bin/bash

sc=~/safe-canary.so
np=~/nullpin.so
ld=~/libdft.so
tar=~/repo/tar/build_x86/src/tar
cflag=cf
xflag=xf
tmptar=test.tar
pin=~/pin/pin

dir=~/repo/write-ups-2016

timing(){
    cmd=$@
    echo $cmd
    echo "========================"
    echo "Raw cmd"
    time $cmd
    echo "========================"
    echo "Nullpin"
    time "$pin" "-t" "$np" "--" $cmd
    echo "========================"
    echo "libdft"
    time "$pin" "-t" "$ld" "--" $cmd
    echo "========================"
    echo "safe-canary"
    time "$pin" "-t" "$sc" "--" $cmd
}

test(){
    echo "Creating testing directory..."
    mkdir -p test_dir
    cd test_dir
    echo "The following commands will be tested..."
    cmd="$tar $cflag $tmptar $dir"
    echo "$cmd"
    timing $cmd
    
    cmd="$tar $xflag $tmptar"
    echo "$cmd"
    timing $cmd
    cd ..
    rm -rf test_dir
}
for i in `seq 1 $1`; do
    test
done
