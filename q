dir=student-distrib


echo "run gdb bootimg now in other window "

truncate -s 1G hd.img

qemu-system-i386 -hda $dir/mp3.img -m 512 -gdb tcp:127.0.0.1:1234 -name mp4 -display curses $1 -drive file=hd.img,index=1,media=disk,if=ide,format=raw
