dir=student-distrib


echo "run gdb bootimg now in other window "
# qemu-system-i386 -kernel $dir/bootimg -m 256 -gdb tcp:127.0.0.1:1234 -S -name mp3 
# qemu-system-i386 -kernel $dir/bootimg -m 512 -gdb tcp:127.0.0.1:1234 -S -name mp3 -display curses



qemu-system-i386 -hda $dir/mp3.img -m 512 -gdb tcp:127.0.0.1:1234 -name mp4 -display curses $1
# qemu-system-i386 -hda $dir/mp3.img -m 512 -gdb tcp:127.0.0.1:1234 -S -name mp3 
