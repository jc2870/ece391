dir=student-distrib


echo "run gdb bootimg now in other window "

truncate -s 1G hd_bus.img
truncate -s 1G hd_scsi.img

qemu-system-i386 -hda $dir/mp3.img -m 512 -gdb tcp:127.0.0.1:1234 -name mp4 -nographic $1 -hdb hd_bus.img \
	-device virtio-scsi-pci,id=scsi0 -device scsi-hd,drive=hd2,bus=scsi0.0 -drive if=none,file=./hd_scsi.img,format=raw,id=hd2
