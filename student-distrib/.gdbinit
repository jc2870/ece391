target remote 127.0.0.1:1234
layout split
set pagination off

b start
b entry
b __panic
b intr0xD_handler
b schedule
b test_tasks
b common_intr_entry
b intr0xE_handler
b tasks.c:95
b tasks.c:96
b tasks.c:94
b tasks.c:104
