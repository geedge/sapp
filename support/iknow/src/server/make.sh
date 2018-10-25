echo "gcc -I ../../include  -g iknow_cmd_parser.c -lMESA_htable -l pthread"
gcc -o iknow_server -I ../../include  -g -D_GNU_SOURCE=1 iknow_cmd_parser.c iknow_server.c  iknow_task_scheduler.c example_server.c -lMESA_htable -l pthread

