#ifndef _SOCK_H
#define _SOCK_H

extern void swill_initialize_comm(void);
extern void swill_terminate_comm(void);

extern int swill_create_listening_socket(int port);
extern int swill_get_assigned_port(int socket);
extern int swill_accept_connection(int sock, char* address);
extern void swill_close_socket(int sock);

extern int swill_sock_set_nonblock(int sock);
extern void swill_sock_restore_block(int sock, int value);

extern int swill_sock_can_read(int sock, int timeout);
extern int swill_sock_do_read(int sock, char* buffer, unsigned int length);

extern int swill_sock_can_write(int sock, int timeout);
extern int swill_sock_do_write(int sock, char* buffer, unsigned int length);

#endif
