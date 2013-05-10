/*-
 * Copyright (c) 2012, John Mehr <jcm@visi.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 *
 */

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/tree.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/ssl3.h>

#include <ctype.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <md5.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SVNUP_VERSION "0.71"
#define BUFFER_UNIT 4096
#define COMMAND_BUFFER 32768
#define COMMAND_BUFFER_THRESHOLD 32000

typedef struct {
	int            socket_descriptor;
	SSL           *ssl;
	SSL_CTX       *ctx;
	char          *address;
	unsigned short port;
	unsigned int   revision;
	int            family;
	char          *root;
	char          *trunk;
	char          *branch;
	char          *path_target;
	char          *response;
	size_t         response_length;
	unsigned int   response_blocks;
	unsigned int   response_groups;
	char          *path_work;
	char          *known_files;
	long           known_files_size;
	char          *known_files_old;
	char          *known_files_new;
	int            verbosity;
	} connector;


typedef struct {
	char          *href;
	char          *path;
	char          *md5;
	unsigned long  size;
	unsigned long  raw_size;
	unsigned int   index;
	char           executable;
	char           special;
	char           download;
	char          *revision_tag;
	} file_node;


struct tree_node {
	RB_ENTRY(tree_node)  link;
	char                *path;
	char                *md5;
	};


/* Function Prototypes */

static int	 tree_node_compare(const struct tree_node *, const struct tree_node *);
void		 prune(connector *, char *);
char		*find_response_end(unsigned short, char *, char *);
char		*terminate_response(unsigned short, char *, char *);
void		 reset_connection(connector *);
void		 send_command(connector *, const char *);
int		 check_command_success(unsigned short, char **, char **);
char		*process_command_svn(connector *, const char *, unsigned int);
char		*process_command_http(connector *, char *);
char		*parse_xml_value(char *, char *, const char *);
void		 parse_response_group(connector *, char **, char **);
int		 parse_response_item(connector *, char *, int *, char **, char **);
int		 confirm_md5(char *, char *);
file_node	*new_file_node(file_node ***, int *, int *);
void		 new_buffer(char ***, int **, int *);
void		 save_file(char *, char *, char *, char *, int, int);
void		 save_known_file_list(connector *, file_node **, int);
void		 set_configuration_parameters(connector *, char *, size_t, const char *);
void		 load_configuration(connector *, char *, char *);
void		 create_directory(char *);
void		 process_report_svn(connector *, char *, file_node ***, int *, int *);
void		 process_report_http(connector *, file_node ***, int *file_count, int *);
void		 parse_additional_attributes(connector *, char *, char *, file_node *);
void		 get_files(connector *, char *, char *, file_node **, int, int);
void		 usage(char *);

/*
 * tree_node_compare
 *
 * Function that informs the Red-Black tree functions how to sort keys.
 */

static int tree_node_compare(const struct tree_node *a, const struct tree_node *b) {
	return strcmp(a->path, b->path);
	}

RB_HEAD(rbtree, tree_node) known_files = RB_INITIALIZER(&known_files);
RB_PROTOTYPE(rbtree, tree_node, link, tree_node_compare);
RB_GENERATE(rbtree, tree_node, link, tree_node_compare);

/*
 * prune
 *
 * Procedure that recursively removes the file or directory tree passed in.
 */

void
prune(connector *connection, char *path_target)
{
	char          *temp_file;
	size_t         length;
	DIR           *dp;
	struct stat    local;
	struct dirent *de;

	length = strlen(path_target) + strlen(connection->path_target) + 2;

	if ((temp_file = (char *)malloc(length)) == NULL)
		err(EXIT_FAILURE, "prune temp_file malloc");

	snprintf(temp_file, length, "%s%s", connection->path_target, path_target);

	if (lstat(temp_file, &local) != -1) {
		if (connection->verbosity) printf(" - %s\n", temp_file);

		if ((S_ISREG(local.st_mode)) || (S_ISLNK(local.st_mode)))
			if ((remove(temp_file)) != 0)
				err(EXIT_FAILURE, "Cannot remove %s", temp_file);

		if (S_ISDIR(local.st_mode))
			if ((dp = opendir(temp_file)) != NULL) {
				while ((de = readdir(dp)) != NULL) {
					if (strcmp(de->d_name, "." ) == 0) continue;
					if (strcmp(de->d_name, "..") == 0) continue;

					snprintf(temp_file,
						length,
						"%s/%s",
						temp_file,
						de->d_name
						);

					/* prune(connection, temp_file); */
				}

				closedir(dp);

				if ((rmdir(temp_file)) != 0)
					err(EXIT_FAILURE, "Cannot remove %s", temp_file);
			}
	}

	free(temp_file);
}


/*
 * find_response_end
 *
 * Function that counts opening and closing parenthesis of a command's response in
 * order to find the end of the response.
 */

char *
find_response_end(unsigned short port, char *start, char *end)
{
	int count = 0;

	if (port == 3690)
		do {
			count += (*start == '(' ? 1 : (*start == ')' ? -1 : 0));
		}
		while ((*start != '\0') && (start++ < end) && (count > 0));

	if ((port == 80) || (port == 443))
		start = strstr(start, "\r\n\r\n") + 4;

	return (start);
}


/*
 * terminate_response
 *
 * Function that puts a null character at the end of a command's response.
 */

char *
terminate_response(unsigned short port, char *start, char *end)
{
	end = find_response_end(port, start, end);
	*end = '\0';

	return (end);
}


/*
 * reset_connection
 *
 * Procedure that (re)establishes a connection with the server.
 */

void
reset_connection(connector *connection)
{
	struct addrinfo hints, *start, *temp;
	int   error, option;
	char  type[10];

	if (connection->socket_descriptor)
		if (close(connection->socket_descriptor) != 0)
			if (errno != EBADF) err(EXIT_FAILURE, "close_connection");

	switch (connection->port) {
		case   23: snprintf(type, sizeof(type), "svn+ssh"); break;
		case   80: snprintf(type, sizeof(type), "http"); break;
		case  443: snprintf(type, sizeof(type), "https"); break;
		case 3690: snprintf(type, sizeof(type), "svn"); break;
		default  : errx(EXIT_FAILURE, "Invalid port/protocol");
	}

	bzero(&hints, sizeof(hints));

	hints.ai_family = connection->family;
	hints.ai_socktype = SOCK_STREAM;

	if ((error = getaddrinfo(connection->address, type, &hints, &start)))
		errx(EXIT_FAILURE, "%s", gai_strerror(error));

	connection->socket_descriptor = -1;
	while (start) {
		temp = start;

		if (connection->socket_descriptor < 0) {
			if ((connection->socket_descriptor = socket(temp->ai_family, temp->ai_socktype, temp->ai_protocol)) < 0)
				err(EXIT_FAILURE, "socket failure");

			if (connect(connection->socket_descriptor, temp->ai_addr, temp->ai_addrlen) < 0)
				err(EXIT_FAILURE, "connect failure");
		}

		start = temp->ai_next;
		freeaddrinfo(temp);
	}

	fcntl(connection->socket_descriptor, F_SETFL, O_NONBLOCK);

	if (connection->port == 443) {
		if (SSL_library_init() == 0)
			err(EXIT_FAILURE, "reset_connection: SSL_library_init");

		SSL_load_error_strings();
		connection->ctx = SSL_CTX_new(SSLv23_client_method());
		SSL_CTX_set_mode(connection->ctx, SSL_MODE_AUTO_RETRY);

		if ((connection->ssl = SSL_new(connection->ctx)) == NULL)
			err(EXIT_FAILURE, "reset_connection: SSL_new");

		SSL_set_fd(connection->ssl, connection->socket_descriptor);
		while ((error = SSL_connect(connection->ssl)) == -1) ; //fprintf(stderr, "%d\n", code);
	}

	option = 1;

	if (setsockopt(connection->socket_descriptor, SOL_SOCKET, SO_KEEPALIVE, &option, sizeof(option)))
		err(EXIT_FAILURE, "setsockopt SO_KEEPALIVE error");

	option = COMMAND_BUFFER;

	if (setsockopt(connection->socket_descriptor, SOL_SOCKET, SO_SNDBUF, &option, sizeof(option)))
		err(EXIT_FAILURE, "setsockopt SO_SNDBUF error");

	if (setsockopt(connection->socket_descriptor, SOL_SOCKET, SO_RCVBUF, &option, sizeof(option)))
		err(EXIT_FAILURE, "setsockopt SO_RCVBUF error");
}


/*
 * send_command
 *
 * Procedure that sends commands to the http/svn server.
 */

void
send_command(connector *connection, const char *command)
{
	int bytes_written, total_bytes_written, bytes_to_write;

	if (command) {
		total_bytes_written = 0;
		bytes_to_write = strlen(command);

		if (connection->verbosity > 2)
			fprintf(stdout, "<< %d bytes\n%s", bytes_to_write, command);

		while (total_bytes_written < bytes_to_write) {
			bytes_written = -1;
			while (bytes_written == -1)
				if (connection->port == 443)
					bytes_written = SSL_write(
						connection->ssl,
						command + total_bytes_written,
						bytes_to_write - total_bytes_written
						);
				else
					bytes_written = write(
						connection->socket_descriptor,
						command + total_bytes_written,
						bytes_to_write - total_bytes_written
						);

			total_bytes_written += bytes_written;
		}
	}
}


/*
 * check_command_success
 *
 * Function that makes sure a failure response has not been sent from the svn server.
 */

int
check_command_success(unsigned short port, char **start, char **end)
{
	int  ok = 1;

	if (port == 3690) {
		if (strstr(*start, "( success ( ( ) 0: ) ) ( failure") == *start)
			ok = 0;

		if (strstr(*start, "( success ( ) ) ( failure") == *start)
			ok = 0;

		if (ok) {
			if (strstr(*start, "( success ") == *start) {
				if (strstr(*start, "( success ( ( ) 0: ) )") == *start)
					*start += 23;
				*end = find_response_end(port, *start, *end) + 1;
			}
		else ok = 0;
		}
	}

	if ((port == 80) || (port == 443)) {
		if (strstr(*start, "HTTP/1.1 20") == *start) {
			*start = strstr(*start, "\r\n\r\n");
			if (*start) *start += 4; else ok = 0;
		}
	}

	if (!ok) fprintf(stderr, "Command Failure: %s\n", *start);

	return (!ok);
}


/*
 * process_command_svn
 *
 * Function that sends a command set to the svn server and parses its response to make
 * sure that the expected number of response strings have been received.
 */

char *
process_command_svn(connector *connection, const char *command, unsigned int expected_bytes)
{
	int           bytes_read, ok, count;
	unsigned int  group, try, position;
	char          input[BUFFER_UNIT + 1], *check;

	try = 0;
	retry:

	send_command(connection, command);

	count = position = ok = group = connection->response_length = 0;

	do {
		bzero(input, BUFFER_UNIT + 1);

		bytes_read = -1;
		while (bytes_read == -1)
			bytes_read = read(
				connection->socket_descriptor,
				input,
				BUFFER_UNIT
				);

		if (bytes_read == 0) {
			try++;
			if (try > 5) errx(EXIT_FAILURE, "Error in svn stream.  Quitting.");
			if (try > 1) fprintf(stderr, "Error in svn stream, retry #%d\n", try);
			goto retry;
		}

		connection->response_length += bytes_read;

		if (connection->response_length > connection->response_blocks * BUFFER_UNIT) {
			connection->response_blocks += 1;
			connection->response = (char *)realloc(
				connection->response,
				connection->response_blocks * BUFFER_UNIT + 1
				);

			if (connection->response == NULL)
				err(EXIT_FAILURE, "process_command_svn realloc");
		}

		if (expected_bytes == 0) {
			if (input[1] == '\0') {
				connection->response[position++] = input[0];
				continue;
			}

			if (connection->verbosity > 3)
				fprintf(stdout, "==========\n>> Response Parse:\n");

			check = input;
			if ((count == 0) && (input[0] == ' ')) *check++ = '\0';

			do {
				count += (*check == '(' ? 1 : (*check == ')' ? -1 : 0));

				if (connection->verbosity > 3) fprintf(stderr, "%d", count);

				if (count == 0) {
					group++;
					check++;
					if (*check == ' ') *check = '\0';
					if (*check != '\0') fprintf(stderr, "oops: %d %c\n", *check, *check);
					}
			}
			while (++check < input + bytes_read);
		}

		memcpy(connection->response + position, input, bytes_read + 1);
		position += bytes_read;

		if ((expected_bytes == 0) && (connection->verbosity > 3))
			fprintf(stderr, ". = %d %d\n", group, connection->response_groups);

		if (group == connection->response_groups) ok = 1;
		if (position == expected_bytes) ok = 1;

	}
	while (!ok);

	if ((expected_bytes == 0) && (connection->verbosity > 2))
		fprintf(stdout, "==========\n>> Response:\n%s", connection->response);

	connection->response[position] = '\0';

	return (connection->response);
}


/*
 * process_command_http
 *
 * Function that sends a command set to the http server and parses its response to make
 * sure that the expected number of response bytes have been received.
 */

char *
process_command_http(connector *connection, char *command)
{
	int   bytes_read, chunk, gap, chunked_transfer, spread, read_more;
	char *begin, *end, *marker1, *marker2, *temp, input[BUFFER_UNIT + 1];
	unsigned int groups, offset, try;

	try = 0;
	retry:

	chunked_transfer = -1;
	connection->response_length = chunk = groups = 0;
	offset = read_more = 0;
	begin = end = marker1 = marker2 = temp = NULL;

	bzero(connection->response, connection->response_blocks * BUFFER_UNIT + 1);
	bzero(input, BUFFER_UNIT + 1);

	reset_connection(connection);
	send_command(connection, command);

	while (groups < connection->response_groups) {
		spread = connection->response_length - offset;

		if (spread <= 0)
			read_more = 1;

		if ((chunked_transfer == 1) && (spread <= 5))
			read_more = 1;

		if ((chunked_transfer == 0) && (spread == 0) && (connection->response_groups - groups == 1))
			break;

		if (read_more) {
			bytes_read = -1;
			while (bytes_read == -1)
				if (connection->port == 443)
					bytes_read = SSL_read(
						connection->ssl,
						input,
						BUFFER_UNIT
						);
				else
					bytes_read = read(
						connection->socket_descriptor,
						input,
						BUFFER_UNIT
						);

			if (connection->response_length + bytes_read > connection->response_blocks * BUFFER_UNIT) {
				connection->response_blocks += 1;
				connection->response = (char *)realloc(
					connection->response,
					connection->response_blocks * BUFFER_UNIT + 1
					);

				if (connection->response == NULL)
					err(EXIT_FAILURE, "process_command_http realloc");
			}

			if (bytes_read == 0) {
				try++;
				if (try > 5) errx(EXIT_FAILURE, "Error in http stream.  Quitting.");
				if (try > 1) fprintf(stderr, "Error in http stream, retry #%d\n", try);
				goto retry;
			}

			memcpy(connection->response + connection->response_length, input, bytes_read + 1);
			connection->response_length += bytes_read;
			connection->response[connection->response_length] = '\0';
			read_more = 0;
			spread = connection->response_length - offset;
		}

		if ((chunked_transfer == 0) && (spread >= 0)) {
			chunked_transfer = -1;
			groups++;
		}

		if (chunked_transfer == -1) {
			begin = connection->response + offset;
			if ((begin = strstr(begin, "HTTP/1.1 20")) == NULL) {
				read_more = 1;
				continue;
			}

			if ((end = strstr(begin, "\r\n\r\n")) == NULL) {
				read_more = 1;
				continue;
			}

			end += 4;

			offset += (end - begin);
			groups++;

			marker1 = strstr(begin, "Content-Length: ");
			marker2 = strstr(begin, "Transfer-Encoding: chunked");

			if (marker1) chunked_transfer = 0;
			if (marker2) chunked_transfer = 1;

			if ((marker1) && (marker2)) chunked_transfer = (marker1 < marker2) ? 0 : 1;

			if (chunked_transfer == 0) {
				chunked_transfer = 0;
				chunk = strtol(marker1 + 16, (char **)NULL, 10);
				if (chunk < 0)
					errx(EXIT_FAILURE, "process_command_http: Bad stream data");

				offset += chunk;
				if (connection->response_length > offset) {
					chunked_transfer = -1;
					groups++;
				}
			}

			if (chunked_transfer == 1) {
				chunk = 0;
				marker2 = end;
			}
		}

		while ((chunked_transfer == 1) && ((end = strstr(marker2, "\r\n")) != NULL)) {
			chunk = strtol(marker2, (char **)NULL, 16);
			if (chunk < 0)
				errx(EXIT_FAILURE, "process_command_http: Bad stream data ");

			gap = end - marker2 + 4;
			offset += chunk + gap;
			marker2 += chunk + gap;

			if ((chunk == 0) && (gap == 5)) {
				chunked_transfer = -1;
				groups++;
			}
		}

		if (connection->verbosity > 2)
			fprintf(stderr, "\rBytes read: %zd, Bytes expected: %d, g:%d, rg:%d",
				connection->response_length,
				offset,
				groups,
				connection->response_groups
				);
	}

	if (connection->verbosity > 2) fprintf(stderr, "\n");

	if (connection->verbosity > 3)
		fprintf(stdout, "==========\n%s\n==========\n", connection->response);

	return (connection->response);
}


/*
 * parse_xml_value
 *
 * Function that returns the text found between the opening and closing tags passed in.
 */

char *
parse_xml_value(char *start, char *end, const char *tag)
{
	char   *data_start, *data_end, *end_tag, *value, temp_end;
	size_t  tag_length;

	value = NULL;
	temp_end = *end;
	*end = '\0';

	tag_length = strlen(tag) + 4;
	if ((end_tag = (char *)malloc(tag_length)) == NULL)
		err(EXIT_FAILURE, "parse_xml_value end_tag malloc");

	snprintf(end_tag, tag_length, "</%s>", tag);

	if ((data_start = strstr(start, tag))) {
		if ((data_start = strchr(data_start, '>'))) {
			data_start++;
			data_end = strstr(data_start, end_tag);

			if (data_end) {
				if ((value = (char *)malloc(data_end - data_start + 1)) == NULL)
					err(EXIT_FAILURE, "parse_xml_value value malloc");

				memcpy(value, data_start, data_end - data_start);
				value[data_end - data_start] = '\0';
			}
		}
	}

	free(end_tag);
	*end = temp_end;

	return (value);
}


/*
 * parse_response_group
 *
 * Procedure that isolates the next response group from the list of responses.
 */

void
parse_response_group(connector *connection, char **start, char **end)
{
	if (connection->port == 3690)
		*end = find_response_end(connection->port, *start, *end);

	if ((connection->port == 80) || (connection->port == 443)) {
		*end = strstr(*start, "</D:multistatus>");
		if (*end != NULL) *end += 16;
		else errx(EXIT_FAILURE, "Error in http stream: %s\n", *start);
	}

	**end = '\0';
}


/*
 * parse_response_item
 *
 * Function that isolates the next response from the list of responses.
 */

int
parse_response_item(connector *connection, char *end, int *count, char **item_start, char **item_end)
{
	int ok = 1, c = 0, has_entries = 0;

	if (connection->port == 3690) {
		if (*count == '\0') {
			while ((c < 3) && (*item_start < end)) {
				c += (**item_start == '(' ? 1 : (**item_start == ')' ? -1 : 0));
				if (**item_start == ':') has_entries++;
				(*item_start)++;
			}

			(*item_start) += 5;
			*item_end = *item_start;
		}

		c = 1;
		(*item_end)++;

		while ((c > 0) && (*item_end < end)) {
			(*item_end)++;
			c += (**item_end == '(' ? 1 : (**item_end == ')' ? -1 : 0));
			if (**item_end == ':') has_entries++;
		}

		(*item_end)++;
		**item_end = '\0';
	}

	if ((connection->port == 80) || (connection->port == 443)) {
		*item_end = strstr(*item_start, "</D:response>");

		if (*item_end != NULL) {
			*item_end += 13;
			**item_end = '\0';
			has_entries = 1;
		} else ok = 0;
	}

	if (!has_entries) ok = 0;

	(*count)++;

	return (ok);
}


/*
 * confirm_md5
 *
 * Function that loads a local file and removes revision tags one at a time until
 * the MD5 checksum matches that of the corresponding repository file or the file
 * has run out of $ FreeBSD : markers.
 */

int
confirm_md5(char *md5, char *file_path_target)
{
	int      fd, mismatch;
	size_t   temp_size;
	char    *buffer, *start, *value, *eol, *md5_check;
	MD5_CTX  md5_context;
	struct stat file;

	mismatch = 1;

	/* Load the file into memory. */

	if (lstat(file_path_target, &file) != -1) {
		if (S_ISLNK(file.st_mode)) mismatch = 0;
		else {
			if ((buffer = (char *)malloc(file.st_size + 1)) == NULL)
				err(EXIT_FAILURE, "confirm_md5 temp_buffer malloc");

			if ((fd = open(file_path_target, O_RDONLY)) == -1)
				err(EXIT_FAILURE, "read file (%s):", file_path_target);

			if (read(fd, buffer, file.st_size) != file.st_size)
				err(EXIT_FAILURE, "read file (%s): file changed", file_path_target);

			buffer[file.st_size] = '\0';

			close(fd);

			temp_size = file.st_size;
			start = buffer;

			/* Continue removing revision tags while the MD5 sums do not match. */

			while ((mismatch) && (start)) {
				MD5Init(&md5_context);
				MD5Update(&md5_context, buffer, temp_size);
				md5_check = MD5End(&md5_context, NULL);
				mismatch = strncmp(md5, md5_check, 33);
				free(md5_check);

				start = strstr(start, "$FreeBSD:");

				if ((mismatch) && (start)) {
					start += 8;
					value = strchr(start, '$');
					eol = strchr(start, '\n');

					if ((value) && ((eol == NULL) || (value < eol))) {
						memmove(start, value, temp_size - (value - buffer));
						temp_size -= (value - start);
						buffer[temp_size] = '\0';
					}
				}
			}

			free(buffer);
		}
	}

	return (mismatch);
}


/*
 * new_file_node
 *
 * Function that allocates a new file_node and expands the dynamic
 * array that stores file_nodes.
 */

file_node *
new_file_node(file_node ***file, int *file_count, int *file_max)
{
	file_node *node;

	if ((node = (file_node *)malloc(sizeof(file_node))) == NULL)
		err(EXIT_FAILURE, "new_file_node node malloc");

	if ((node->md5 = (char *)malloc(34)) == NULL)
		err(EXIT_FAILURE, "new_file_node node->md5 malloc");

	bzero(node->md5, 33);
	node->size = node->raw_size = 0;
	node->href = node->revision_tag = NULL;
	node->special = node->executable = node->download = 0;
	node->index = *file_count;

	(*file)[*file_count] = node;

	if (++(*file_count) == *file_max) {
		*file_max += BUFFER_UNIT;

		if ((*file = (file_node **)realloc(*file, *file_max * sizeof(file_node **))) == NULL)
			err(EXIT_FAILURE, "new_file_node file realloc");
	}

	return (node);
}


/*
 * new_buffer
 *
 * Procedure that creates a new buffer for storing commands to be
 * sent and expands the dynamic array that keeps track of them.
 */

void
new_buffer(char ***buffer, int **buffer_commands, int *buffers)
{
	(*buffers)++;

	if ((*buffer = realloc(*buffer, sizeof(char **) * (*buffers + 1))) == NULL)
		err(EXIT_FAILURE, "new_buffer buffer realloc");

	if ((*buffer_commands = realloc(*buffer_commands, sizeof(int *) * (*buffers + 1))) == NULL)
		err(EXIT_FAILURE, "new_buffer buffer_commands realloc");

	if (((*buffer)[*buffers] = malloc(COMMAND_BUFFER)) == NULL)
		err(EXIT_FAILURE, "new_buffer buffer[0] malloc");

	(*buffer_commands)[*buffers] = 0;
	bzero((*buffer)[*buffers], COMMAND_BUFFER);
}


/*
 * save_file
 *
 * Procedure that saves a file and inserts revision tags if any exist.
 */

void
save_file(char *filename, char *revision_tag, char *start, char *end, int executable, int special)
{
	char *tag;
	int   fd;

	if (special) {
		if (strstr(start, "link ") == start) {
			*end = '\0';

			if (symlink(start + 5, filename))
				if (errno != EEXIST)
					err(EXIT_FAILURE, "Cannot link %s -> %s", start + 5, filename);
		}
	} else {
		if ((fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC)) == -1)
			err(EXIT_FAILURE, "write file failure %s", filename);

		if (revision_tag) {
			*end = '\0';

			while ((start < end) && ((tag = strstr(start, "$FreeBSD$")) != NULL)) {
				tag += 8;
				write(fd, start, tag - start);
				write(fd, revision_tag, strlen(revision_tag));
				start = tag;
			}
		}

		write(fd, start, end - start);
		close(fd);
		chmod(filename, executable ? 0755 : 0644);
	}
}


/*
 * save_known_file_list
 *
 * Procedure that saves the list of files known to be in the repository.
 */

void
save_known_file_list(connector *connection, file_node **file, int file_count)
{
	struct tree_node  find, *found;
	char              revision[16];
	int               x, fd;

	if ((fd = open(connection->known_files_new, O_WRONLY | O_CREAT | O_TRUNC)) == -1)
		err(EXIT_FAILURE, "write file failure %s", connection->known_files_new);

	snprintf(revision, 16, "%u\r\n", connection->revision);
	write(fd, revision, strlen(revision));

	for (x = 0; x < file_count; x++) {
		write(fd, file[x]->md5, strlen(file[x]->md5));
		write(fd, "\t", 1);
		write(fd, file[x]->path, strlen(file[x]->path));
		write(fd, "\n", 1);

		find.path = file[x]->path;
		if ((found = RB_FIND(rbtree, &known_files, &find)) != NULL)
			free(RB_REMOVE(rbtree, &known_files, found));

		free(file[x]->path);
		if (file[x]->revision_tag) free(file[x]->revision_tag);
		if (file[x]->href) free(file[x]->href);
		free(file[x]);
		file[x] = NULL;
	}

	close(fd);
	chmod(connection->known_files_new, 0644);
}


/*
 * set_configuration_parameters
 *
 * Procedure that parses a line of text from the config file, allocates
 * space and stores the values.
 */

void
set_configuration_parameters(connector *connection, char *buffer, size_t length, const char *section)
{
	char *line, *item, *bracketed_section;
	unsigned int x;

	if ((bracketed_section = (char *)malloc(strlen(section) + 4)) == NULL)
		err(EXIT_FAILURE, "set_configuration bracketed_section malloc");

	snprintf(bracketed_section, strlen(section) + 4, "[%s]\n", section);

	if ((item = strstr(buffer, bracketed_section)) != NULL) {
		item += strlen(bracketed_section);

		while ((line = strsep(&item, "\n"))) {
			if ((strlen(line) == 0) || (line[0] == '[')) break;
			if (line[0] == '#') continue;

			if (strstr(line, "host=") == line) {
				line += 5;
				if ((connection->address = (char *)realloc(connection->address, item - line + 1)) == NULL)
					err(EXIT_FAILURE, "set_configuration bracketed_section realloc");

				memcpy(connection->address, line, item - line);
				continue;
			}

			if (strstr(line, "branch=") == line) {
				line += 7;
				while (*line == '/') line++;

				if ((connection->branch = (char *)realloc(connection->branch, item - line + 1)) == NULL)
					err(EXIT_FAILURE, "set_configuration connection->branch realloc");

				memcpy(connection->branch, line, item - line);
				continue;
			}

			if (strstr(line, "target=") == line) {
				line += 7;
				if ((connection->path_target = (char *)realloc(connection->path_target, item - line + 1)) == NULL)
					err(EXIT_FAILURE, "set_configuration connection->path_target realloc");

				memcpy(connection->path_target, line, item - line);
				continue;
			}

			if (strstr(line, "work_directory=") == line) {
				line += 15;
				if ((connection->path_work = (char *)realloc(connection->path_work, item - line + 1)) == NULL)
					err(EXIT_FAILURE, "set_configuration connection->path_work realloc");

				memcpy(connection->path_work, line, item - line);
				continue;
			}

			if (strstr(line, "protocol=") == line) {
				line += 9;
				if (strncmp(line, "svn", 3) == 0) connection->port = 3690;
				if (strncmp(line, "svn+ssh", 7) == 0) connection->port = 23;
				if (strncmp(line, "http", 4) == 0) connection->port = 80;
				if (strncmp(line, "https", 5) == 0) connection->port = 443;
				continue;
			}

			if (strstr(line, "verbosity=") == line) {
				connection->verbosity = strtol(line + 10, (char **)NULL, 10);
				continue;
			}
		}
	}

	for (x = 0; x < length; x++) if (buffer[x] == '\0') buffer[x] = '\n';

	free(bracketed_section);
}


/*
 * load_configuration
 *
 * Procedure that loads the section options from /usr/local/etc/svnup.conf
 */

void
load_configuration(connector *connection, char *configuration_file, char *section)
{
	char        *buffer;
	struct stat  file;
	int          fd;

	if (lstat(configuration_file, &file) == -1)
		err(EXIT_FAILURE, "Cannot find configuration file");

	if ((buffer = (char *)malloc(file.st_size + 1)) == NULL)
		err(EXIT_FAILURE, "load_configuration temp_buffer malloc");

	if ((fd = open(configuration_file, O_RDONLY)) == -1)
		err(EXIT_FAILURE, "Cannot read configuration file %s", configuration_file);

	if (read(fd, buffer, file.st_size) != file.st_size)
		err(EXIT_FAILURE, "Problem reading configuration file %s", configuration_file);

	buffer[file.st_size] = '\0';
	close(fd);

	set_configuration_parameters(connection, buffer, file.st_size, "defaults");
	set_configuration_parameters(connection, buffer, file.st_size, section);

	free(buffer);
	}


/*
 * create_directory
 *
 * Procedure that checks and creates a local directory if possible. 
 */

void
create_directory(char *directory)
{
	struct stat local;

	if (lstat(directory, &local) != -1) {
		if (!S_ISDIR(local.st_mode))
			errx(EXIT_FAILURE, "%s exists and is not a directory.", directory);
	} else {
		if (mkdir(directory, 0755))
			err(EXIT_FAILURE, "Cannot create %s", directory);
	}
}


/*
 * process_report_svn
 *
 * Procedure that sends the svn report command and saves the initial details
 * in a dynamic array of file_nodes.
 */

void
process_report_svn(connector *connection, char *command, file_node ***file, int *file_count, int *file_max)
{
	char   *start, *end, *item_start, *item_end, *name, *marker, *command_start;
	char   *directory_start, *directory_end, path_source[MAXNAMLEN + 1];
	char    temp_path[BUFFER_UNIT], next_command[BUFFER_UNIT], *temp, **buffer;
	int     x, buffers, *buffer_commands, count, path_exists, try;
	size_t  d, length, path_length, name_length, path_source_length;
	file_node   *this_file;
	struct stat  local;

	try = buffers = -1;
	buffer = NULL;
	buffer_commands = NULL;
	new_buffer(&buffer, &buffer_commands, &buffers);

	retry:

	start = process_command_svn(connection, command, 0);
	end   = start + connection->response_length;

	command_start = command;

	directory_start = command_start;

	for (d = 0; d < connection->response_groups / 2; d++) {
		if (strstr(directory_start, "( get-dir ( ") != directory_start)
			errx(EXIT_FAILURE, "Error in response: %s\n", directory_start);

		directory_end = strchr(directory_start, '\n');

		temp = strchr(directory_start, ':') + 1;
		directory_start = strchr(temp, ' ');

		length = directory_start - temp;
		if (length > 0) memcpy(path_source, temp, length);

		path_source[length] = '\0';
		path_source_length = length;

		directory_start = directory_end + 1;

		/* Parse the response for file/directory names. */

		end   = connection->response + connection->response_length;
		if (check_command_success(connection->port, &start, &end)) {
			try++;
			if (try > 5) errx(EXIT_FAILURE, "Error in svn stream.  Quitting.");
			if (try > 1) fprintf(stderr, "Error in svn stream, retry #%d\n", try);
			goto retry;
		}

		parse_response_group(connection, &start, &end);

		item_start = start;
		item_end = end;

		count = 0;

		while (parse_response_item(connection, end, &count, &item_start, &item_end)) {
			temp = NULL;

			/* Keep track of the remote files. */

			length = strtol(item_start + 1, (char **)NULL, 10);
			if (length > MAXNAMLEN)
				errx(EXIT_FAILURE, "entry_is_file file name is too long");

			marker = strchr(item_start, ':') + 1 + length;

			if (strstr(marker, " file ") == marker) {
				this_file = new_file_node(file, file_count, file_max);

				name_length = strtol(item_start + 1, (char **)NULL, 10);
				if (name_length > MAXNAMLEN)
					errx(EXIT_FAILURE, "process_file_entry file name is too long");

				name = item_start = strchr(item_start, ':') + 1;

				item_start += name_length;
				*item_start = '\0';
				path_length = strlen(path_source) + name_length + 2;

				if (strstr(item_start + 1, "file ") != item_start + 1)
					errx(EXIT_FAILURE, "process_file_entry malformed response");

				if ((this_file->path = (char *)malloc(path_length)) == NULL)
					err(EXIT_FAILURE, "process_file_entry file->path malloc");

				snprintf(this_file->path, path_length, "%s/%s", path_source, name);

				item_start = strchr(item_start + 1, ' ');
				this_file->size = strtol(item_start, (char **)NULL, 10);
			}

			if (strstr(marker, " dir ") == marker) {
				length = strtol(item_start + 1, (char **)NULL, 10);
				if (length > MAXNAMLEN)
					errx(EXIT_FAILURE, "process_file file name is too long");

				name = strchr(item_start, ':') + 1;
				name[length] = '\0';

				snprintf(temp_path,
					BUFFER_UNIT,
					"%s%s/%s",
					connection->path_target,
					path_source,
					name
					);

				/* Create the directory locally if it doesn't exist. */

				path_exists = lstat(temp_path, &local);

				if ((path_exists != -1) && (!S_ISDIR(local.st_mode)))
					errx(EXIT_FAILURE, "%s exists locally and is not a directory.", temp_path);

				if (path_exists == -1) {
					if (connection->verbosity)
						printf(" + %s\n", temp_path);

					if (mkdir(temp_path, 0755))
						err(EXIT_FAILURE, "Cannot create target directory");
				}

				/* Add a get-dir command to the command buffer. */

				length += path_source_length + 1;

				snprintf(next_command,
					BUFFER_UNIT,
					"( get-dir ( %zd:%s/%s ( %d ) false true ( kind size ) ) )\n",
					length,
					path_source,
					name,
					connection->revision
					);

				length = strlen(buffer[buffers]);
				strncat(buffer[buffers], next_command, COMMAND_BUFFER - length);

				buffer_commands[buffers]++;

				if (length > COMMAND_BUFFER_THRESHOLD)
					new_buffer(&buffer, &buffer_commands, &buffers);
			}

			item_start = item_end + 1;
		}

		start = end + 1;
	}

	/* Recursively process the command buffers. */

	x = 0;
	while (x <= buffers) {
		if (buffer_commands[x]) {
			connection->response_groups = 2 * buffer_commands[x];
			process_report_svn(connection, buffer[x], file, file_count, file_max);

			free(buffer[x]);
			buffer[x] = NULL;
		}

		x++;
	}

	if (buffer[0]) free(buffer[0]);
	free(buffer_commands);
	free(buffer);
}


/*
 * process_report_http
 *
 * Procedure that sends the http report command and saves the initial details
 * in a dynamic array of file_nodes.
 */

void
process_report_http(connector *connection, file_node ***file, int *file_count, int *file_max)
{
	int        x, revision_length;
	char      *start, *end, *temp, *value, *href, *path, *md5, *d;
	char       command[COMMAND_BUFFER + 1], temp_buffer[BUFFER_UNIT];
	file_node *this_file;

	connection->response_groups = 2;

	revision_length = 1;
	x = connection->revision;
	while ((int)(x /= 10) > 0)
		revision_length++;

	snprintf(command,
		COMMAND_BUFFER,
		"REPORT /%s/!svn/me HTTP/1.1\r\n"
		"Host: %s\r\n"
		"User-Agent: svnup-%s\r\n"
		"Content-Type: text/xml\r\n"
		"DAV: http://subversion.tigris.org/xmlns/dav/svn/depth\r\n"
		"DAV: http://subversion.tigris.org/xmlns/dav/svn/mergeinfo\r\n"
		"DAV: http://subversion.tigris.org/xmlns/dav/svn/log-revprops\r\n"
		"Transfer-Encoding: chunked\r\n\r\n"
		"%lx\r\n"
		"<S:update-report xmlns:S=\"svn:\">\n"
		"<S:src-path>/%s</S:src-path>\n"
		"<S:target-revision>%d</S:target-revision>\n"
		"<S:depth>unknown</S:depth>\n"
		"<S:entry rev=\"%d\" depth=\"infinity\" start-empty=\"true\"></S:entry>\n"
		"</S:update-report>\n"
		"\r\n0\r\n\r\n",
		connection->root,
		connection->address,
		SVNUP_VERSION,
		strlen(connection->branch) + revision_length + revision_length + 209,
		connection->branch,
		connection->revision,
		connection->revision
		);

	process_command_http(connection, command);

	/* Process response for subdirectories and create them locally. */

	start = connection->response;
	end   = connection->response + connection->response_length;

	while ((start = strstr(start, "<S:add-directory")) && (start < end)) {
		value = parse_xml_value(start, end, "D:href");
		temp = strstr(value, connection->trunk) + strlen(connection->trunk);

		snprintf(temp_buffer, BUFFER_UNIT, "%s%s", connection->path_target, temp);
		mkdir(temp_buffer, 0755);
		free(value);
		start++;
	}

	start = connection->response;

	while ((start = strstr(start, "<S:add-file")) && (start < end)) {
		md5  = parse_xml_value(start, end, "V:md5-checksum");
		href = parse_xml_value(start, end, "D:href");
		temp = strstr(href, connection->trunk);
		temp += strlen(connection->trunk);
		path = strdup(temp);

		/* Convert any hex encoded characters in the path. */

		d = path;
		while ((d = strchr(d, '%')) != NULL)
			if ((isxdigit(d[1])) && (isxdigit(d[2]))) {
				d[1] = toupper(d[1]);
				d[2] = toupper(d[2]);
				*d = ((isalpha(d[1]) ? 10 + d[1] -'A' : d[1] - '0') << 4) +
				      (isalpha(d[2]) ? 10 + d[2] -'A' : d[2] - '0');
				memmove(d + 1, d + 3, strlen(path) - (d - path + 2));
				d++;
			}

		this_file = new_file_node(file, file_count, file_max);
		this_file->href = href;
		this_file->path = path;
		memcpy(this_file->md5, md5, 32);

		start++;
	}
}


/*
 * parse_additional_attributes
 *
 * Procedure that extracts md5 signature plus last author, committed date
 * and committed rev and saves them for later inclusion in revision tags. 
 */

void
parse_additional_attributes(connector *connection, char *start, char *end, file_node *file)
{
	char  revision_tag[BUFFER_UNIT], *value, *temp, *md5;
	char *last_author, *last_author_end, *committed_date, *committed_date_end;
	char *committed_rev, *committed_rev_end, *getetag, *relative_path;

	last_author    = last_author_end    = NULL;
	committed_rev  = committed_rev_end  = NULL;
	committed_date = committed_date_end = NULL;

	if (connection->port == 3690)
		if ((temp = strchr(start, ':')) != NULL) {
			md5 = ++temp;
			memcpy(file->md5, md5, 32);

			file->executable = (strstr(start, "14:svn:executable") ? 1 : 0);
			file->special    = (strstr(start, "11:svn:special") ? 1 : 0);

			if ((temp = strstr(start, "last-author ")) != NULL) {
				last_author     = strchr(temp, ':') + 1;
				last_author_end = strchr(last_author, ' ');
			}

			if ((temp = strstr(start, "committed-rev ")) != NULL) {
				committed_rev     = strchr(temp, ':') + 1;
				committed_rev_end = strchr(committed_rev, ' ');
			}

			if ((temp = strstr(start, "committed-date ")) != NULL) {
				committed_date = strchr(temp, ':') + 1;
				temp = strchr(committed_date, 'T');
				*temp++ = ' ';
				temp = strchr(committed_date, '.');
				*temp++ = 'Z';
				committed_date_end = temp;
			}

			if ((last_author) && (committed_rev) && (committed_date)) {
				*last_author_end    = '\0';
				*committed_rev_end  = '\0';
				*committed_date_end = '\0';

				snprintf(revision_tag,
					BUFFER_UNIT,
					": %s%s %s %s %s ",
					connection->branch,
					file->path,
					committed_rev,
					committed_date,
					last_author
					);
			}
		}

	if ((connection->port == 80) || (connection->port == 443)) {
		value = parse_xml_value(start, end, "lp1:getcontentlength");
		file->size = strtol(value, (char **)NULL, 10);
		free(value);

		file->executable = (strstr(start, "<S:executable/>") ? 1 : 0);
		file->special    = (strstr(start, "<S:special>*</S:special>") ? 1 : 0);

		last_author    = parse_xml_value(start, end, "lp1:creator-displayname");
		committed_date = parse_xml_value(start, end, "lp1:creationdate");
		committed_rev  = parse_xml_value(start, end, "lp1:version-name");
		getetag        = parse_xml_value(start, end, "lp1:getetag");

		relative_path = strstr(getetag, "//") + 2;
		relative_path[strlen(relative_path) - 1] = '\0';

		if ((temp = strchr(committed_date, '.')) != NULL) {
			*temp++ = 'Z';
			*temp = '\0';
		}

		if ((temp = strchr(committed_date, 'T')) != NULL) *temp = ' ';

		snprintf(revision_tag,
			BUFFER_UNIT,
			": %s/%s %s %s %s ",
			connection->root,
			relative_path,
			committed_rev,
			committed_date,
			last_author
			);

		free(last_author);
		free(committed_rev);
		free(committed_date);
		free(getetag);
	}

	file->revision_tag = strdup(revision_tag);
}


/*
 * get_files
 *
 * Procedure that extracts and saves files from the response stream.
 */

void
get_files(connector *connection, char *command, char *path_target, file_node **file, int file_start, int file_end)
{
	int     x, offset, position, block_size_markers, file_block_remainder;
	int     raw_size, first_response, last_response, block_size, try;
	char   *start, *end, *gap, *md5_check, *begin, *temp_end, file_path_target[BUFFER_UNIT];
	MD5_CTX md5_context;

	/* Calculate the number of bytes the server is going to send back. */

	try = 0;
	retry:

	raw_size = 0;

	if ((connection->port == 80) || (connection->port == 443)) {
		process_command_http(connection, command);

		start = connection->response;

		for (x = file_start; x <= file_end; x++) {
			if ((file[x] == NULL) || (file[x]->download == 0)) continue;

			end = strstr(start, "\r\n\r\n") + 4;
			file[x]->raw_size = file[x]->size + (end - start);
			start = end + file[x]->size;
			raw_size += file[x]->raw_size;
		}
	}

	if (connection->port == 3690) {
		last_response  = 20;
		first_response = 84;

		x = connection->revision;
		while ((int)(x /= 10) > 0) first_response++;

		for (x = file_start; x <= file_end; x++) {
			if ((file[x] == NULL) || (file[x]->download == 0)) continue;

			block_size_markers = 6 * (int)(file[x]->size / BUFFER_UNIT);
			if (file[x]->size % BUFFER_UNIT) block_size_markers += 3;

			file_block_remainder = file[x]->size % BUFFER_UNIT;
			while ((int)(file_block_remainder /= 10) > 0) block_size_markers++;

			file[x]->raw_size = file[x]->size +
				first_response +
				last_response +
				block_size_markers;

			raw_size += file[x]->raw_size;
		}

		process_command_svn(connection, command, raw_size);
	}

	position = raw_size;

	for (x = file_end; x >= file_start; x--) {
		if (file[x]->download == 0) continue;

		snprintf(file_path_target,
			BUFFER_UNIT,
			"%s%s",
			path_target,
			file[x]->path
			);

		/* Extract the file from the response stream. */

		end = connection->response + position;
		start = end - file[x]->raw_size;
		begin = end - file[x]->size;
		temp_end = end;

		if (check_command_success(connection->port, &start, &temp_end)) {
			try++;
			if (try > 5) errx(EXIT_FAILURE, "Error in get_files.  Quitting.");
			if (try > 1) fprintf(stderr, "Error in get files, retry #%d\n", try);
			goto retry;
		}

		if (connection->port == 3690) {
			start = find_response_end(connection->port, start, temp_end) + 1;
			begin = strchr(start, ':') + 1;
			block_size = strtol(start, (char **)NULL, 10);
			offset = 0;
			start = begin;

			while (block_size == BUFFER_UNIT) {
				start += block_size + offset;
				gap = start;
				start = strchr(gap, ':') + 1;
				block_size = strtol(gap, (char **)NULL, 10);
				memmove(gap, start, file[x]->raw_size - (start - begin) + 1);
				offset = gap - start;
			}
		}

		/*
		 * Check to make sure the MD5 signature of the file in the buffer
		 * matches what the svn server originally reported.
		 */

		MD5Init(&md5_context);
		MD5Update(&md5_context, begin, file[x]->size);
		md5_check = MD5End(&md5_context, NULL);

		if (connection->verbosity)
			printf(" + %s\n", file_path_target);

		/* Make sure the MD5 checksums match before saving the file. */

		save_file(file_path_target,
			file[x]->revision_tag,
			begin,
			begin + file[x]->size,
			file[x]->executable,
			file[x]->special
			);

		if (strncmp(file[x]->md5, md5_check, 33) != 0) {
			begin[file[x]->size] = '\0';
			errx(EXIT_FAILURE, "MD5 checksum mismatch: should be %s, calculated %s\n", file[x]->md5, md5_check);
		}

		position -= file[x]->raw_size;
		bzero(connection->response + position, file[x]->raw_size);

		free(md5_check);
	}
}


/*
 * usage
 *
 * Procedure that prints a summary of command line options and exits.
 */

void
usage(char *configuration_file)
{
	fprintf(stderr, "Usage: svnup <section> [options]\n\n");
	fprintf(stderr, "  Please see %s for the list of <section> options.\n\n", configuration_file);
	fprintf(stderr, "  Options:\n");
	fprintf(stderr, "    -4  Use IPv4 addresses only.\n");
	fprintf(stderr, "    -6  Use IPv6 addresses only.\n");
	fprintf(stderr, "    -b  Override the specified section's Subversion branch.\n");
	fprintf(stderr, "    -h  Override the specified section's hostname or IP address.\n");
	fprintf(stderr, "    -l  Override the specified section's destination directory.\n");
	fprintf(stderr, "    -n  Display the section's most recently downloaded revision number and exit.\n");
	fprintf(stderr, "    -r  The revision number to retreive (defaults to the branch's\n");
	fprintf(stderr, "          most recent revision if this option is not specified).\n");
	fprintf(stderr, "    -v  How verbose the output should be (0 = no output, 1 = the\n");
	fprintf(stderr, "          default normal output, 2 = also show command and response\n");
	fprintf(stderr, "          text, 3 = also show command response parsing codes).\n");
	fprintf(stderr, "    -V  Display svnup's version number and exit.\n");
	fprintf(stderr, "\n");

	exit(EXIT_FAILURE);
}


/*
 * main
 *
 */

int
main(int argc, char **argv)
{
	char *start, *end, *value, *path, *md5, command[COMMAND_BUFFER + 1];
	char  temp_buffer[BUFFER_UNIT], **buffer, *configuration_file;
	int   option, x, fd, file_count, file_max, length, command_count;
	int   buffers, *buffer_commands, buffer_full, b, f, c, f0, display_last_revision;

	struct stat local;
	struct tree_node *data = NULL;
	file_node **file = NULL;
	connector connection;

	buffers = -1;
	buffer = NULL;
	buffer_commands = NULL;
	new_buffer(&buffer, &buffer_commands, &buffers);

	display_last_revision = file_count = command_count = 0;
	buffer_full = length = f = f0 = 0;

	configuration_file = strdup("/usr/local/etc/svnup.conf");

	file_max = BUFFER_UNIT;

	if ((file = (file_node **)malloc(file_max * sizeof(file_node **))) == NULL)
		err(EXIT_FAILURE, "process_directory source malloc");

	command[0] = '\0';

	connection.address = connection.branch = connection.path_target = NULL;
	connection.path_work = connection.known_files = NULL;
	connection.known_files_old = connection.known_files_new = NULL;
	connection.ssl = NULL;
	connection.ctx = NULL;
	connection.socket_descriptor = connection.port = connection.known_files_size = 0;
	connection.verbosity = 1;
	connection.family = AF_INET;

	if (argc < 2) usage(configuration_file);

	if (argv[1][0] == '-') {
		if (argv[1][1] == 'V') {
			fprintf(stdout, "svnup version %s\n", SVNUP_VERSION);
			exit(0);
			}
		else usage(configuration_file);
	} else {
		if (strncmp(argv[1], "default", 7) == 0)
			errx(EXIT_FAILURE, "Invalid section.  Please use one defined in svnup.conf.");

		load_configuration(&connection, configuration_file, argv[1]);
		optind = 2;
	}

	while ((option = getopt(argc, argv, "46b:h:l:nr:v")) != -1) {
		switch (option) {
			case '4': connection.family = AF_INET;  break;
			case '6': connection.family = AF_INET6; break;
			case 'b':
				x = (optarg[0] == '/' ? 1 : 0);
				connection.branch = (char *)malloc(strlen(optarg) - x + 1);
				memcpy(connection.branch, optarg + x, strlen(optarg) - x + 1);
				break;
			case 'h':
				connection.address = strdup(optarg);
				break;
			case 'l':
				connection.path_target = realloc(connection.path_target, strlen(optarg) + 2);
				snprintf(connection.path_target, strlen(optarg) + 1, "%s", optarg);
				break;
			case 'n':
				display_last_revision = 1;
				break;
			case 'r':
				connection.revision = strtol(optarg, (char **)NULL, 10);
				break;
			case 'v':
				connection.verbosity = strtol(optarg, (char **)NULL, 10);
				break;
		}
	}

	if (connection.path_work == NULL)
		if ((connection.path_work = strdup("/var/db/svnup")) == NULL)
			errx(EXIT_FAILURE, "Cannot set connection.path_work");

	if (connection.address == NULL)
		errx(EXIT_FAILURE, "\nNo mirror specified.  Please uncomment the preferred SVN mirror in %s.\n\n", configuration_file);

	if ((connection.branch == NULL) || (connection.path_target == NULL)) usage(configuration_file);

	value = strchr(connection.branch + (*connection.branch == '/' ? 1 : 0), '/');
	length = value - connection.branch;

	if ((connection.root = (char *)malloc(length + 1)) == NULL)
		err(EXIT_FAILURE, "main connection.root alloc");

	bzero(connection.root, length + 1);
	memcpy(connection.root, value - length, length);

	if ((connection.trunk = (char *)malloc(strlen(connection.branch) - length + 1)) == NULL)
		err(EXIT_FAILURE, "main connection.root alloc");

	bzero(connection.trunk, strlen(connection.branch) - length + 1);
	memcpy(connection.trunk, connection.branch + length + 1, strlen(connection.branch) - length);

	/* Create the destination directories if they doesn't exist. */

	create_directory(connection.path_work);
	create_directory(connection.path_target);

	/* Load the list of known files and MD5 signatures, if they exist. */

	length = strlen(connection.path_work) + MAXNAMLEN;

	connection.known_files_old = (char *)malloc(length);
	connection.known_files_new = (char *)malloc(length);

	snprintf(connection.known_files_old, length, "%s/%s", connection.path_work, argv[1]);
	snprintf(connection.known_files_new, length, "%s/%s.new", connection.path_work, argv[1]);

	if (lstat(connection.known_files_old, &local) != -1) {
		connection.known_files_size = local.st_size;
		if ((connection.known_files = (char *)malloc(connection.known_files_size + 1)) == NULL)
			err(EXIT_FAILURE, "main connection.known_files malloc");

		if ((fd = open(connection.known_files_old, O_RDONLY)) == -1)
			err(EXIT_FAILURE, "open file (%s)", connection.known_files_old);

		if (read(fd, connection.known_files, connection.known_files_size) != connection.known_files_size)
			err(EXIT_FAILURE, "read file error (%s)", connection.known_files_old);

		connection.known_files[connection.known_files_size] = '\0';
		close(fd);

		if ((value = strstr(connection.known_files, "\r\n"))) {
			value += 2;

			if (display_last_revision) {
				printf("%ld\n", strtol(connection.known_files, (char **)NULL, 10));
				exit(0);
			}
		} else value = connection.known_files;

		while (*value) {
			md5 = value;
			path = strchr(value, '\t') + 1;
			value = strchr(path, '\n');
			*value++ = '\0';
			md5[32] = '\0';
			data = (struct tree_node *)malloc(sizeof(struct tree_node));
			data->path = path;
			data->md5 = md5;
			RB_INSERT(rbtree, &known_files, data);
		}
	}

	/* Initialize connection with the server and get the latest revision number. */

	connection.response_blocks = 10240;
	connection.response_length = connection.revision = 0;

	if ((connection.response = (char *)malloc(connection.response_blocks * BUFFER_UNIT + 1)) == NULL)
		err(EXIT_FAILURE, "main connection.response malloc");

	reset_connection(&connection);

	/* Send initial response string. */

	if (connection.port == 3690) {
		connection.response_groups = 1;
		process_command_svn(&connection, "", 0);

		snprintf(command,
			COMMAND_BUFFER,
			"( 2 ( edit-pipeline svndiff1 absent-entries commit-revprops depth log-revprops atomic-revprops partial-replay ) %ld:svn://%s/%s 10:svnup-%s ( ) )\n",
			strlen(connection.address) + strlen(connection.branch) + 7,
			connection.address,
			connection.branch,
			SVNUP_VERSION
			);

		process_command_svn(&connection, command, 0);

		start = connection.response;
		end = connection.response + connection.response_length;
		check_command_success(connection.port, &start, &end);

		/* Login anonymously. */

		connection.response_groups = 2;
		process_command_svn(&connection, "( ANONYMOUS ( 0: ) )\n", 0);

		/* Get latest revision number. */

		if (connection.revision <= 0) {
			process_command_svn(&connection, "( get-latest-rev ( ) )\n", 0);

			start = connection.response;
			end = connection.response + connection.response_length;
			check_command_success(connection.port, &start, &end);

			if ((start != NULL) && (start == strstr(start, "( success ( "))) {
				start += 12;
				value = start;
				while (*start != ' ') start++;
				*start = '\0';

				connection.revision = strtol(value, (char **)NULL, 10);
			} else errx(EXIT_FAILURE, "Cannot retrieve latest revision.");
		}

		/* Check to make sure client-supplied remote path is a directory. */

		snprintf(command,
			COMMAND_BUFFER,
			"( check-path ( 0: ( %d ) ) )\n",
			connection.revision
			);
		process_command_svn(&connection, command, 0);

		if ((strcmp(connection.response, "( success ( ( ) 0: ) )") != 0) &&
		    (strcmp(connection.response + 23, "( success ( dir ) ) ") != 0))
			errx(EXIT_FAILURE,
				"Remote path %s is not a repository directory.\n%s",
				connection.branch,
				connection.response
				);
		}

	if ((connection.port == 80) || (connection.port == 443)) {
		connection.response_groups = 2;

		/* Get the latest revision number. */

		if (connection.revision <= 0) {
			snprintf(command,
				COMMAND_BUFFER,
				"OPTIONS /%s HTTP/1.1\r\n"
				"Host: %s\r\n"
				"User-Agent: svnup-%s\r\n"
				"Content-Type: text/xml\r\n"
				"DAV: http://subversion.tigris.org/xmlns/dav/svn/depth\r\n"
				"DAV: http://subversion.tigris.org/xmlns/dav/svn/mergeinfo\r\n"
				"DAV: http://subversion.tigris.org/xmlns/dav/svn/log-revprops\r\n"
				"Transfer-Encoding: chunked\r\n\r\n"
				"83\r\n"
				"<?xml version=\"1.0\" encoding=\"utf-8\"?>"
				"<D:options xmlns:D=\"DAV:\">"
				"<D:activity-collection-set></D:activity-collection-set>"
				"</D:options>\r\n"
				"0\r\n\r\n",
				connection.branch,
				connection.address,
				SVNUP_VERSION
				);

			process_command_http(&connection, command);

			if ((value = strstr(connection.response, "SVN-Youngest-Rev: ")) == NULL)
				errx(EXIT_FAILURE, "Cannot find revision number.");
			else
				connection.revision = strtol(value + 18, (char **)NULL, 10);
		}
	}

	if (connection.verbosity) printf("Fetching revision: %d\n", connection.revision);

	if (connection.port == 3690) {
		connection.response_groups = 2;

		snprintf(command,
			COMMAND_BUFFER,
			"( get-dir ( 0: ( %d ) false true ( kind size ) ) )\n",
			connection.revision
			);

		process_report_svn(&connection, command, &file, &file_count, &file_max);
	}

	if ((connection.port == 80) || (connection.port == 443))
		process_report_http(&connection, &file, &file_count, &file_max);

	/* Get additional file information not contained in the first report. */

	for (f = 0; f < file_count; f++) {
		if (connection.port == 3690)
			snprintf(temp_buffer,
				BUFFER_UNIT,
				"( get-file ( %zd:%s ( %d ) true false ) )\n",
				strlen(file[f]->path),
				file[f]->path,
				connection.revision
				);

		if ((connection.port == 80) || (connection.port == 443))
			snprintf(temp_buffer,
				BUFFER_UNIT,
				"PROPFIND %s HTTP/1.1\n"
				"Depth: 1\n"
				"Host: %s\n\n",
				file[f]->href,
				connection.address
				);

		length += strlen(temp_buffer);
		strncat(buffer[buffers], temp_buffer, COMMAND_BUFFER - length);
		buffer_commands[buffers]++;

		if (((connection.port == 80) || (connection.port == 443)) && (buffer_commands[buffers] > 95))
			buffer_full = 1;

		if ((connection.port == 3690) && (length > COMMAND_BUFFER_THRESHOLD))
			buffer_full = 1;

		if (buffer_full) {
			new_buffer(&buffer, &buffer_commands, &buffers);
			buffer_full = length = 0;
		}
	}

	for (f = 0, f0 = 0, b = 0; b <= buffers; b++) {
		if (buffer_commands[b] == 0) break;

		connection.response_groups = buffer_commands[b] * 2;
		if (connection.port == 80)   process_command_http(&connection, buffer[b]);
		if (connection.port == 443)  process_command_http(&connection, buffer[b]);
		if (connection.port == 3690) process_command_svn(&connection, buffer[b], 0);

		start = connection.response;
		end = start + connection.response_length;

		command[0] = '\0';
		connection.response_groups = 0;

		for (length = 0, c = 0; c < buffer_commands[b]; c++) {
			check_command_success(connection.port, &start, &end);

			if ((connection.port == 80) || (connection.port == 443))
				parse_response_group(&connection, &start, &end);

			if (connection.port == 3690)
				end = strchr(start, '\0');

			parse_additional_attributes(&connection, start, end, file[f]);

			snprintf(temp_buffer,
				BUFFER_UNIT,
				"%s%s",
				connection.path_target,
				file[f]->path
				);

			if (confirm_md5(file[f]->md5, temp_buffer)) {
				file[f]->download = 1;
				connection.response_groups += 2;

				if ((connection.port == 80) || (connection.port == 443))
					snprintf(temp_buffer,
						BUFFER_UNIT,
						"GET %s HTTP/1.1\n"
						"Host: %s\n"
						"Connection: Keep-Alive\n\n",
						file[f]->href,
						connection.address
						);

				if (connection.port == 3690)
					snprintf(temp_buffer,
						BUFFER_UNIT,
						"( get-file ( %zd:%s ( %d ) false true ) )\n",
						strlen(file[f]->path),
						file[f]->path,
						connection.revision
						);

				length += strlen(temp_buffer);

				strncat(command, temp_buffer, COMMAND_BUFFER - length);
			}

			start = end + 1;
			f++;
		}

		if (connection.response_groups)
			get_files(&connection,
				command,
				connection.path_target,
				file,
				f0,
				f - 1
				);

		f0 = f;
	}

	save_known_file_list(&connection, file, file_count);

	/* Any files left in the tree are safe to delete. */

	RB_FOREACH(data, rbtree, &known_files) prune(&connection, data->path);

	/* Wrap it all up. */

	if (close(connection.socket_descriptor) != 0)
		if (errno != EBADF) err(EXIT_FAILURE, "close connection failed");

	remove(connection.known_files_old);

	if ((rename(connection.known_files_new, connection.known_files_old)) != 0)
		err(EXIT_FAILURE, "Cannot rename %s", connection.known_files_old);

	free(connection.known_files_old);
	free(connection.known_files_new);
	free(connection.response);
	if (connection.address) free(connection.address);
	if (connection.root) free(connection.root);
	if (connection.trunk) free(connection.trunk);
	if (connection.branch) free(connection.branch);
	if (connection.known_files) free(connection.known_files);
	if (connection.path_target) free(connection.path_target);
	if (connection.path_work) free(connection.path_work);
	if (connection.ssl) {
		SSL_shutdown(connection.ssl);
		SSL_CTX_free(connection.ctx);
		SSL_free(connection.ssl);
	}

	free(file);

	return (0);
}
