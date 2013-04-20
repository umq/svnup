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

#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/ssl3.h>

#include <ctype.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#ifdef OPENSSL
#include <openssl/md5.h>
#else
#include <md5.h>
#endif
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SVNUP_VERSION "0.63"
#define BUFFER_UNIT 4096
#define COMMAND_BUFFER 32768
#define COMMAND_BUFFER_THRESHOLD 32000
#ifdef OPENSSL
#define MD5Init MD5_Init
#define MD5Update MD5_Update
#endif

static char twirly[4] = { '|', '/', '-', '\\' };

typedef struct {
	int            socket_descriptor;
	SSL           *ssl;
	SSL_CTX       *ctx;
	char          *address;
	unsigned short port;
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
	char          *data;
	size_t         data_size;
	char          *data_file_old;
	char          *data_file_new;
	int            verbosity;
	} connector;


typedef struct {
	char          *href;
	char          *path;
	char          *md5;
	char           exists;
	unsigned long  size;
	unsigned long  raw_size;
	char           executable;
	char           special;
	char          *revision_tag;
	} file_node;


typedef struct tree {
	char *path;
	char *md5;
	int   depth_left;
	int   depth_right;
	struct tree *parent;
	struct tree *left;
	struct tree *right;
	} tree_node;


/* Function Prototypes */

void  print_tree(tree_node *me);
void  prune(connector *connection, char *path_target);
void  prune_tree(connector *connection, tree_node *me, int depth);
void  adjust_tree_depth(tree_node *me);
void  adjust_tree_node(tree_node **head, tree_node *node, tree_node *new_node);
tree_node *locate_tree_node(tree_node *head, char *search);
void  balance_tree(tree_node **head, tree_node *node);
void  delete_tree_node(tree_node **head, char *key);
void  insert_tree_node(tree_node **head, char *path, char *md5);
char *find_response_end(unsigned short port, char *start, char *end);
char *terminate_response(unsigned short port, char *start, char *end);
void  send_command(connector *connection, const char *command);
void  check_command_success(unsigned short port, char **start, char **end);
char *process_command_svn(connector *connection, const char *command);
char *process_command_http(connector *connection, char *command);
void  extract_directory_name(connector *connection, char *raw, char *path_source);
int   entry_is_file(connector *connection, char *start, char *end);
int   entry_is_directory(connector *connection, char *start, char *end);
file_node *process_file_entry(connector *connection, char *path_source, char *start, char *end);
void  parse_response_group(connector *connection, char **start, char **end);
int   parse_response_item(connector *connection, char *start, char *end, int *count, char **item_start, char **item_end);
void  build_source_directory_tree_svn(connector *connection, char *command, file_node ***file, int *file_count, int *max_file, char *path_target, int revision);
void  get_files_http(connector *connection, char *command, tree_node **tree);
void  process_file_attributes_svn(connector *connection, char *command, file_node **file, int file_start, int file_end, char *path_target);
int   confirm_md5(char *md5, char *path_target);
void  save_file(char *filename, char *revision_tag, char *start, char *end, int executable, int special);
void  get_files_svn(connector *connection, char *command, char *path_target, file_node **file, int file_start, int file_end, int revision);
void  reset_connection(connector *connection);
void  set_configuration_parameters(connector *connection, char *buffer, size_t length, const char *section);
void  load_configuration(connector *connection, char *configuration_file, char *section);
void  usage(void);
#ifdef OPENSSL
char *MD5End(MD5_CTX *ctx, char *buf);


char *MD5End(MD5_CTX *ctx, char *buf)	{
	int i;
	unsigned char digest[MD5_DIGEST_LENGTH];
	static const char hex[]="0123456789abcdef";

	if (!buf)
		buf = malloc(2*MD5_DIGEST_LENGTH + 1);
	if (!buf)
		return 0;
	MD5_Final(digest, ctx);
	for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
		buf[i+i] = hex[digest[i] >> 4];
		buf[i+i+1] = hex[digest[i] & 0x0f];
		}
	buf[i+i] = '\0';
	return buf;
	}
#endif


/*
 * prune
 *
 * Procedure that recursively removes the file or directory tree passed in.
 *
 */

void prune(connector *connection, char *path_target) {
	char          *check, *temp_file, ok;
	size_t         length;
	DIR           *dp;
	struct stat    local;
	struct dirent *de;

	length = strlen(path_target) + strlen(connection->path_target) + 2;

	if ((temp_file = (char *)malloc(length)) == NULL)
		err(EXIT_FAILURE, "prune temp_file malloc");

	snprintf(temp_file, length, "%s%s", connection->path_target, path_target);

	lstat(temp_file, &local);

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

				//prune(connection, temp_file);
				}

			closedir(dp);

			if ((rmdir(temp_file)) != 0)
				err(EXIT_FAILURE, "Cannot remove %s", temp_file);
			}

	free(temp_file);
	}


/*
 * prune_tree
 *
 * Procedure that recursively removes the files contained in a tree.
 *
 */

void prune_tree(connector *connection, tree_node *me, int depth) {
	if (me) {
		if (me->left)  prune_tree(connection, me->left,  depth + 1);
		if (me->right) prune_tree(connection, me->right, depth + 1);

		prune(connection, me->path);
		free(me);
		}
	}


/*
 * print_tree
 *
 * Procedure that recursively prints the files contained in a tree.
 *
 */

void print_tree(tree_node *me) {
	if (me) {
		if (me->left) print_tree(me->left);
		fprintf(stdout, "%s %s\n", me->md5, me->path);
		if (me->right) print_tree(me->right);
		}
	}


/*
 * adjust_tree_depth
 *
 * Procedure that calculates the depth of a node in a tree.
 *
 */

void adjust_tree_depth(tree_node *me) {
	int ld, rd;

	if (me) {
		if (me->left) {
			ld = (me->left)->depth_left  + 1;
			rd = (me->left)->depth_right + 1;
			me->depth_left = (ld > rd ? ld : rd);
			}
		else me->depth_left = 0;

		if (me->right) {
			ld = (me->right)->depth_left  + 1;
			rd = (me->right)->depth_right + 1;
			me->depth_right = ld > rd ? ld : rd;
			}
		else me->depth_right = 0;
		}
	}


/*
 * adjust_tree_node
 *
 * Procedure that fixes parent/child links in a tree.
 *
 */

void adjust_tree_node(tree_node **head, tree_node *node, tree_node *new_node) {
	if (*head == node) {
		*head = new_node;
		if (new_node) new_node->parent = NULL;
		}
	else {
		if (new_node) new_node->parent = node->parent;

		if (node->parent->left == node) node->parent->left = new_node;
		else node->parent->right = new_node;
		}
	}


/*
 * locate_tree_node
 *
 * Procedure that recursively traverses a tree looking for a specific node.
 *
 */

tree_node *locate_tree_node(tree_node *node, char *search) {
	int  compare;

	while (node) {
		compare = strcmp(search, node->path);

		if (compare < 0)  node = node->left;
		if (compare == 0) return (node);
		if (compare > 0)  node = node->right;
		}

	return (NULL);
	}


/*
 * balance_tree
 *
 * Procedure that rebalances a tree if the depth of one side is two greater than the other.
 *
 */

void balance_tree(tree_node **head, tree_node *node) {
	tree_node  *new_node, *new_left, *new_right;
	int         lcount, rcount;

	new_node = new_left = new_right = NULL;

	lcount = node->depth_left;
	rcount = node->depth_right;

	if (lcount > rcount) {
		lcount = node->left->depth_left;
		rcount = node->left->depth_right;

		if (lcount > rcount) {
			new_node = node->left;
			new_right = node;

			adjust_tree_node(head, node, new_node);

			new_right->left = new_node->right;
			if (new_node->right) new_node->right->parent = new_right;

			new_node->right = new_right;
			new_right->parent = new_node;
			}
		else {
			new_node = node->left->right;
			new_left = node->left;
			new_right = node;

			if (new_node) {
				adjust_tree_node(head, node, new_node);

				new_left->right = new_node->left;
				if (new_node->left) new_node->left->parent = new_left;

				new_right->left = new_node->right;
				if (new_node->right) new_node->right->parent = new_right;

				new_node->left = new_left;
				new_left->parent = new_node;

				new_node->right = new_right;
				new_right->parent = new_node;
				}
			}
		}
	else {
		lcount = node->right->depth_left;
		rcount = node->right->depth_right;

		if (lcount > rcount) {
			new_node = (node->right)->left;
			new_right = node->right;
			new_left = node;

			if (new_node) {
				adjust_tree_node(head, node, new_node);

				new_left->right = new_node->left;
				if (new_node->left) new_node->left->parent = new_left;

				new_right->left = new_node->right;
				if (new_node->right) new_node->right->parent = new_right;

				new_node->left = new_left;
				new_left->parent = new_node;

				new_node->right = new_right;
				new_right->parent = new_node;
				}
			}
		else {
			new_node = node->right;
			new_left = node;

			adjust_tree_node(head, node, new_node);

			new_left->right = new_node->left;
			if (new_node->left) new_node->left->parent = new_left;

			new_node->left = new_left;
			new_left->parent = new_node;
			}
		}

	adjust_tree_depth(new_left);
	adjust_tree_depth(new_right);
	adjust_tree_depth(new_node);
	}


/*
 * delete_tree_node
 *
 * Procedure that removes a node and rebalances the tree if necessary.
 *
 */

void delete_tree_node(tree_node **head, char *key) {
	int         difference, compare;
	tree_node  *node, *parent, *new_node, *me;

	if (*head) {
		node = locate_tree_node(*head, key);

		if (node) {
			parent = node->parent;

			if ((node->left == NULL) && (node->right == NULL)) {
				if (parent) {
					if (parent->left == node) parent->left = NULL;
					else parent->right = NULL;
					me = parent;
					}
				else { me = *head = NULL; }
				}
			else {
				new_node = NULL;

				if (node->right) {
					new_node = node->right;
					while (new_node->left) new_node = new_node->left;
					}
				else {
					if (node->left) {
						new_node = node->left;
						while (new_node->right) new_node = new_node->right;
						}
					}

				if (node->left != new_node) {
					new_node->left = node->left;
					if (node->left) new_node->left->parent = new_node;
					else new_node->left = NULL;
					}

				if (node->right != new_node) {
					new_node->right = node->right;
					if (node->right) new_node->right->parent = new_node;
					else new_node->right = NULL;
					}

				adjust_tree_node(head, new_node, NULL);
				adjust_tree_node(head, node, new_node);
				me = new_node;
				}

			if ((node == *head) && (node->left == NULL) && (node->right == NULL))
				head = NULL;

			while (me) {
				adjust_tree_depth(me);
				if (abs(me->depth_left - me->depth_right) > 1) balance_tree(head, me);
				me = me->parent;
				}

			free(node);
			}
		}
	}


/*
 * insert_tree_node
 *
 * Procedure that adds a node and rebalances the tree if necessary.
 *
 */

void insert_tree_node(tree_node **head, char *path, char *md5) {
	int         compare;
	tree_node  *new, *me, *last;

	if ((new = (tree_node *)malloc(sizeof(tree_node))) == NULL)
		err(EXIT_FAILURE, "insert_tree malloc");

	me = *head;

	new->path = path;
	new->md5 = md5;
	new->parent = new->left = new->right = NULL;
	new->depth_right = new->depth_left = 0;

	if (*head == NULL) *head = new;
	else {
		while (me) {
			last = me;
			compare = strcmp(path, me->path);

			if (compare < 0)  me = me->left;
			if (compare > 0)  me = me->right;
			if (compare == 0)
				err(EXIT_FAILURE, "Duplicate path %s", path);
			}

		new->parent = last;
		(compare < 0) ? (last->left = new) : (last->right = new);

		me = last;
		while (me) {
			adjust_tree_depth(me);
			if (abs(me->depth_left - me->depth_right) > 1)
				balance_tree(head, me);

			me = me->parent;
			}
		}
	}


/*
 * find_response_end
 *
 * Function that counts opening and closing parenthesis of a command's response in
 * order to find the end of the response.
 *
 */

char *find_response_end(unsigned short port, char *start, char *end) {
	int count = 0;

	if (port == 3690) {
		do {
			count += (*start == '(' ? 1 : (*start == ')' ? -1 : 0));
			}
		while ((*start != '\0') && (start++ < end) && (count > 0));
		}

	if ((port == 80) || (port == 443))
		start = strstr(start, "\r\n\r\n") + 4;

	return (start);
	}


/*
 * terminate_response
 *
 * Function that puts a null character at the end of a command's response.
 *
 */

char *terminate_response(unsigned short port, char *start, char *end) {
	end = find_response_end(port, start, end);
	*end = '\0';

	return (end);
	}


/*
 * send_command
 *
 * Procedure that sends commands to the http/svn server.
 *
 */

void send_command(connector *connection, const char *command) {
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
 *
 */

void check_command_success(unsigned short port, char **start, char **end) {
	int  ok = 1;

	if (port == 3690) {
		if (*start[0] == '\n') start++;
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

	if (!ok) errx(EXIT_FAILURE, "Command failure: %s\n", *start);
	}


/*
 * process_command_svn
 *
 * Function that sends a command set to the svn server and parses its response to make
 * sure that the expected number of response strings have been received.
 *
 */

char *process_command_svn(connector *connection, const char *command) {
	int           bytes_read, ok, count, position;
	unsigned int  group;
	char          input[BUFFER_UNIT + 1], *check;

	send_command(connection, command);

	count = position = ok = group = connection->response_length = 0;
	check = connection->response;

	do {
		bzero(input, BUFFER_UNIT + 1);

		bytes_read = -1;
		while (bytes_read == -1)
			bytes_read = read(
				connection->socket_descriptor,
				input,
				BUFFER_UNIT
				);

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

		if ((input[0] == ' ') && (input[1] == '\0')) {
			connection->response[position++] = '\n';
			continue;
			}

		if (connection->verbosity > 3)
			fprintf(stdout, "==========\n>> Response Parse:\n");

		check = input;
		if ((count == 0) && (input[0] == ' ')) *check++ = '\n';

		do {
			count += (*check == '(' ? 1 : (*check == ')' ? -1 : 0));

			if (connection->verbosity > 3) fprintf(stderr, "%d", count);

			if (count == 0) {
				group++;
				check++;
				*check = '\n';
				}
			}
		while (++check < input + bytes_read);

		memcpy(connection->response + position, input, bytes_read + 1);
		position += bytes_read;

		if (connection->verbosity > 3)
			fprintf(stderr, ". = %d %d\n", group, connection->response_groups);

		if (group == connection->response_groups) ok = 1;
		}
	while (!ok);

	if (connection->verbosity > 2)
		fprintf(stdout, "==========\n>> Response:\n%s", connection->response);

	connection->response[position] = '\0';

	return (connection->response);
	}


/*
 * process_command_http
 *
 * Function that sends a command set to the http server and parses its response to make
 * sure that the expected number of response bytes have been received.
 *
 */

char *process_command_http(connector *connection, char *command) {
	int   bytes_read, chunk, offset, groups, gap, chunked_transfer;
	int   spread, read_more;
	char *begin, *end, *marker1, *marker2, *temp, input[BUFFER_UNIT + 1];

	bytes_read = chunked_transfer = -1;
	connection->response_length = chunk = offset = groups = 0;
	gap = spread = offset = read_more = 0;
	begin = end = marker1 = marker2 = temp = NULL;

	bzero(connection->response, connection->response_blocks * BUFFER_UNIT + 1);
	bzero(input, BUFFER_UNIT + 1);

	reset_connection(connection);
	send_command(connection, command);

	while (groups < connection->response_groups) {
		spread = connection->response_length - offset;

		if (spread <= 0) read_more = 1;
		if ((chunked_transfer == 1) && (spread <= 5)) read_more = 1;
		if ((chunked_transfer == 0) && (spread == 0) && (connection->response_groups - groups == 1)) break;

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
				connection->response = (char *)realloc(connection->response, connection->response_blocks * BUFFER_UNIT + 1);

				if (connection->response == NULL)
					err(EXIT_FAILURE, "process_command_svn realloc");
				}

			if (bytes_read == 0)
				errx(EXIT_FAILURE, "process_command_http: No bytes left to read.");

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
			if ((begin = strstr(begin, "HTTP/1.1 20")) == NULL) { read_more = 1; continue; }
			if ((end = strstr(begin, "\r\n\r\n")) == NULL) { read_more = 1; continue; }
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
				//chunked_transfer = -1;
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
			fprintf(stderr, "\rBytes read: %zd, Bytes expected: %d", connection->response_length, offset);
		}

	if (connection->verbosity > 2) fprintf(stderr, "\n");

	if (connection->verbosity > 3)
		fprintf(stdout, "==========\n%s\n==========\n", connection->response);

	return (connection->response);
	}


/*
 * extract_directory_name_svn
 *
 * Function that parses a command for the directory.
 *
 */

void extract_directory_name_svn(connector *connection, char *raw, char *path_source) {
	char   *value;
	size_t  length;

	if (strstr(raw, "( get-dir ( ") != raw)
		errx(EXIT_FAILURE, "Error in response: %s\n", raw);

	value = strchr(raw, ':') + 1;
	raw = strchr(value, ' ');

	length = raw - value;

	if (length > 0) memcpy(path_source, value, length);
	path_source[length] = '\0';
	}


/*
 * parse_xml_value
 *
 * Function that returns the text found between the opening and closing tags passed in.
 *
 */

char *parse_xml_value(char *start, char *end, const char *tag) {
	char   *data_start, *data_end, *end_tag, *value;
	size_t  tag_length;

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

	return (value);
	}


/*
 * entry_is_file
 *
 * Function that returns true if the directory entry passed in is a file.
 *
 */

int entry_is_file(connector *connection, char *start, char *end) {
	int   name_length, ok = 0;
	char *marker;

	name_length = strtol(start + 1, (char **)NULL, 10);
	if (name_length > MAXNAMLEN)
		errx(EXIT_FAILURE, "entry_is_file file name is too long");

	marker = strchr(start, ':') + 1 + name_length;
	if (strstr(marker, " file ") == marker) ok = 1;

	return (ok);
	}


/*
 * entry_is_directory
 *
 * Function that returns true if the directory entry passed in is a directory.
 *
 */

int entry_is_directory(connector *connection, char *start, char *end) {
	int   name_length, ok = 0;
	char *marker;

	name_length = strtol(start + 1, (char **)NULL, 10);
	if (name_length > MAXNAMLEN)
		errx(EXIT_FAILURE, "entry_is_directory file name is too long");

	marker = strchr(start, ':') + 1 + name_length;
	if (strstr(marker, " dir ") == marker) ok = 1;

	return (ok);
	}


/*
 * process_file_entry
 *
 * Function that returns a node with as much information as it can find within the start/end bounds.
 *
 */

file_node *process_file_entry(connector *connection, char *path_source, char *start, char *end) {
	file_node *file;
	char      *name;
	size_t     path_length, name_length;

	if ((file = (file_node *)malloc(sizeof(file_node))) == NULL)
		err(EXIT_FAILURE, "process_file_entry file malloc");

	if ((file->md5 = (char *)malloc(33)) == NULL)
		err(EXIT_FAILURE, "process_file_entry file->md5 malloc");

	file->md5[0] = '\0';
	file->size = file->raw_size = 0;
	file->href = file->revision_tag = NULL;

	name_length = strtol(start + 1, (char **)NULL, 10);
	if (name_length > MAXNAMLEN)
		errx(EXIT_FAILURE, "process_file_entry file name is too long");

	name = start = strchr(start, ':') + 1;

	start += name_length;
	*start = '\0';
	path_length = strlen(path_source) + name_length + 2;

	if (strstr(start + 1, "file ") != start + 1)
		errx(EXIT_FAILURE, "process_file_entry malformed response");

	if ((file->path = (char *)malloc(path_length)) == NULL)
		err(EXIT_FAILURE, "process_file_entry file->path malloc");

	snprintf(file->path, path_length, "%s/%s", path_source, name);

	start = strchr(start + 1, ' ');
	file->size = strtol(start, (char **)NULL, 10);

	return (file);
	}


/*
 * parse_response_group
 *
 * Procedure that isolates the next response group from the list of responses.
 *
 */

void parse_response_group(connector *connection, char **start, char **end) {
	if (connection->port == 3690) {
		*end = strchr(*start, '\n');
		if (*end == NULL) errx(EXIT_FAILURE, "Error in svn stream: %s\n", *start);
		}

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
 * Procedure that isolates the next response from the list of responses.
 *
 */

int parse_response_item(connector *connection, char *start, char *end, int *index, char **item_start, char **item_end) {
	int ok = 1, c = 0, has_entries = 0;

	if (connection->port == 3690) {
		if (*index == '\0') {
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
			}
		else ok = 0;
		}

	if (!has_entries) ok = 0;

	(*index)++;

	return (ok);
	}


/*
 * confirm_md5
 *
 * Function that loads a local file and removes revision tags one at a time until
 * the MD5 checksum matches that of the corresponding repository file or the file
 * has run out of $ FreeBSD : markers.
 */

int confirm_md5(char *md5, char *file_path_target) {
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
 * save_file
 *
 * Saves a file and inserts revision tags if any exist.
 *
 */

void save_file(char *filename, char *revision_tag, char *start, char *end, int executable, int special) {
	char  *tag;
	int    fd;

	if (special) {
		if (strstr(start, "link ") == start) {
			*end = '\0';

			if (symlink(start + 5, filename))
				if (errno != EEXIST)
					err(EXIT_FAILURE, "Cannot link %s -> %s", start + 5, filename);
			}
		}
	else {
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
 * build_source_directory_tree_svn
 *
 */

void build_source_directory_tree_svn(connector *connection, char *command, file_node ***file, int *file_count, int *max_file, char *path_target, int revision) {
	char   *start, *end, *item_start, *item_end, *name, *directory_command;
	char  **local_file, *temp_path, *next_command, *temp, **buffer;
	char    new_path_target[BUFFER_UNIT], path_source[MAXNAMLEN + 1];
	char    lookup[BUFFER_UNIT], *columns, line[BUFFER_UNIT];
	int     x, f, d, buffers, *buffer_commands, local_file_max, command_count;
	int     local_files, termwidth, index, more, path_exists;
	size_t  length, path_source_length, path_target_length;
	size_t  temp_path_size, name_length;
	DIR    *dp;
	file_node      *this_file;
	struct stat     local;
	struct winsize  win;
	struct dirent  *de;

	termwidth = -1;
	buffers = command_count = length = local_file_max = 0;
	local_file = NULL;

	path_target_length = strlen(path_target);
	temp_path_size = path_target_length + MAXNAMLEN + MAXNAMLEN + 2;

	if ((temp_path = (char *)malloc(temp_path_size)) == NULL)
		err(EXIT_FAILURE, "build_source_directory_tree_svn temp_path malloc");

	if ((buffer = (char **)malloc(sizeof(char **))) == NULL)
		err(EXIT_FAILURE, "build_source_directory_tree_svn buffer malloc");

	if ((buffer_commands = (int *)malloc(sizeof(int *))) == NULL)
		err(EXIT_FAILURE, "build_source_directory_tree_svn buffer_commands malloc");

	if ((buffer[0] = (char *)malloc(COMMAND_BUFFER)) == NULL)
		err(EXIT_FAILURE, "build_source_directory_tree_svn buffer[0] malloc");

	bzero(buffer[0], COMMAND_BUFFER);
	buffer_commands[0] = 0;
	temp_path[0] = '\0';

	start = process_command_svn(connection, command);

	directory_command = command;
	for (d = 0; d < connection->response_groups / 2; d++) {
		extract_directory_name_svn(connection, directory_command, path_source);
		directory_command = strchr(directory_command, '\n') + 1;

		path_source_length = strlen(path_source);

		snprintf(new_path_target, BUFFER_UNIT, "%s%s", path_target, path_source);

		if ((next_command = (char *)malloc(path_source_length + MAXNAMLEN + MAXNAMLEN + 2)) == NULL)
			err(EXIT_FAILURE, "build_source_directory_tree_svn next_command malloc");

		if (connection->verbosity > 1) {
			if (isatty(STDERR_FILENO)) {
				if (((columns = getenv("COLUMNS")) != NULL) && (*columns != '\0'))
					termwidth = strtol(columns, (char **)NULL, 10);
				else {
					if ((ioctl(STDERR_FILENO, TIOCGWINSZ, &win) != -1) && (win.ws_col > 0))
						termwidth = win.ws_col;
					}

				snprintf(line, BUFFER_UNIT, " d %s", new_path_target);

				if ((termwidth == -1) || (strlen(line) < (unsigned int)termwidth))
					fprintf(stderr, "\e[2K%s\r", line);
				else
					fprintf(stderr, "\e[2K%.*s...\r", termwidth - 4, line);
				}
			}

		/* Find all files/directories in the corresponding local directory. */

		local_files = 0;

		if ((dp = opendir(new_path_target)) != NULL) {
			while ((de = readdir(dp)) != NULL) {
				if (strcmp(de->d_name, "." ) == 0) continue;
				if (strcmp(de->d_name, "..") == 0) continue;

				if (local_files == local_file_max) {
					local_file_max++;

					if ((local_file = (char **)realloc(local_file, sizeof(char **) * (local_file_max + 1))) == NULL)
						err(EXIT_FAILURE, "build_source_directory_tree_svn local_directory realloc");

					if ((local_file[local_files] = (char *)malloc(BUFFER_UNIT)) == NULL)
						err(EXIT_FAILURE, "build_source_directory_tree_svn file malloc");
					}

				snprintf(local_file[local_files],
					BUFFER_UNIT,
					"%s/%s",
					new_path_target,
					de->d_name
					);

				local_files++;
				}

			closedir(dp);
			}

		/* Parse the response for file/directory names. */

		check_command_success(connection->port, &start, &end);
		parse_response_group(connection, &start, &end);

		item_start = start;
		item_end = end;

		index = 0;
		more = 1;

		while ((more = parse_response_item(connection, start, end, &index, &item_start, &item_end)) != 0) {
			temp = NULL;

			/* Keep track of the remote files. */

			if (entry_is_file(connection, item_start, item_end)) {
				this_file = process_file_entry(connection, path_source, item_start, item_end);
				(*file)[*file_count] = this_file;
				if (++(*file_count) == *max_file) {
					*max_file += BUFFER_UNIT;
					if ((*file = (file_node **)realloc(*file, *max_file * sizeof(file_node **))) == NULL)
						err(EXIT_FAILURE, "build_source_directory_tree_svn source realloc");
					}

				snprintf(temp_path,
					temp_path_size,
					"%s%s",
					path_target,
					this_file->path
					);
				}

			if (entry_is_directory(connection, item_start, item_end)) {
				name_length = strtol(item_start + 1, (char **)NULL, 10);
				if (name_length > MAXNAMLEN)
					errx(EXIT_FAILURE, "process_file file name is too long");

				name = strchr(item_start, ':') + 1;
				name[name_length] = '\0';

				snprintf(temp_path,
					temp_path_size,
					"%s%s/%s",
					path_target,
					path_source,
					name
					);

				/* Create the directory locally if it doesn't exist. */

				path_exists = lstat(temp_path, &local);
/*
				if ((path_exists != -1) && (!S_ISDIR(local.st_mode))) {
					prune(connection, temp_path);
					path_exists = -1;
					}
*/
				if (path_exists == -1) {
					if (connection->verbosity)
						printf(" + %s\n", temp_path);

					if (mkdir(temp_path, 0755))
						err(EXIT_FAILURE, "Cannot create target directory");
					}

				/* Add a get-dir command to the command buffer. */

				length = path_source_length + name_length + 1;

				snprintf(next_command,
					path_source_length + MAXNAMLEN + MAXNAMLEN + 2,
					"( get-dir ( %zd:%s/%s ( %d ) false true ( kind size ) ) )\n",
					length,
					path_source,
					name,
					revision
					);

				length = strlen(buffer[buffers]);
				strncat(buffer[buffers], next_command, COMMAND_BUFFER - length);

				buffer_commands[buffers]++;

				if (length > COMMAND_BUFFER_THRESHOLD) {
					buffers++;

					if ((buffer = (char **)realloc(buffer, sizeof(char **) * (buffers + 1))) == NULL)
						err(EXIT_FAILURE, "build_source_directory_tree_svn buffer realloc");

					if ((buffer_commands = (int *)realloc(buffer_commands, sizeof(int *) * (buffers + 1))) == NULL)
						err(EXIT_FAILURE, "build_source_directory_tree_svn buffer_commands realloc");

					if ((buffer[buffers] = (char *)malloc(COMMAND_BUFFER)) == NULL)
						err(EXIT_FAILURE, "build_source_directory_tree_svn buffer[0] malloc");

					buffer_commands[buffers] = 0;
					bzero(buffer[buffers], COMMAND_BUFFER);
					command_count = 0;
					}
				}

			/* Iterate through the local filenames and
			 * exclude any matches from later deletion.
			 */

			length = strlen(temp_path);

			for (f = 0; f < local_files; f++)
				if (length == strlen(local_file[f]))
					if (strncmp(local_file[f], temp_path, length) == 0)
						local_file[f][0] = '\0';

			item_start = item_end + 1;
			}

		/* Remove any local files/directories that do not exist in the current directory. */

		for (f = 0; f < local_files; f++) {
			if (local_file[f][0] != '\0') {
				snprintf(lookup, BUFFER_UNIT, "\t%s\n", local_file[f] + strlen(path_target));

				if ((connection->data) && ((temp = strstr(connection->data, lookup))))
					prune(connection, local_file[f] + strlen(path_target));
				}
			}

		free(next_command);

		start = end + 1;
		}

	/* Recursively process the command buffers. */

	x = 0;
	while (x <= buffers) {
		if (buffer_commands[x]) {
			connection->response_groups = 2 * buffer_commands[x];

			build_source_directory_tree_svn(
				connection,
				buffer[x],
				file,
				file_count,
				max_file,
				path_target,
				revision
				);

			free(buffer[x]);
			buffer[x] = NULL;
			}

		x++;
		}

	if (buffer[0]) free(buffer[0]);
	for (x = 0; x < local_file_max; x++) free(local_file[x]);
	free(temp_path);
	free(local_file);
	free(buffer_commands);
	free(buffer);
	}


/*
 * process_file_attributes_svn
 *
 * Procedure that parses a svn get-file command response and extracts the MD5 checksum,
 * last author, committed revision number and committed date.
 *
 */

void process_file_attributes_svn(connector *connection, char *command, file_node **file, int file_start, int file_end, char *path_target) {
	char *start, *end, *temp, *md5, *columns, line[BUFFER_UNIT];
	char *last_author, *last_author_end, *committed_rev, *committed_rev_end;
	char *committed_date, *committed_date_end;
	int   x, revision_tag_length, termwidth;
	struct winsize   win;

	termwidth = -1;

	connection->response_groups = 2 * (file_end - file_start + 1);

	start = process_command_svn(connection, command);

	for (x = file_start; x <= file_end; x++) {
		if (file[x] == NULL) continue;

		if (connection->verbosity > 1) {
			if (isatty(STDERR_FILENO)) {
				if (((columns = getenv("COLUMNS")) != NULL) && (*columns != '\0'))
					termwidth = strtol(columns, (char **)NULL, 10);
				else {
					if ((ioctl(STDERR_FILENO, TIOCGWINSZ, &win) != -1) && (win.ws_col > 0))
						termwidth = win.ws_col;
					}
				snprintf(line, BUFFER_UNIT, " f %s%s", path_target, file[x]->path);

				if ((termwidth == -1) || (strlen(line) < (unsigned int)termwidth))
					fprintf(stderr, "\e[2K%s\r", line);
				else
					fprintf(stderr, "\e[2K%.*s...\r", termwidth - 4, line);
				}
			}

		end = connection->response + connection->response_length;

		check_command_success(connection->port, &start, &end);
		end = terminate_response(connection->port, start, end);

		last_author    = last_author_end    = NULL;
		committed_rev  = committed_rev_end  = NULL;
		committed_date = committed_date_end = NULL;

		/* Extract the file attributes. */

		if ((start = strchr(start, ':')) != NULL) {
			md5 = ++start;
			start = strchr(start, ' ');
			*start++ = '\0';

			file[x]->revision_tag = NULL;
			snprintf(file[x]->md5, 33, "%s", md5);

			file[x]->executable = (strstr(start, "14:svn:executable") ? 1 : 0);
			file[x]->special    = (strstr(start, "11:svn:special") ? 1 : 0);

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

			if (strstr(start, "( 12:svn:keywords 10:FreeBSD=%H ) ") != NULL) {
				if ((last_author) && (committed_rev) && (committed_date)) {
					*last_author_end    = '\0';
					*committed_rev_end  = '\0';
					*committed_date_end = '\0';

					revision_tag_length = 8
						+ strlen(connection->branch)
						+ strlen(file[x]->path)
						+ strlen(committed_rev)
						+ strlen(committed_date)
						+ strlen(last_author);

					if ((file[x]->revision_tag = (char *)malloc(revision_tag_length)) == NULL)
						err(EXIT_FAILURE, "process_file_attributes_svn revision_tag malloc");

					snprintf(file[x]->revision_tag,
						revision_tag_length,
						": %s%s %s %s %s ",
						connection->branch,
						file[x]->path,
						committed_rev,
						committed_date,
						last_author
						);
					}
				}
			}

		start = end + 1;
		}
	}


/*
 * get_files_svn
 *
 */

void get_files_svn(connector *connection, char *command, char *path_target, file_node **file, int file_start, int file_end, int revision) {
	int     x, t, temp, bytes_read, file_length_source, file_length_target;
	int     offset, position, block_size_markers, file_block_remainder;
	int     total_bytes_read, raw_size, first_response, last_response, block_size;
	size_t  blocks, temp_file_length;
	char   *temp_file, *file_path_source, *file_path_target;
	char   *start, *end, *gap, *md5_check, *begin, *temp_end;
	MD5_CTX md5_context;

	file_length_source = MAXNAMLEN + 2;
	file_length_target = strlen(path_target) + MAXNAMLEN + 2;

	temp_file_length = 128 + (file_length_source > file_length_target ? file_length_source : file_length_target);

	if ((file_path_source = (char *)malloc(file_length_source)) == NULL)
		err(EXIT_FAILURE, "get_files_svn file_path_source malloc");

	if ((file_path_target = (char *)malloc(file_length_target)) == NULL)
		err(EXIT_FAILURE, "get_files_svn file_path_target malloc");

	if ((temp_file = (char *)malloc(temp_file_length)) == NULL)
		err(EXIT_FAILURE, "get_files_svn temp_file malloc");

	/* Calculate the number of bytes the server is going to send back. */

	t = total_bytes_read = block_size_markers = raw_size = 0;

	last_response  = 20;
	first_response = 84;

	temp = revision;
	while ((int)(temp /= 10) > 0) first_response++;

	for (x = file_start; x <= file_end; x++) {
		if (file[x] == NULL) continue;

		block_size_markers = 6 * (int)(file[x]->size / BUFFER_UNIT);
		if (file[x]->size % BUFFER_UNIT) block_size_markers += 3;

		file_block_remainder = file[x]->size % BUFFER_UNIT;
		while ((int)(file_block_remainder /= 10) > 0) block_size_markers++;

		file[x]->raw_size = file[x]->size
			+ first_response
			+ last_response
			+ block_size_markers;

		raw_size += file[x]->raw_size;
		}

	if ((connection->verbosity > 1) && (isatty(STDERR_FILENO)))
		fprintf(stderr, "\r\e[2K\r");

	send_command(connection, command);

	blocks = raw_size / BUFFER_UNIT + 2;
	position = raw_size;

	if (blocks > connection->response_blocks) {
		connection->response_blocks = blocks;
		connection->response = (char *)realloc(connection->response, connection->response_blocks * BUFFER_UNIT + 1);
		if (connection->response == NULL) err(EXIT_FAILURE, "process_command_svn realloc");
		}

	while (total_bytes_read < raw_size) {
		bytes_read = -1;
		while (bytes_read == -1)
			bytes_read = read(
				connection->socket_descriptor,
				connection->response + total_bytes_read,
				connection->response_blocks * BUFFER_UNIT - total_bytes_read
				);

		if (bytes_read == 0) errx(EXIT_FAILURE, "Empty response");

		total_bytes_read += bytes_read;

		if ((connection->verbosity > 1) && (isatty(STDERR_FILENO)))
			fprintf(stderr, " %c\r", twirly[(t++ / 16) % 4]);
		}

	for (x = file_end; x >= file_start; x--) {
		if (file[x] == NULL) continue;

		snprintf(file_path_target,
			file_length_target,
			"%s%s",
			path_target,
			file[x]->path
			);

		/* Extract the file from the response stream. */

		end = connection->response + position;
		temp_end = end;

		start = end - file[x]->raw_size;

		check_command_success(connection->port, &start, &temp_end);
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

		if (strncmp(file[x]->md5, md5_check, 33) != 0)
			errx(EXIT_FAILURE, "MD5 checksum mismatch: should be %s, calculated %s\n", file[x]->md5, md5_check);

		save_file(
			file_path_target,
			file[x]->revision_tag,
			begin,
			begin + file[x]->size,
			file[x]->executable,
			file[x]->special
			);

		position -= file[x]->raw_size;
		bzero(connection->response + position, file[x]->raw_size);

		free(md5_check);
		if (file[x]->href) free(file[x]->href);
		if (file[x]->md5) free(file[x]->md5);
		if (file[x]->revision_tag) free(file[x]->revision_tag);
		free(file[x]->path);
		free(file[x]);
		file[x] = NULL;
		}

	free(temp_file);
	free(file_path_source);
	free(file_path_target);
	}


/*
 * get_files_http
 *
 */

void get_files_http(connector *connection, char *command, tree_node **tree) {
	char   *start, *end, *directory, *temp, *value, *header, *path, *data_start, *d;
	char   *t1, *t2, **buffer, next_command[BUFFER_UNIT];
	char    temp_file[BUFFER_UNIT], revision_tag[BUFFER_UNIT], *md5, *href;
	char   *last_author, *committed_date, *committed_rev, *getetag, *relative_path;
	int     x, f, fd, download, max_file, file_count, index, buffers;
	int    *buffer_commands, executable, special;
	int     local_file_max;
	size_t  length, file_length;
	struct stat  local;
	file_node   *this_file, **file = NULL;
	tree_node   *find;

	index = max_file = file_count = buffers = local_file_max = 0;

	if ((buffer = (char **)malloc(sizeof(char **))) == NULL)
		err(EXIT_FAILURE, "get_files_http buffer malloc");

	if ((buffer_commands = (int *)malloc(sizeof(int *))) == NULL)
		err(EXIT_FAILURE, "get_files_http buffer_commands malloc");

	if ((buffer[0] = (char *)malloc(COMMAND_BUFFER)) == NULL)
		err(EXIT_FAILURE, "get_files_http buffer[0] malloc");

	bzero(buffer[0], COMMAND_BUFFER);
	buffer_commands[0] = 0;

	/* Process response for subdirectories and create them locally. */

	start = connection->response;
	end   = connection->response + connection->response_length;

	while ((start = strstr(start, "<S:add-directory")) && (start < end)) {
		value = parse_xml_value(start, end, "D:href");
		temp = strstr(value, connection->trunk) + strlen(connection->trunk);

		length = strlen(connection->path_target) + strlen(temp) + 1;

		if ((directory = (char *)malloc(length)) == NULL)
			err(EXIT_FAILURE, "get_files_http directory malloc");

		snprintf(directory, length, "%s%s", connection->path_target, temp);

		mkdir(directory, 0755);

		start += strlen(value);
		free(value);
		free(directory);
		}

	/* Process response for files and save the list of files for the next run. */

	if ((fd = open(connection->data_file_new, O_WRONLY | O_CREAT | O_TRUNC)) == -1)
		err(EXIT_FAILURE, "write file failure %s", connection->data_file_new);

	start = connection->response;

	data_start = connection->data;

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

		start += strlen(href);

		write(fd, md5, strlen(md5));
		write(fd, "\t", 1);
		write(fd, path, strlen(path));
		write(fd, "\n", 1);

		download = 0;

		if ((data_start != NULL) && ((find = locate_tree_node(*tree, path)) != NULL)) {
			if (strncmp(find->md5, md5, 32) != 0) download = 1;
			delete_tree_node(tree, path);
			}

		snprintf(temp_file,
			BUFFER_UNIT,
			"%s%s",
			connection->path_target,
			path
			);

		if (confirm_md5(md5, temp_file) != 0) download = 2;

		if (download == 0) {
			free(md5);
			free(path);
			free(href);
			continue;
			}

		if ((this_file = (file_node *)malloc(sizeof(file_node))) == NULL)
			err(EXIT_FAILURE, "get_files_http file malloc");

		this_file->href = href;
		this_file->md5  = md5;
		this_file->path = path;
		this_file->revision_tag = NULL;
		this_file->exists = 0;
		if (download == 2) this_file->exists = 1;

		if (file_count == max_file) {
			max_file += BUFFER_UNIT;

			if ((file = (file_node **)realloc(file, max_file * sizeof(file_node **))) == NULL)
				err(EXIT_FAILURE, "get_files_http file realloc");
			}

		file[file_count++] = this_file;

		length = strlen(href) + MAXNAMLEN + 2;

		snprintf(next_command,
			length,
			"PROPFIND %s HTTP/1.1\n"
			"Depth: 1\n"
			"Host: %s\n\n",
			href,
			connection->address
			);

		strncat(buffer[buffers], next_command, COMMAND_BUFFER - strlen(buffer[buffers]));

		snprintf(next_command,
			length,
			"GET %s HTTP/1.1\n"
			"Host: %s\n\n",
			href,
			connection->address
			);

		strncat(buffer[buffers], next_command, COMMAND_BUFFER - strlen(buffer[buffers]));

		buffer_commands[buffers] += 2;

		if (buffer_commands[buffers] > 95) {
			buffers++;

			if ((buffer = (char **)realloc(buffer, sizeof(char **) * (buffers + 1))) == NULL)
				err(EXIT_FAILURE, "get_files_http buffer realloc");

			if ((buffer_commands = (int *)realloc(buffer_commands, sizeof(int *) * (buffers + 1))) == NULL)
				err(EXIT_FAILURE, "get_files_http buffer_commands realloc");

			if ((buffer[buffers] = (char *)malloc(COMMAND_BUFFER)) == NULL)
				err(EXIT_FAILURE, "get_files_http buffer[0] malloc");

			buffer_commands[buffers] = 0;
			bzero(buffer[buffers], COMMAND_BUFFER);
			}
		}

	close(fd);
	chmod(connection->data_file_new, 0644);

	/* Any files left in the tree are safe to delete. */

	prune_tree(connection, *tree, 0);

	/* Parse response for embedded files. */

	for (x = 0; x <= buffers; x++) {
		if (buffer_commands[x] == 0) break;

		connection->response_groups = buffer_commands[x] * 2;
		process_command_http(connection, buffer[x]);

		start = connection->response;
		end = start + connection->response_length;

		check_command_success(connection->port, &start, &end);
		parse_response_group(connection, &start, &end);

		for (f = 0; f < buffer_commands[x] / 2; f++) {
			end = strstr(start, "</D:multistatus>") + 16;
			*end = '\0';

			value = parse_xml_value(start, end, "lp1:getcontentlength");
			file[index]->size = strtol(value, (char **)NULL, 10);
			free(value);

			special = executable = 0;
			if (strstr(start, "<S:executable/>")) executable = 1;
			if (strstr(start, "<S:special>*</S:special>")) special = 1;

			revision_tag[0] = '\0';

			if (strstr(start, "<S:keywords>FreeBSD=%H</S:keywords>")) {
				last_author = parse_xml_value(start, end, "lp1:creator-displayname");
				committed_date = parse_xml_value(start, end, "lp1:creationdate");
				committed_rev = parse_xml_value(start, end, "lp1:version-name");
				getetag = parse_xml_value(start, end, "lp1:getetag");

				relative_path = strstr(getetag, "//") + 2;
				relative_path[strlen(relative_path) - 1] = '\0';

				if ((d = strchr(committed_date, '.')) != NULL) {
					*d++ = 'Z';
					*d = '\0';
					}

				if ((d = strchr(committed_date, 'T')) != NULL) *d = ' ';

				snprintf(revision_tag,
					BUFFER_UNIT,
					": %s %s %s %s ",
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

			header = end + 1;
			start = strstr(header, "\r\n\r\n") + 4;

			temp = strstr(header, "Content-Length: ") + 16;
			file_length = strtol(temp, (char **)NULL, 10);

			snprintf(next_command,
				BUFFER_UNIT,
				"%s%s",
				connection->path_target,
				file[index]->path
				);

			if (connection->verbosity)
				printf(" + %s\n", next_command);

			save_file(
				next_command,
				revision_tag,
				start,
				start + file_length,
				executable,
				special
				);

			start += file_length + 1;

			free(file[index]->href);
			free(file[index]->md5);
			free(file[index]->path);
			free(file[index]);

			index++;
			}

		free(buffer[x]);
		buffer[x] = NULL;
		}

	if (buffer[0]) free(buffer[0]);
	if (file) free(file);
	free(buffer_commands);
	free(buffer);
	}


/*
 * reset_connection
 *
 */

void reset_connection(connector *connection) {
	struct addrinfo hints, *start, *temp;
	int   error, option = 1;
	char  type[10];

	if (connection->socket_descriptor)
		if (close(connection->socket_descriptor) != 0)
			if (errno != EBADF) err(EXIT_FAILURE, "close_connection");

	switch (connection->port) {
		case   23: snprintf(type, sizeof(type), "svn+ssh"); break;
		case   80: snprintf(type, sizeof(type), "http"); break;
		case  443: snprintf(type, sizeof(type), "https"); break;
		case 3690: snprintf(type, sizeof(type), "svn"); break;
		default  : err(EXIT_FAILURE, "Invalid port/protocol");
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
 * usage
 *
 */

void usage(void) {
	fprintf(stderr, "Usage: svnup <section> [-h host] [-b branch] [-l local_directory]\n");
	fprintf(stderr, "  Options:\n");
	fprintf(stderr, "    -4  Use IPv4 addresses only.\n");
	fprintf(stderr, "    -6  Use IPv6 addresses only.\n");
	fprintf(stderr, "    -b  The Subversion branch to retrieve.\n");
	fprintf(stderr, "    -h  The hostname or IP address of the Subversion repository.\n");
	fprintf(stderr, "    -l  The local directory to save the repository's files to.\n");
	fprintf(stderr, "    -r  The revision number to retreive (defaults to the branch's\n");
	fprintf(stderr, "          most recent revision if this option is not specified).\n");
	fprintf(stderr, "    -v  How verbose the output should be (0 = no output, 1 = the\n");
	fprintf(stderr, "          default normal output, 2 = also show command and response\n");
	fprintf(stderr, "          text, 3 = also show command response parsing codes).\n");
	fprintf(stderr, "    -V  Show the version number and exit.\n");

	exit(EXIT_FAILURE);
	}


/*
 * set_configuration_parameters
 *
 */

void set_configuration_parameters(connector *connection, char *buffer, size_t length, const char *section) {
	char *line, *item, *bracketed_section;
	int   x;

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
				connection->verbosity = strtol(line + 10, (char **)NULL, 10);;
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
 */

void load_configuration(connector *connection, char *configuration_file, char *section) {
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
 * main
 *
 */

int main(int argc, char **argv) {
	char  *start, *end, *value, *index, *path, *md5;
	char   temp_file[BUFFER_UNIT], command[COMMAND_BUFFER + 1];
	int    option, send, revision, x, x0, temp, fd, revision_length, max_file;
	int    file_count, length, command_count;

	struct stat  local;
	tree_node   *tree = NULL;
	file_node  **file;
	connector    connection;

	char *configuration_file = "/usr/local/etc/svnup.conf";

	revision = file_count = command_count = 0;
	max_file = BUFFER_UNIT;
	command[0] = '\0';

	connection.address = connection.branch = connection.path_target = NULL;
	connection.path_work = connection.data = NULL;
	connection.data_file_old = connection.data_file_new = NULL;
	connection.ssl = NULL;
	connection.ctx = NULL;
	connection.socket_descriptor = connection.port = connection.data_size = 0;
	connection.verbosity = 1;
	connection.family = AF_INET;
	connection.ssl = NULL;
	connection.ctx = NULL;

	if (argc < 2) usage();

	if (argv[1][0] != '-') {
		load_configuration(&connection, configuration_file, argv[1]);
		optind = 2;
		}

	while ((option = getopt(argc, argv, "46b:h:l:r:v:V")) != -1) {
		switch (option) {
			case '4': connection.family = AF_INET;  break;
			case '6': connection.family = AF_INET6; break;
			case 'b':
				x = (optarg[0] == '/' ? 1 : 0);
				connection.branch = (char *)malloc(strlen(optarg) - x + 1);
				memcpy(connection.branch, optarg + x, strlen(optarg) - x + 1);
				break;
			case 'h': connection.address = strdup(optarg); break;
			case 'l':
				connection.path_target = realloc(connection.path_target, strlen(optarg) + 2);
				snprintf(connection.path_target, strlen(optarg) + 1, "%s", optarg);
				break;
			case 'r': revision = strtol(optarg, (char **)NULL, 10); break;
			case 'v': connection.verbosity = strtol(optarg, (char **)NULL, 10); break;
			case 'V': fprintf(stdout, "svnup version %s\n", SVNUP_VERSION); exit(0);
			}
		}

	if (connection.verbosity > 1) {
		fprintf(stderr, "####### Address : %s\n", connection.address);
		fprintf(stderr, "####### Branch  : %s\n", connection.branch);
		fprintf(stderr, "####### Target  : %s\n", connection.path_target);
		fprintf(stderr, "####### WorkDir : %s\n", connection.path_work);
		}

	if (connection.path_work == NULL)
		if ((connection.path_work = strdup("/tmp/svnup")) == NULL)
			errx(EXIT_FAILURE, "Cannot set connection.path_work");

	if (connection.address == NULL)
		errx(EXIT_FAILURE, "\nNo host specified.  Please uncomment the preferred SVN mirror in %s.\n\n", configuration_file);

	if ((connection.branch == NULL) || (connection.path_target == NULL)) usage();

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

	/* Create the working directory if it doesn't exist. */

	if (lstat(connection.path_work, &local) != -1) {
		if (!S_ISDIR(local.st_mode))
			errx(EXIT_FAILURE, "%s is not a directory.", connection.path_work);
		}
	else {
		if (mkdir(connection.path_work, 0755))
			err(EXIT_FAILURE, "Cannot create work directory");
		}

	/* Create the target directory if it doesn't exist. */

	if (lstat(connection.path_target, &local) != -1) {
		if (!S_ISDIR(local.st_mode))
			errx(EXIT_FAILURE, "%s is not a directory.", connection.path_target);
		}
	else {
		if (mkdir(connection.path_target, 0755))
			err(EXIT_FAILURE, "Cannot create target directory");
		}

	connection.response_blocks = 10240;
	connection.response_length = 0;

	if ((connection.response = (char *)malloc(connection.response_blocks * BUFFER_UNIT + 1)) == NULL)
		err(EXIT_FAILURE, "main connection.response malloc");

	reset_connection(&connection);

	/* Send initial response string. */

	if (connection.port == 3690) {
		connection.response_groups = 1;
		process_command_svn(&connection, "");

		snprintf(command,
			COMMAND_BUFFER,
			"( 2 ( edit-pipeline svndiff1 absent-entries commit-revprops depth log-revprops atomic-revprops partial-replay ) %ld:svn://%s/%s 10:svnup-%s ( ) )\n",
			strlen(connection.address) + strlen(connection.branch) + 7,
			connection.address,
			connection.branch,
			SVNUP_VERSION
			);

		process_command_svn(&connection, command);

		start = connection.response;
		end = connection.response + connection.response_length;
		check_command_success(connection.port, &start, &end);

		/* Login anonymously. */

		if (strstr(connection.response, "ANONYMOUS") == NULL)
			err(EXIT_FAILURE, "main connection.response anonymous read not granted");

		connection.response_groups = 2;
		process_command_svn(&connection, "( ANONYMOUS ( 0: ) )\n");

		/* Get latest revision number. */

		if (revision <= 0) {
			process_command_svn(&connection, "( get-latest-rev ( ) )\n");

			start = connection.response;
			end = connection.response + connection.response_length;
			check_command_success(connection.port, &start, &end);

			if ((start != NULL) && (start == strstr(start, "( success ( "))) {
				start += 12;
				value = start;
				while (*start != ' ') start++;
				*start = '\0';

				revision = strtol(value, (char **)NULL, 10);
				}
			else errx(EXIT_FAILURE, "Cannot retrieve latest revision.");
			}

		if (connection.verbosity) printf("####### Revision: %d\n", revision);

		/* Check to make sure client-supplied remote path is a directory. */

		snprintf(command,
			COMMAND_BUFFER,
			"( check-path ( 0: ( %d ) ) )\n",
			revision
			);
		process_command_svn(&connection, command);

		if (strcmp(connection.response, "( success ( ( ) 0: ) )\n( success ( dir ) )\n") != 0)
			errx(EXIT_FAILURE,
				"Remote path %s is not a repository directory.\n%s",
				connection.branch,
				connection.response
				);

		snprintf(command,
			COMMAND_BUFFER,
			"( get-dir ( 0: ( %d ) false true ( kind size ) ) )\n",
			revision
			);
		}

	if ((connection.port == 80) || (connection.port == 443)) {
		connection.response_groups = 2;

		/* Get the latest revision number. */

		if (revision <= 0) {
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
				revision = strtol(value + 18, (char **)NULL, 10);
			}
		}

	revision_length = 1;
	temp = revision;
	while ((int)(temp /= 10) > 0) revision_length++;

	length = strlen(connection.path_work) + MAXNAMLEN;

	connection.data_file_old = (char *)malloc(length);
	connection.data_file_new = (char *)malloc(length);

	snprintf(connection.data_file_old, length, "%s/%s", connection.path_work, argv[1]);
	snprintf(connection.data_file_new, length, "%s/%s.new", connection.path_work, argv[1]);

	if (lstat(connection.data_file_old, &local) != -1) {
		connection.data_size = local.st_size;
		if ((connection.data = (char *)malloc(connection.data_size + 1)) == NULL)
			err(EXIT_FAILURE, "main connection.data malloc");

		if ((fd = open(connection.data_file_old, O_RDONLY)) == -1)
			err(EXIT_FAILURE, "open file (%s)", connection.data_file_old);

		if (read(fd, connection.data, connection.data_size) != connection.data_size)
			err(EXIT_FAILURE, "read file error (%s)", connection.data_file_old);

		connection.data[connection.data_size] = '\0';
		close(fd);

		index = connection.data;
		while (*index) {
			md5 = index;
			path = strchr(index, '\t') + 1;
			index = strchr(path, '\n');
			*index++ = '\0';
			md5[32] = '\0';
			insert_tree_node(&tree, path, md5);
			}
		}

	/* Traverse the directory tree gathering files and directories. */

	if ((file = (file_node **)malloc(sizeof(file_node **) * max_file)) == NULL)
		err(EXIT_FAILURE, "process_directory source malloc");

	if ((connection.port == 80) || (connection.port == 443)) {
		connection.response_groups = 2;

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
			connection.root,
			connection.address,
			SVNUP_VERSION,
			strlen(connection.branch) + revision_length + revision_length + 209,
			connection.branch,
			revision,
			revision
			);

		process_command_http(&connection, command);

		get_files_http(&connection, command, &tree);
		}

	if (connection.port == 3690) {
		build_source_directory_tree_svn(
			&connection,
			command,
			&file,
			&file_count,
			&max_file,
			connection.path_target,
			revision
			);
		}

	if ((connection.verbosity > 1) && (isatty(STDERR_FILENO)))
		fprintf(stderr, "\r\e[2K\r");

	command[0] = '\0';

	if (connection.port == 3690) {
		for (x = 0, x0 = 0; x < file_count; x++) {
			if (file[x] == NULL) continue;

			connection.response_groups += 2;

			snprintf(temp_file,
				BUFFER_UNIT,
				"( get-file ( %zd:%s ( %d ) true false ) )\n",
				strlen(file[x]->path),
				file[x]->path,
				revision
				);

			length = strlen(command);

			strncat(command, temp_file, COMMAND_BUFFER - length);

			if (length > COMMAND_BUFFER_THRESHOLD) {
				process_file_attributes_svn(
					&connection,
					command, file,
					x0,
					x,
					connection.path_target
					);

				command[0] = '\0';
				connection.response_groups = 0;
				command_count = 0;
				x0 = x + 1;
				}
			}

		process_file_attributes_svn(
			&connection,
			command,
			file,
			x0,
			x - 1,
			connection.path_target
			);

		if ((connection.verbosity > 1) && (isatty(STDERR_FILENO)))
			fprintf(stderr, "\r\e[2K\r");

		/* Process response for files and save the list of files for the next run. */

		if ((fd = open(connection.data_file_new, O_WRONLY | O_CREAT | O_TRUNC)) == -1)
			err(EXIT_FAILURE, "write file failure %s", connection.data_file_new);

		for (x = 0; x < file_count; x++) {
			write(fd, file[x]->md5, strlen(file[x]->md5));
			write(fd, "\t", 1);
			write(fd, file[x]->path, strlen(file[x]->path));
			write(fd, "\n", 1);
			}

		close(fd);
		chmod(connection.data_file_new, 0644);
		}

	command[0] = '\0';
	connection.response_groups = 0;

	for (x = 0, x0 = 0; x < file_count; x++) {
		if (file[x] == NULL) continue;

		snprintf(temp_file,
			BUFFER_UNIT,
			"%s%s",
			connection.path_target,
			file[x]->path
			);

		/*
		 * If the MD5 checksums match, then skip the file, otherwise add it
		 * to the command buffer for download.
		 */

		if (confirm_md5(file[x]->md5, temp_file) == 0) {
			if (file[x]) {
				free(file[x]->path);
				if (file[x]->md5) free(file[x]->md5);
				if (file[x]->revision_tag) free(file[x]->revision_tag);
				free(file[x]);
				file[x] = NULL;
				}
			}
		else {
			connection.response_groups += 2;

			if (connection.port == 3690)
				snprintf(temp_file,
					BUFFER_UNIT,
					"( get-file ( %zd:%s ( %d ) false true ) )\n",
					strlen(file[x]->path),
					file[x]->path,
					revision
					);

			if ((connection.port == 80) || (connection.port == 443))
				snprintf(temp_file,
					BUFFER_UNIT,
					"GET /%s%s HTTP/1.1\n"
					"Host: %s\n"
					"Connection: Keep-Alive\n\n",
					connection.branch,
					file[x]->path,
					connection.address
					);

			length = strlen(command);

			strncat(command, temp_file, COMMAND_BUFFER - length);

			send = 0;
			if (length > COMMAND_BUFFER_THRESHOLD) send = 1;
			if (((connection.port == 80) || (connection.port == 443)) && (++command_count > 95)) send = 1;

			if (send) {
				get_files_svn(&connection, command, connection.path_target, file, x0, x, revision);
				command[0] = '\0';
				connection.response_groups = command_count = 0;
				x0 = x + 1;
				}
			}
		}

	if (strcmp(command, "") != 0)
		get_files_svn(&connection, command, connection.path_target, file, x0, x - 1, revision);

	/* Wrap it all up. */

	if (close(connection.socket_descriptor) != 0)
		if (errno != EBADF) err(EXIT_FAILURE, "close connection failed");

	remove(connection.data_file_old);

	if ((rename(connection.data_file_new, connection.data_file_old)) != 0)
		err(EXIT_FAILURE, "Cannot rename %s", connection.data_file_old);

	free(connection.data_file_old);
	free(connection.data_file_new);
	if (connection.address) free(connection.address);
	if (connection.root) free(connection.root);
	if (connection.trunk) free(connection.trunk);
	if (connection.branch) free(connection.branch);
	if (connection.data) free(connection.data);
	if (connection.path_target) free(connection.path_target);
	if (connection.path_work) free(connection.path_work);
	if (connection.ssl) {
		SSL_shutdown(connection.ssl);
		SSL_CTX_free(connection.ctx);
		SSL_free(connection.ssl);
		}
	free(connection.response);
	free(file);

	if ((connection.verbosity > 1) && (isatty(STDERR_FILENO)))
		fprintf(stderr, "\e[2K\n");

	return (0);
	}
