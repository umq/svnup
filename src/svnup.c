/*-
 * Copyright (c) 2012, John Mehr <jcm@visi.com>
 * All rights reserved.
 *
 * Special thanks to Rudolf Cejka <cejkar@fit.vutbr.cz>
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

#include <dirent.h>
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
	char          *response;
	size_t         response_length;
	unsigned int   response_blocks;
	unsigned int   response_groups;
	char          *branch;
	int            verbosity;
	} connector;

typedef struct {
	char          *name;
	char          *path;
	char           md5[33];
	unsigned long  size;
	unsigned long  raw_size;
	char           executable;
	char          *revision_tag;
	} node;


/* Function Prototypes */

char *find_response_end(char *start, char *end);
char *terminate_response(char *start, char *end);
void  prune(char *path_target);
void  send_command(const char *command, connector *connection);
char *svn_check_command_success(char *start, char *end);
char *send_receive_command(const char *command, connector *connection);
int   compare_md5(node *source, char *path_target);
void  process_file_attributes(connector *connection, char *command, node **file, int file_start, int file_end, char *path_target);
void  build_source_directory_tree(connector *connection, char *command, node ***file, int *file_count, int *max_file, char *path_target, int revision);
void  get_files(connector *connection, char *command, char *path_target, node **file, int file_start, int file_end, int revision);
void  croak(const char *error);
void usage(void);
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

void prune(char *path_target) {
	char           *temp_file;
	unsigned int    temp_length;
	DIR            *dp;
	struct stat     sb;
	struct dirent  *de;

	temp_length = strlen(path_target) + MAXNAMLEN + 1;

	if ((temp_file = (char *)malloc(temp_length)) == NULL) croak("prune malloc");

	lstat(path_target, &sb);

	if (S_ISREG(sb.st_mode)) {
		if ((remove(path_target)) != 0) {
			fprintf(stderr, "Cannot remove %s: %s\n", path_target, strerror(errno));
			exit(EXIT_FAILURE);
			}
		}

	if (S_ISDIR(sb.st_mode))
		if ((dp = opendir(path_target)) != NULL) {
			while ((de = readdir(dp)) != NULL) {
				if (strcmp(de->d_name, "." ) == 0) continue;
				if (strcmp(de->d_name, "..") == 0) continue;

				snprintf(temp_file,
					temp_length,
					"%s/%s",
					path_target,
					de->d_name
					);

				prune(temp_file);
				}

			closedir(dp);

			if ((rmdir(path_target)) != 0) {
				fprintf(stderr, "Cannot remove %s: %s\n", path_target, strerror(errno));
				exit(EXIT_FAILURE);
				}
			}

	printf(" - %s\n", path_target);

	free(temp_file);
	}


/*
 * find_response_end
 *
 * Function that counts opening and closing parenthesis of a command's response in
 * order to find the end of the response.
 *
 */

char *find_response_end(char *start, char *end) {
	int count = 0;
	do {
		count += (*start == '(' ? 1 : (*start == ')' ? -1 : 0));
		}
	while ((*start != '\0') && (start++ < end) && (count > 0));

	return (start);
	}


/*
 * terminate_response
 *
 * Function that puts a null character at the end of a command's response.
 *
 */

char *terminate_response(char *start, char *end) {
	start = find_response_end(start, end);
	*start = '\0';

	return (start);
	}


/*
 * croak
 *
 * Procedure that exits when an error has been detected.
 *
 */

void croak(const char *error) {
	perror(error);
	exit(EXIT_FAILURE);
	}


/*
 * send_command
 *
 * Procedure that sends a command to the svn server.
 *
 */

void send_command(const char *command, connector *connection) {
	int bytes_written, total_bytes_written, bytes_to_write;

	if (command) {
		total_bytes_written = 0;
		bytes_to_write = strlen(command);

		if (connection->verbosity > 1)
			fprintf(stdout, "==========\n<< Command: (%d bytes)\n%s", bytes_to_write, command);

		while (total_bytes_written < bytes_to_write) {
			bytes_written = -1;
			while (bytes_written == -1)
				bytes_written = write(
					connection->socket_descriptor,
					command + total_bytes_written,
					strlen(command - total_bytes_written)
					);

			total_bytes_written += bytes_written;
			}
		}
	}


/*
 * svn_check_command_success
 *
 * Function that makes sure a failure response has not been sent from the svn server.
 *
 */

char *svn_check_command_success(char *start, char *end) {
	char *check;
	int   ok = 1;

	if (start[0] == '\n') start++;
	if (strstr(start, "( success ( ( ) 0: ) ) ( failure") == start) ok = 0;
	if (strstr(start, "( success ( ) ) ( failure") == start) ok = 0;

	if (ok) {
		check = strstr(start, "( success ");
		if (check) return (find_response_end(start, end) + 1);
		else ok = 0;
		}

	if (!ok) {
		fprintf(stderr, "Command failure: %s\n", start);
		exit(EXIT_FAILURE);
		}

	return NULL;
	}


/*
 * send_receive_command
 *
 * Function that sends a command to the svn server and parses its response to make
 * sure that the expected number of response strings have been received.
 *
 */

char *send_receive_command(const char *command, connector *connection) {
	int           bytes_read, ok, count, position;
	unsigned int  group;
	char          input[BUFFER_UNIT + 1], *check;

	send_command(command, connection);

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
			connection->response = (char *)realloc(connection->response, connection->response_blocks * BUFFER_UNIT + 1);

			if (connection->response == NULL)
				croak("send_receive_command realloc");
			}

		if ((input[0] == ' ') && (input[1] == '\0')) {
			connection->response[position++] = '\n';
			continue;
			}

		if (connection->verbosity > 2)
			fprintf(stdout, "==========\n>> Response Parse:\n");

		check = input;
		if ((count == 0) && (input[0] == ' ')) *check++ = '\n';

		do {
			count += (*check == '(' ? 1 : (*check == ')' ? -1 : 0));

			if (connection->verbosity > 2) fprintf(stderr, "%d", count);

			if (count == 0) {
				group++;
				check++;
				*check = '\n';
				}
			}
		while (++check < input + bytes_read);

		memcpy(connection->response + position, input, bytes_read + 1);
		position += bytes_read;

		if (connection->verbosity > 2)
			fprintf(stderr, ". = %d %d\n", group, connection->response_groups);

		if (group == connection->response_groups) ok = 1;
		}
	while (!ok);

	if (connection->verbosity > 1)
		fprintf(stdout, "==========\n>> Response:\n%s", connection->response);

	return (connection->response);
	}


/*
 * build_source_directory_tree
 *
 * Procedure that traverses a repository's directory structure, building a set of
 * get-dir commands to recursively find all files and subdirectories.
 *
 */

void build_source_directory_tree(connector *connection, char *command, node ***file, int *file_count, int *max_file, char *path_target, int revision) {
	char  *start, *end, *value, *directory, temp_file[BUFFER_UNIT], **local_file;
	char  *new_path_target, **buffer, *path_source, *columns, line[BUFFER_UNIT];
	int    x, f, buffer_count, buffer_max, *buffer_command_count;
	int    local_file_count, local_file_max, local_file_increment, termwidth;
	node  *this_file;
	DIR            *dp;
	struct dirent  *de;
	struct stat     sb;
	struct winsize  win;
	unsigned int    d, length;

	termwidth = -1;
	local_file_max = local_file_count = buffer_count = 0;
	local_file_increment = 2;
	buffer_max = 1;

	if ((local_file = (char **)malloc(sizeof(char **) * local_file_max)) == NULL)
		croak("build_source_directory_tree local_file malloc");

	if ((buffer = (char **)malloc(sizeof(char **))) == NULL)
		croak("build_source_directory_tree buffer malloc");

	if ((buffer_command_count = (int *)malloc(sizeof(int *))) == NULL)
		croak("build_source_directory_tree buffer_command_count malloc");

	if ((buffer[0] = (char *)malloc(COMMAND_BUFFER)) == NULL)
		croak("build_source_directory_tree buffer[0] malloc");

	bzero(buffer[0], COMMAND_BUFFER);
	buffer_command_count[0] = x = 0;

	start = send_receive_command(command, connection);

	directory = command;

	for (d = 0; d < connection->response_groups / 2; d++) {
		end = strchr(directory, '\n');
		*end = '\0';

		/* Extract the current path from the get-dir command. */

		if (strstr(directory, "( get-dir ( ") != directory) {
			fprintf(stderr, "Error in response: %s\n", directory);
			exit(EXIT_FAILURE);
			}

		directory += 12;
		value = directory;
		directory = strchr(directory, ':');
		*directory = '\0';
		length = strtol(value, (char **)NULL, 10);

		path_source = directory + 1;
		path_source[length] = '\0';
		directory = end + 1;

		length = strlen(path_target) + strlen(path_source) + 1;

		if ((new_path_target = (char *)malloc(length)) == NULL)
			croak("build_source_directory_tree new_path_target malloc");

		snprintf(new_path_target, length, "%s%s", path_target, path_source);

		if (connection->verbosity) {
			if (isatty(STDERR_FILENO)) {
				if (((columns = getenv("COLUMNS")) != NULL) && (*columns != '\0'))
					termwidth = strtol(columns, (char **)NULL, 10);
				else {
					if ((ioctl(STDERR_FILENO, TIOCGWINSZ, &win) != -1) && (win.ws_col > 0))
						termwidth = win.ws_col;
					}
				}

			snprintf(line, BUFFER_UNIT, " d %s", new_path_target);

			if ((termwidth == -1) || (strlen(line) < (unsigned int)termwidth))
				fprintf(stderr, "\e[2K%s\r", line);
			else
				fprintf(stderr, "\e[2K%.*s...\r", termwidth - 4, line);
			}

		/* Find all files/directories in the corresponding local directory. */

		if ((dp = opendir(new_path_target)) != NULL) {

			while ((de = readdir(dp)) != NULL) {
				if (strcmp(de->d_name, "." ) == 0) continue;
				if (strcmp(de->d_name, "..") == 0) continue;

				if (local_file_count == local_file_max) {
					if ((local_file = (char **)realloc(local_file, sizeof(char **) * (local_file_max + local_file_increment))) == NULL)
						croak("build_source_directory_tree local_directory realloc");

					for (x = local_file_max; x < local_file_max + local_file_increment; x++)
						if ((local_file[x] = (char *)malloc(MAXNAMLEN + 1)) == NULL)
							croak("build_source_directory_tree local_file realloc");

					local_file_max += local_file_increment;
					}

				snprintf(local_file[local_file_count++],
					MAXNAMLEN,
					"%s",
					de->d_name
					);
				}

			closedir(dp);
			free(new_path_target);
			}

		/* Parse the response for file/directory names. */

		end = strchr(start, '\n') + 1;
		end = strchr(end, '\n');
		*end = '\0';

		start = svn_check_command_success(start, end);

		while ((start) && (start = strchr(start, ':')) && (start < end)) {
			value = ++start;

			if ((start) && (start = strchr(start, ' '))) *start++ = '\0';

			/* Iterate through the local filenames and exclude any matches from later deletion. */

			for (f = 0; f < local_file_count; f++) {
				length = strlen(local_file[f]);

				if (length == strlen(value))
					if (strncmp(local_file[f], value, length) == 0)
						local_file[f][0] = '\0';
				}

			/* Keep track of the remote files. */

			if (strncmp(start, "file",  4) == 0) {
				if ((this_file = (node *)malloc(sizeof(node))) == NULL)
					croak("build_source_directory_tree file malloc");

				bzero(this_file->md5, 33);
				this_file->size = 0;
				this_file->raw_size = 0;

				length = strlen(path_source) + strlen(value) + 1;

				if ((this_file->path = (char *)malloc(length)) == NULL)
					croak("build_source_directory_tree this_file->path malloc");

				snprintf(this_file->path, length, "%s", path_source);

				length = strlen(value) + 1;

				if ((this_file->name = (char *)malloc(length)) == NULL)
					croak("build_source_directory_tree this_file->name malloc");

				snprintf(this_file->name, length, "%s", value);

				start = strchr(start, ' ');
				this_file->size = strtol(start, (char **)NULL, 10);

				(*file)[*file_count] = this_file;

				if (++(*file_count) == *max_file) {
					*max_file += BUFFER_UNIT;
					if ((*file = (node **)realloc(*file, *max_file * sizeof(node **))) == NULL)
						croak("build_source_directory_tree source realloc");
					}
				}

			if (strncmp(start, "dir",  3) == 0) {
				length = 2
					+ strlen(path_target)
					+ strlen(path_source)
					+ strlen(value);

				/* Create the directory locally if it doesn't exist. */

				if ((new_path_target = (char *)malloc(length)) == NULL)
					croak("build_source_directory_tree new_path_target malloc");

				snprintf(new_path_target,
					length,
					"%s%s/%s",
					path_target,
					path_source,
					value
					);

				if (lstat(new_path_target, &sb) == -1) {
					mkdir(new_path_target, 0755);
					if (connection->verbosity) fprintf(stdout, " + %s\n", new_path_target);
					}
				else {
					if (!S_ISDIR(sb.st_mode)) {
						prune(new_path_target);

						mkdir(new_path_target, 0755);
						if (connection->verbosity) fprintf(stdout, " + %s\n", new_path_target);
						}
					}

				free(new_path_target);

				/* Add a get-dir command to the command buffer. */

				length = strlen(path_source) + strlen(value) + 1;

				snprintf(temp_file,
					BUFFER_UNIT,
					"( get-dir ( %d:%s/%s ( %d ) false true ( kind size ) ) )\n",
					length,
					path_source,
					value,
					revision
					);

				length = strlen(buffer[buffer_count]);

				strncat(buffer[buffer_count], temp_file, COMMAND_BUFFER - length);

				buffer_command_count[buffer_count]++;
				if (length > COMMAND_BUFFER_THRESHOLD) {
					buffer_count++;
					buffer_max++;

					if ((buffer = (char **)realloc(buffer, sizeof(char **) * buffer_max)) == NULL)
						croak("build_source_directory_tree buffer realloc");

					if ((buffer_command_count = (int *)realloc(buffer_command_count, sizeof(int *) * buffer_max)) == NULL)
						croak("build_source_directory_tree buffer_command_count realloc");

					if ((buffer[buffer_count] = (char *)malloc(COMMAND_BUFFER)) == NULL)
						croak("build_source_directory_tree buffer[0] malloc");

					buffer_command_count[buffer_count] = 0;
					bzero(buffer[buffer_count], COMMAND_BUFFER);
					}
				}

			/* Skip to the next MD5 signature. */

			if ((start) && (start < end) && (start = strchr(start, ':'))) start++;
			if ((start) && (start < end) && (start = strchr(start, ':'))) start++;
			if ((start) && (start < end) && (start = strchr(start, ':'))) start++;
			}

		/* Remove any local files/directories that do not exist in the current directory. */

		for (f = 0; f < local_file_count; f++) {
			if (strlen(local_file[f]) > 0) {
				length = 2
					+ strlen(path_target)
					+ strlen(path_source)
					+ strlen(local_file[f]);

				snprintf(temp_file,
					length,
					"%s%s/%s",
					path_target,
					path_source,
					local_file[f]
					);

				prune(temp_file);
				}
			}

		start = end + 1;
		}

	/* Recursively process the command buffers. */

	x = 0;
	while (x <= buffer_count) {
		if (buffer_command_count[x]) {
			connection->response_groups = 2 * buffer_command_count[x];

			build_source_directory_tree(
				connection,
				buffer[x],
				file,
				file_count,
				max_file,
				path_target,
				revision
				);

			free(buffer[x]);
			}

		x++;
		}

	for (x = 0; x < local_file_max; x++) free(local_file[x]);
	free(local_file);

	free(buffer_command_count);
	free(buffer);
	}


/*
 * process_file_attributes
 *
 * Procedure that parses a get-file command response and extracts the MD5 checksum,
 * last author, committed revision number and committed date.
 */

void process_file_attributes(connector *connection, char *command, node **file, int file_start, int file_end, char *path_target) {
	char *start, *end, *temp, *md5, *columns, line[BUFFER_UNIT];
	char *last_author,    *last_author_end;
	char *committed_rev,  *committed_rev_end;
	char *committed_date, *committed_date_end;
	int  s, revision_tag_length, termwidth;
	struct winsize   win;

	termwidth = -1;

	connection->response_groups = 2 * (file_end - file_start + 1);

	start = send_receive_command(command, connection);

	for (s = file_start; s <= file_end; s++) {
		if (file[s] == NULL) continue;

		if (connection->verbosity) {
			if (isatty(STDERR_FILENO)) {
				if (((columns = getenv("COLUMNS")) != NULL) && (*columns != '\0'))
					termwidth = strtol(columns, (char **)NULL, 10);
				else {
					if ((ioctl(STDERR_FILENO, TIOCGWINSZ, &win) != -1) && (win.ws_col > 0))
						termwidth = win.ws_col;
					}
				}

			snprintf(line, BUFFER_UNIT, " f %s%s/%s", path_target, file[s]->path, file[s]->name);

			if ((termwidth == -1) || (strlen(line) < (unsigned int)termwidth))
				fprintf(stderr, "\e[2K%s\r", line);
			else
				fprintf(stderr, "\e[2K%.*s...\r", termwidth - 4, line);
			}

		start = svn_check_command_success(start, connection->response + connection->response_length);
		end = terminate_response(start, connection->response + connection->response_length);

		last_author    = last_author_end    = NULL;
		committed_rev  = committed_rev_end  = NULL;
		committed_date = committed_date_end = NULL;

		/* Extract the file attributes. */

		if ((start = strchr(start, ':')) != NULL) {
			md5 = ++start;
			start = strchr(start, ' ');
			*start++ = '\0';

			file[s]->revision_tag = NULL;
			snprintf(file[s]->md5, 33, "%s", md5);
			file[s]->executable = (strstr(start, "14:svn:executable") ? 1 : 0);

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
						+ strlen(file[s]->path)
						+ strlen(file[s]->name)
						+ strlen(committed_rev)
						+ strlen(committed_date)
						+ strlen(last_author);

					if ((file[s]->revision_tag = (char *)malloc(revision_tag_length)) == NULL)
						croak("process_file_attributes revision_tag malloc");

					snprintf(file[s]->revision_tag,
						revision_tag_length,
						": %s%s/%s %s %s %s ",
						connection->branch,
						file[s]->path,
						file[s]->name,
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
 * compare_md5
 *
 * Function that loads a local file and removes revision tags one at a time until
 * the MD5 checksum matches that of the corresponding repository file or the file
 * has run out of $ FreeBSD : markers.
 */

int compare_md5(node *source, char *file_path_target) {
	int     fd, mismatch;
	size_t  temp_size;
	char   *buffer, *start, *value, *eol;
	MD5_CTX md5_context;
	struct stat sb;

	mismatch = 1;

	if (lstat(file_path_target, &sb) != -1) {
		if ((buffer = (char *)malloc(sb.st_size + 1)) == NULL)
			croak("compare_md5 temp_buffer malloc");

		/* Load the file into memory. */

		if ((fd = open(file_path_target, O_RDONLY)) == -1) {
			fprintf(stderr, "read file (%s): %s\n", file_path_target, strerror(errno));
			exit(EXIT_FAILURE);
			}

		if (read(fd, buffer, sb.st_size) != sb.st_size) {
			fprintf(stderr, "read file (%s): file changed\n", file_path_target);
			exit(EXIT_FAILURE);
			}

		buffer[sb.st_size] = '\0';

		close(fd);

		temp_size = sb.st_size;
		start = buffer;

		/* Continue removing revision tags while the MD5 sums do not match. */

		while ((mismatch) && (start)) {
			MD5Init(&md5_context);
			MD5Update(&md5_context, buffer, temp_size);
			mismatch = strncmp(source->md5, MD5End(&md5_context, NULL), 33);

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

	return (mismatch);
	}


/*
 * get_files
 *
 */

void get_files(connector *connection, char *command, char *path_target, node **file, int file_start, int file_end, int revision) {
	int   x, t, out, temp, bytes_read, file_length_source, file_length_target;
	int   offset, position, block_size_markers, file_block_remainder;
	unsigned int   blocks, temp_file_length;
	int   total_bytes_read, raw_size, first_response, last_response;
	int   block_size, tag_length;
	char *temp_file, *file_path_source, *file_path_target;
	char *start, *end, *gap, *md5_check, *begin;
	MD5_CTX md5_context;

	file_length_source = MAXNAMLEN + 2;
	file_length_target = strlen(path_target) + MAXNAMLEN + 2;

	temp_file_length = 128 + (file_length_source > file_length_target ? file_length_source : file_length_target);

	if ((file_path_source = (char *)malloc(file_length_source)) == NULL)
		croak("get_files file_path_source malloc");

	if ((file_path_target = (char *)malloc(file_length_target)) == NULL)
		croak("get_files file_path_target malloc");

	if ((temp_file = (char *)malloc(temp_file_length)) == NULL)
		croak("get_files temp_file malloc");

	t = total_bytes_read = 0;

	/* Calculate the number of bytes the server is going to send back. */

	block_size_markers = raw_size = 0;

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

	send_command(command, connection);

	if (connection->verbosity) fprintf(stdout, "\r\e[2K\r");

	blocks = raw_size / BUFFER_UNIT + 2;
	position = raw_size;

	if (blocks > connection->response_blocks) {
		connection->response_blocks = blocks;
		connection->response = (char *)realloc(connection->response, connection->response_blocks * BUFFER_UNIT + 1);
		if (connection->response == NULL)
			croak("send_receive_command realloc");
		}

	while (total_bytes_read < raw_size) {
		bytes_read = -1;
		while (bytes_read == -1)
			bytes_read = read(
				connection->socket_descriptor,
				connection->response + total_bytes_read,
				connection->response_blocks * BUFFER_UNIT - total_bytes_read
				);

		total_bytes_read += bytes_read;

		if (connection->verbosity)
			fprintf(stderr, " %c\r", twirly[(t++ / 16) % 4]);
		}

	for (x = file_end; x >= file_start; x--) {
		if (file[x] == NULL) continue;

		snprintf(file_path_target,
			file_length_target,
			"%s%s/%s",
			path_target,
			file[x]->path,
			file[x]->name
			);

		end   = connection->response + position;
		start = end - file[x]->raw_size;

		/* Extract the file from the response stream. */

		start = svn_check_command_success(start, end);
		start = svn_check_command_success(start, end);
		start--;

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
			fprintf(stdout, " + %s\n", file_path_target);

		/* Insert revision tags if any exist. */

		if (file[x]->revision_tag) {
			tag_length = strlen(file[x]->revision_tag);

			while (((start = strstr(begin, "$FreeBSD$")) != NULL) && (start < end) && (tag_length > 0)) {
				start += 8;
				memmove(start + tag_length, start, file[x]->size - (start - begin));
				memcpy(start, file[x]->revision_tag, tag_length);

				file[x]->size += tag_length;
				end += tag_length;
				}
			}

		/* Make sure the MD5 checksums match before saving the file. */

		if (strncmp(file[x]->md5, md5_check, 33) != 0) {
			fprintf(stderr, "MD5 checksum mismatch: should be %s, calculated %s\n", file[x]->md5, md5_check);
			exit(EXIT_FAILURE);
			}

		if ((out = open(file_path_target, O_WRONLY | O_CREAT | O_TRUNC)) == -1) {
			fprintf(stderr, "write file failure %s: %s\n", file_path_target, strerror(errno));
			exit(EXIT_FAILURE);
			}

		write(out, begin, file[x]->size);
		close(out);

		chmod(file_path_target, file[x]->executable ? 0755 : 0644);

		position -= file[x]->raw_size;
		bzero(connection->response + position, file[x]->raw_size);

		free(file[x]->path);
		free(file[x]->name);
		if (file[x]->revision_tag) free(file[x]->revision_tag);
		free(file[x]);
		file[x] = NULL;
		}

	if (total_bytes_read != raw_size) {
		fprintf(stderr, "total_bytes_read != raw_size: %d %d\n", total_bytes_read, raw_size);
		exit(EXIT_FAILURE);
		}

	free(temp_file);
	free(file_path_source);
	free(file_path_target);
	}


/*
 * usage
 *
 */

void usage(void) {
	fprintf(stderr, "Usage: svnup -h host -b branch\n");
	fprintf(stderr, "  Options:\n");
	fprintf(stderr, "    -4  Use IPv4 addresses only.\n");
	fprintf(stderr, "    -6  Use IPv6 addresses only.\n");

	fprintf(stderr, "    -b  The Subversion branch to retrieve.\n");

	fprintf(stderr, "    -h  The hostname or IP address of the Subversion repository.\n");

	fprintf(stderr, "    -l  The local directory to save the repository's files to.\n");

	fprintf(stderr, "    -p  The port to connect to (defaults to 3690 if this option is\n");
	fprintf(stderr, "          not specified).\n");

	fprintf(stderr, "    -r  The revision number to retreive (defaults to the branch's\n");
	fprintf(stderr, "          most recent revision if this option is not specified).\n");

	fprintf(stderr, "    -v  How verbose the output should be (0 = no output, 1 = the\n");
	fprintf(stderr, "          default normal output, 2 = also show command and response\n");
	fprintf(stderr, "          text, 3 = also show command response parsing codes).\n");

	exit(EXIT_FAILURE);
	}


/*
 * main
 *
 */

int main(int argc, char **argv) {
	char  *start, *value, *addr, *branch, *path_target;
	char   temp_file[BUFFER_UNIT], command[COMMAND_BUFFER + 1];
	int    option, revision, port, family, x, x0, temp, revision_length;
	int    max_file, file_count, length;
	node **file;

	struct sockaddr_in  sin;
	struct in_addr      hostaddr;
	struct hostent     *host;
	struct stat         local_directory;
	connector           connection;

	connection.verbosity = 1;
	port = revision = file_count = 0;
	family = AF_INET;
	max_file = BUFFER_UNIT;

	addr = branch = path_target = NULL;

	while ((option = getopt(argc, argv, "46b:h:l:p:r:v:V")) != -1) {
		switch (option) {
			case '4': family = AF_INET;  break;
			case '6': family = AF_INET6; break;
			case 'b': branch = strdup(optarg); break;
			case 'h': addr = strdup(optarg); break;
			case 'l': path_target = strdup(optarg); break;
			case 'p': port = strtol(optarg, (char **)NULL, 10); break;
			case 'r': revision = strtol(optarg, (char **)NULL, 10); break;
			case 'v': connection.verbosity = strtol(optarg, (char **)NULL, 10); break;
			case 'V': fprintf(stdout, "svnup version 0.56\n"); exit(0);
			}
		}

	if ((port <= 0) || (port > 65535)) port = 3690;

	if (addr == NULL) usage();

	if (branch == NULL) usage();
	else {
		connection.branch = branch;
		if (strchr(branch, '/')) connection.branch = strchr(branch, '/') + 1;
		}

	if (path_target == NULL) path_target = getcwd(NULL, 1);

	if (lstat(path_target, &local_directory) != -1) {
		if (!S_ISDIR(local_directory.st_mode)) {
			fprintf(stderr, "%s is not a directory\n", path_target);
			exit(EXIT_FAILURE);
			}
		}
	else {
		if (mkdir(path_target, 0755))
			croak("Cannot create target directory.");
		}

	connection.response_blocks = 128;
	connection.response_length = 0;

	if ((connection.response = (char *)malloc(connection.response_blocks * BUFFER_UNIT + 1)) == NULL)
		croak("main connection.response malloc");

	hostaddr.s_addr = inet_addr(addr);
	if ((host = gethostbyaddr((const void *)&hostaddr, sizeof(hostaddr), family)) == NULL) {
		if ((host = gethostbyname(addr)) == NULL) {
			fprintf(stderr, "host lookup failed (%s) - %s\n", addr, strerror(errno));
			exit(EXIT_FAILURE);
			}
		}

	if ((connection.socket_descriptor = socket(family, SOCK_STREAM, 0)) < 0)
		croak("socket failure");

	bzero((char *) &sin, sizeof(sin));
	sin.sin_family = family;
	sin.sin_port = htons(port);
	bcopy(host->h_addr, &sin.sin_addr, host->h_length);

	if (connect(connection.socket_descriptor, (struct sockaddr *)&sin, sizeof(sin)) < 0)
		croak("connect failure");

	fcntl(connection.socket_descriptor, F_SETFL, O_NONBLOCK);

	connection.response_groups = 1;
	send_receive_command("", &connection);

	/* Send initial response string. */

	snprintf(command,
		COMMAND_BUFFER,
		"( 2 ( edit-pipeline svndiff1 absent-entries commit-revprops depth log-revprops atomic-revprops partial-replay ) %ld:svn://%s/%s 10:svnup-0.56 ( ) )\n",
		strlen(addr) + strlen(branch) + 7,
		addr,
		branch
		);

	send_receive_command(command, &connection);

	start = svn_check_command_success(connection.response, connection.response + connection.response_length);

	/* Login anonymously. */

	if (strstr(connection.response, "ANONYMOUS") == NULL)
		croak("Anonymous read is not allowed.");

	connection.response_groups = 2;
	send_receive_command("( ANONYMOUS ( 0: ) )\n", &connection);

	/* Get latest revision number. */

	if (revision <= 0) {
		send_receive_command("( get-latest-rev ( ) )\n", &connection);

		start = svn_check_command_success(connection.response, connection.response + connection.response_length);

		if ((start != NULL) && (start == strstr(start, "( success ( "))) {
			start += 12;
			value = start;
			while (*start != ' ') start++;
			*start = '\0';

			revision = strtol(value, (char **)NULL, 10);
			}
		else croak("Cannot retrieve latest revision.");
		}

	revision_length = 1;
	temp = revision;
	while ((int)(temp /= 10) > 0) revision_length++;

	if (connection.verbosity) printf("####### Fetching revision: %d\n", revision);

	/* Check to make sure client-supplied remote path is a directory. */

	snprintf(command,
		COMMAND_BUFFER,
		"( check-path ( 0: ( %d ) ) )\n",
		revision);
	send_receive_command(command, &connection);

	if (strcmp(connection.response, "( success ( ( ) 0: ) )\n( success ( dir ) )\n") != 0)
		croak("Remote path is not a directory.\n");

	/* Traverse the directory tree gathering files and directories. */

	if ((file = (node **)malloc(sizeof(node **) * max_file)) == NULL)
		croak("process_directory source malloc");

	snprintf(command,
		COMMAND_BUFFER,
		"( get-dir ( 0: ( %d ) false true ( kind size ) ) )\n",
		revision);

	connection.response_groups = 2;

	build_source_directory_tree(&connection, command, &file, &file_count, &max_file, path_target, revision);
	if (connection.verbosity) fprintf(stdout, "\r\e[2K\r");
	command[0] = '\0';

	for (x = 0, x0 = 0; x < file_count; x++) {
		if (file[x] == NULL) continue;

		snprintf(temp_file,
			BUFFER_UNIT,
			"( get-file ( %zd:%s/%s ( %d ) true false ) )\n",
			strlen(file[x]->path) + strlen(file[x]->name) + 1,
			file[x]->path,
			file[x]->name,
			revision
			);

		length = strlen(command);

		strncat(command, temp_file, COMMAND_BUFFER - length);

		if (length > COMMAND_BUFFER_THRESHOLD) {
			process_file_attributes(&connection, command, file, x0, x, path_target);
			command[0] = '\0';
			x0 = x + 1;
			}
		}

	process_file_attributes(&connection, command, file, x0, x - 1, path_target);

	if (connection.verbosity) fprintf(stderr, "\r\e[2K\r");

	command[0] = '\0';
	connection.response_groups = 0;

	for (x = 0, x0 = 0; x < file_count; x++) {
		if (file[x] == NULL) continue;

		snprintf(temp_file,
			BUFFER_UNIT,
			"%s%s/%s",
			path_target,
			file[x]->path,
			file[x]->name
			);

		/*
		 * If the MD5 checksums match, then skip the file, otherwise add it
		 * to the command buffer for download.
		 */

		if (compare_md5(file[x], temp_file) == 0) {
			if (file[x]) {
				free(file[x]->path);
				free(file[x]->name);
				if (file[x]->revision_tag) free(file[x]->revision_tag);
				free(file[x]);
				file[x] = NULL;
				}
			}
		else {
			connection.response_groups += 2;

			snprintf(temp_file,
				BUFFER_UNIT,
				"( get-file ( %zd:%s/%s ( %d ) false true ) )\n",
				strlen(file[x]->path) + strlen(file[x]->name) + 1,
				file[x]->path,
				file[x]->name,
				revision
				);

			length = strlen(command);

			strncat(command, temp_file, COMMAND_BUFFER - length);

			if (length > COMMAND_BUFFER_THRESHOLD) {
				get_files(&connection, command, path_target, file, x0, x, revision);
				command[0] = '\0';
				connection.response_groups = 0;
				x0 = x + 1;
				}
			}
		}

	if (strcmp(command, "") != 0)
		get_files(&connection, command, path_target, file, x0, x - 1, revision);

	/* Wrap it all up. */

	if (close(connection.socket_descriptor) != 0)
		if (errno != EBADF) croak("close_connection");

	if (addr) free(addr);
	if (branch) free(branch);
	if (path_target) free(path_target);

	free(connection.response);
	free(file);

	if (connection.verbosity) fprintf(stdout, "\e[2K\n");

	return (0);
	}
