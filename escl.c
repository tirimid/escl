#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <crypt.h>
#include <fcntl.h>
#include <pwd.h>
#include <strings.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>

#define CONF_FILE "/etc/escl.conf"

static int execargs(int argc, char const *argv[]);
static void gensalt(char out_salt[3]);
static char *getpasswd(char const *prompt);
static int conf_add(char const *label, char const *data);
static int conf_rm(ssize_t line);
static ssize_t conf_find(char const *label, char const *data);
static ssize_t conf_findhashed(char const *label, char const *data);

int
main(int argc, char const *argv[])
{
	srand(time(NULL));
	
	if (argc <= 1) {
		printf("usage: %s [options] command [...]\n", argv[0]);
		return 0;
	}

	int firstarg = execargs(argc, argv);
	if (firstarg == argc)
		return 0;

	char const *user = getpwuid(getuid())->pw_name;
	if (conf_find("user", user) == -1) {
		fprintf(stderr, "user is not authorized to use escl: %s\n", user);
		return 1;
	}

	char *passwd = getpasswd("password: ");
	if (!passwd) {
		fputs("failed to get password\n", stderr);
		return 1;
	}
	
	ssize_t pwline = conf_findhashed("passwd", passwd);
	explicit_bzero(passwd, strlen(passwd) * sizeof(char));
	free(passwd);

	if (pwline == -1) {
		fputs("authentication failed\n", stderr);
		return 1;
	}

	if (setuid(0)) {
		fputs("failed to become root\n", stderr);
		return 1;
	}
	
	if (execvp(argv[firstarg], (char *const *)argv + firstarg) == -1) {
		perror("failed to execute command");
		return 1;
	}
}

static int
execargs(int argc, char const *argv[])
{
	int i;
	
	for (i = 1; i < argc; ++i) {
		if (argv[i][0] != '-')
			break;
		
		++argv[i];

		if (!strcmp(argv[i], "h")) {
			puts("usage:");
			printf("\t%s [options] ...\n", argv[0]);
			puts("options:");
			puts("\t-h          display this menu");
			puts("\t-ua (user)  give a user the ability to use escl");
			puts("\t-ur (user)  remove a user's ability to use escl");
			puts("\t-pa         add an escl password");
			puts("\t-pr         remove an escl password");
		} else if (!strcmp(argv[i], "ua")) {
			++i;
			
			if (conf_find("user", argv[i]) != -1)
				continue;
			
			if (conf_add("user", argv[i])) {
				fprintf(stderr, "failed to add user: %s\n", argv[i]);
				exit(1);
			}
		} else if (!strcmp(argv[i], "ur")) {
			if (conf_rm(conf_find("user", argv[++i]))) {
				fprintf(stderr, "failed to remove user: %s\n", argv[i]);
				exit(1);
			}
		} else if (!strcmp(argv[i], "pa")) {
			char salt[3];
			gensalt(salt);

			char *passwd = getpasswd("add password: ");
			if (conf_findhashed("passwd", passwd) != -1) {
				explicit_bzero(passwd, strlen(passwd) * sizeof(char));
				free(passwd);
				continue;
			}
			
			int rc = conf_add("passwd", crypt(passwd, salt));
			
			explicit_bzero(passwd, strlen(passwd) * sizeof(char));
			free(passwd);

			if (rc) {
				fputs("failed to add password\n", stderr);
				exit(1);
			}
		} else if (!strcmp(argv[i], "pr")) {
			char *passwd = getpasswd("remove password: ");
			int rc = conf_rm(conf_findhashed("passwd", passwd));

			explicit_bzero(passwd, strlen(passwd) * sizeof(char));
			free(passwd);

			if (rc) {
				fputs("failed to remove password\n", stderr);
				exit(1);
			}
		} else {
			fprintf(stderr, "unsupported option: %s\n", argv[i]);
			exit(1);
		}
	}

	return i;
}

static void
gensalt(char out_salt[3])
{
	char const *saltchrs =
		"abcdefghijklmnopqrstuvwxyz"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"0123456789"
		"./";

	size_t sclen = strlen(saltchrs);

	out_salt[0] = saltchrs[rand() % sclen];
	out_salt[1] = saltchrs[rand() % sclen];
	out_salt[2] = 0;
}

static char *
getpasswd(char const *prompt)
{
	FILE *ttyfp = fopen(ctermid(NULL), "w+");
	if (!ttyfp)
		return NULL;

	fputs(prompt, ttyfp);
	fflush(ttyfp);

	struct termios old;
	if (tcgetattr(fileno(ttyfp), &old) == -1) {
		fclose(ttyfp);
		return NULL;
	}
	
	struct termios new = old;
	new.c_lflag &= ~ECHO;

	if (tcsetattr(fileno(ttyfp), TCSAFLUSH, &new) == -1) {
		fclose(ttyfp);
		return NULL;
	}

	char *lptr = NULL;
	size_t n;
	getline(&lptr, &n, ttyfp);
	lptr[strlen(lptr) - 1] = 0;
	
	tcsetattr(fileno(ttyfp), TCSAFLUSH, &old);
	putc('\n', ttyfp);
	
	fclose(ttyfp);

	return lptr;
}

static int
conf_add(char const *label, char const *data)
{
	if (getuid())
		return 1;

	if (!label || !data)
		return 1;

	FILE *fp = fopen(CONF_FILE, "a+");
	if (!fp)
		return 1;

	char *labeldata = malloc(strlen(label) + strlen(data) + 3);
	sprintf(labeldata, "%s %s\n", label, data);
	fputs(labeldata, fp);
	
	free(labeldata);
	fclose(fp);
	
	return 0;
}

static int
conf_rm(ssize_t line)
{
	if (getuid())
		return 1;

	if (line == -1)
		return 1;

	char tmpfname[32];
	sprintf(tmpfname, "/tmp/escl%x\n", getpid());

	// write conf (with modifications) to tmpfile.
	FILE *tmpfp = fopen(tmpfname, "w");
	if (!tmpfp)
		return 1;

	FILE *fp = fopen(CONF_FILE, "r");
	if (!fp) {
		fclose(tmpfp);
		return 1;
	}

	char *lptr = NULL;
	size_t n;
	ssize_t lcnt = -1;
	while (getline(&lptr, &n, fp) != -1) {
		if (++lcnt != line)
			fputs(lptr, tmpfp);
	}

	free(lptr);

	// copy tmpfile back into conf.
	if (!(tmpfp = freopen(tmpfname, "r", tmpfp)))
		return 1;
	
	if (!(fp = freopen(CONF_FILE, "w", fp))) {
		fclose(tmpfp);
		return 1;
	}

	lptr = NULL;
	while (getline(&lptr, &n, tmpfp) != -1)
		fputs(lptr, fp);

	free(lptr);
	fclose(fp);
	fclose(tmpfp);

	unlink(tmpfname);
	
	return 0;
}

static ssize_t
conf_find(char const *label, char const *data)
{
	if (!label || !data)
		return -1;

	FILE *fp = fopen(CONF_FILE, "r");
	if (!fp)
		return -1;

	char *labeldata = malloc(strlen(label) + strlen(data) + 3);
	sprintf(labeldata, "%s %s\n", label, data);

	char *lptr = NULL;
	size_t n;
	ssize_t rc = -1, line = -1;
	while (getline(&lptr, &n, fp) != -1) {
		++line;
		if (!strcmp(labeldata, lptr)) {
			rc = line;
			break;
		}
	}

	free(lptr);
	free(labeldata);
	fclose(fp);
	
	return rc;
}

static ssize_t
conf_findhashed(char const *label, char const *data)
{
	if (!label || !data)
		return -1;

	FILE *fp = fopen(CONF_FILE, "r");
	if (!fp)
		return -1;

	size_t lablen = strlen(label);
	char *pfx = malloc(lablen + 2);
	sprintf(pfx, "%s ", label);

	char *lptr = NULL;
	size_t n;
	ssize_t rc = -1, line = -1, llen;
	while ((llen = getline(&lptr, &n, fp)) != -1) {
		++line;

		if (llen < lablen + 3 || strncmp(lptr, pfx, lablen + 1))
			continue;

		char salt[3] = {lptr[lablen + 1], lptr[lablen + 2], 0};
		char const *hash = crypt(data, salt);

		char *labeldata = malloc(lablen + strlen(hash) + 3);
		sprintf(labeldata, "%s %s\n", label, hash);
		bool eql = !strcmp(labeldata, lptr);
		free(labeldata);
		
		if (eql) {
			rc = line;
			break;
		}
	}

	free(lptr);
	free(pfx);
	fclose(fp);
	
	return rc;
}
