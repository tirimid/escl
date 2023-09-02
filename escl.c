#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <crypt.h>
#include <fcntl.h>
#include <pwd.h>
#include <strings.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>

#define CONF_FILE "/etc/escl.conf"
#define SALT "pw"

static char *getpasswd(char const *prompt);
static int conf_add(char const *label, char const *data);
static int conf_rm(char const *label, char const *data);
static ssize_t conf_find(char const *label, char const *data);

int
main(int argc, char const *argv[])
{
	int i, icp;
	char *passwd, *hash;
	char const *user = getpwuid(getuid())->pw_name;
	
	if (argc <= 1) {
		printf("usage: %s [options] command [...]\n", argv[0]);
		return 0;
	}

	for (i = 1; i < argc; ++i) {
		if (argv[i][0] != '-')
			break;
		
		++argv[i];

		if (!strcmp(argv[i], "h")) {
			puts("options:");
			puts("\t-h          display this menu");
			puts("\t-ua (user)  give a user the ability to use escl");
			puts("\t-ur (user)  remove a user's ability to use escl");
			puts("\t-pa (pass)  add an escl password");
			puts("\t-pr (pass)  remove an escl password");
			
			return 0;
		} else if (!strcmp(argv[i], "ua")) {
			if (conf_add("user", argv[++i])) {
				fprintf(stderr, "failed to add user: %s\n", argv[i]);
				return 1;
			}
		} else if (!strcmp(argv[i], "ur")) {
			if (conf_rm("user", argv[++i])) {
				fprintf(stderr, "failed to remove user: %s\n", argv[i]);
				return 1;
			}
		} else if (!strcmp(argv[i], "pa")) {
			if (conf_add("passwd", crypt(argv[++i], SALT))) {
				fprintf(stderr, "failed to add password: %s\n", argv[i]);
				return 1;
			}
		} else if (!strcmp(argv[i], "pr")) {
			if (conf_rm("passwd", crypt(argv[++i], SALT))) {
				fprintf(stderr, "failed to remove password: %s\n", argv[i]);
				return 1;
			}
		} else {
			fprintf(stderr, "unsupported option: %s\n", argv[i]);
			return 1;
		}
	}

	if (i == argc)
		return 0;

	if (conf_find("user", user) == -1) {
		fprintf(stderr, "user is not authorized to use escl: %s\n", user);
		return 1;
	}

	if (!(passwd = getpasswd("password: "))) {
		fputs("failed to get password\n", stderr);
		return 1;
	}
	
	hash = crypt(passwd, SALT);
	explicit_bzero(passwd, strlen(passwd));
	free(passwd);

	if (conf_find("passwd", hash) == -1) {
		fputs("authentication failed\n", stderr);
		return 1;
	}

	if (setuid(0)) {
		fputs("failed to become root\n", stderr);
		return 1;
	}
	
	return execvp(argv[i], (char *const *)argv + i);
}

static char *
getpasswd(char const *prompt)
{
	struct termios old, new;
	char *lptr = NULL;
	size_t n;
	FILE *ttyfp;
	
	if (!(ttyfp = fopen(ctermid(NULL), "w+")))
		return NULL;

	fputs(prompt, ttyfp);
	fflush(ttyfp);

	if (tcgetattr(fileno(ttyfp), &old) == -1) {
		fclose(ttyfp);
		return NULL;
	}
	
	new = old;
	new.c_lflag &= ~ECHO;

	if (tcsetattr(fileno(ttyfp), TCSAFLUSH, &new) == -1) {
		fclose(ttyfp);
		return NULL;
	}

	getline(&lptr, &n, ttyfp);
	
	tcsetattr(fileno(ttyfp), TCSAFLUSH, &old);
	putc('\n', ttyfp);
	
	fclose(ttyfp);

	return lptr;
}

static int
conf_add(char const *label, char const *data)
{
	FILE *fp;
	char *lptr = NULL, *labeldata;
	size_t n;

	if (getuid())
		return 1;

	if (!label || !data)
		return 1;

	if (!(fp = fopen(CONF_FILE, "a+")))
		return 1;

	labeldata = malloc(strlen(label) + strlen(data) + 3);
	sprintf(labeldata, "%s %s\n", label, data);

	while (getline(&lptr, &n, fp) != -1) {
		if (!strcmp(lptr, labeldata))
			goto exit;
	}

	fputs(labeldata, fp);

exit:
	free(labeldata);
	free(lptr);
	fclose(fp);
	
	return 0;
}

static int
conf_rm(char const *label, char const *data)
{
	FILE *fp, *tmpfp;
	char *labeldata, tmpfname[32], *lptr = NULL;
	size_t n;
	
	if (getuid())
		return 1;

	if (!label || !data)
		return 1;

	sprintf(tmpfname, "/tmp/escl%x\n", getpid());

	/* write conf (with modifications) to tmpfile. */
	if (!(tmpfp = fopen(tmpfname, "w")))
		return 1;

	if (!(fp = fopen(CONF_FILE, "r"))) {
		fclose(tmpfp);
		return 1;
	}

	labeldata = malloc(strlen(label) + strlen(data) + 3);
	sprintf(labeldata, "%s %s\n", label, data);

	while (getline(&lptr, &n, fp) != -1) {
		if (strcmp(labeldata, lptr))
			fputs(lptr, tmpfp);
	}

	free(lptr);
	lptr = NULL;
	fclose(fp);
	fclose(tmpfp);

	/* copy tmpfile back into conf. */
	if (!(tmpfp = fopen(tmpfname, "r"))) {
		free(labeldata);
		return 1;
	}

	if (!(fp = fopen(CONF_FILE, "w"))) {
		free(labeldata);
		fclose(tmpfp);
		return 1;
	}

	while (getline(&lptr, &n, tmpfp) != -1)
		fputs(lptr, fp);

	free(lptr);
	free(labeldata);
	fclose(fp);
	fclose(tmpfp);

	unlink(tmpfname);
	
	return 0;
}

static ssize_t
conf_find(char const *label, char const *data)
{
	FILE *fp;
	char *lptr = NULL, *labeldata;
	size_t n;
	ssize_t rc = -1, line = -1;

	if (!label || !data)
		return -1;

	if (!(fp = fopen(CONF_FILE, "r")))
		return -1;

	labeldata = malloc(strlen(label) + strlen(data) + 3);
	sprintf(labeldata, "%s %s\n", label, data);

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
