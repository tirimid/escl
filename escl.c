#include <limits.h>
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

static char const *hashpasswd(char const *passwd);
static int execargs(int argc, char const *argv[]);
static char *getpasswd(char const *prompt);
static int conf_add(char const *label, char const *data);
static int conf_rm(char const *label, char const *data);
static ssize_t conf_find(char const *label, char const *data);

int
main(int argc, char const *argv[])
{
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
	
	char const *hash = hashpasswd(passwd);
	explicit_bzero(passwd, strlen(passwd) * sizeof(char));
	free(passwd);

	if (conf_find("passwd", hash) == -1) {
		fputs("authentication failed\n", stderr);
		return 1;
	}

	if (setuid(0)) {
		fputs("failed to become root\n", stderr);
		return 1;
	}
	
	return execvp(argv[firstarg], (char *const *)argv + firstarg);
}

static char const *
hashpasswd(char const *passwd)
{
	char hname[HOST_NAME_MAX + 1];
	gethostname(hname, HOST_NAME_MAX);

	// repeatedly use hostname to determine salt.
	// individual user-related details cannot be used, as the passwords must
	// apply globally to any user who wishes to use them - thus, the "global"
	// scale is used: the machine which the users are on.
	// this is still perfectly workable for the intended use case.
	char *iterh = strdup(crypt(passwd, "pw"));
	
	for (size_t i = 0, slen = strlen(hname); i < slen; i += 2) {
		char salt[3] = {hname[i], hname[i + 1] ? hname[i + 1] : 'w', 0};
		char *tmph = iterh;
		iterh = strdup(crypt(tmph, salt));
		free(tmph);
	}

	char const *reth = crypt(iterh, "pw");
	free(iterh);
	
	return reth;
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
			puts("options:");
			puts("\t-h          display this menu");
			puts("\t-ua (user)  give a user the ability to use escl");
			puts("\t-ur (user)  remove a user's ability to use escl");
			puts("\t-pa (pass)  add an escl password");
			puts("\t-pr (pass)  remove an escl password");

			exit(0);
		} else if (!strcmp(argv[i], "ua")) {
			if (conf_add("user", argv[++i])) {
				fprintf(stderr, "failed to add user: %s\n", argv[i]);
				exit(1);
			}
		} else if (!strcmp(argv[i], "ur")) {
			if (conf_rm("user", argv[++i])) {
				fprintf(stderr, "failed to remove user: %s\n", argv[i]);
				exit(1);
			}
		} else if (!strcmp(argv[i], "pa")) {
			if (conf_add("passwd", hashpasswd(argv[++i]))) {
				fprintf(stderr, "failed to add password: %s\n", argv[i]);
				exit(1);
			}
		} else if (!strcmp(argv[i], "pr")) {
			if (conf_rm("passwd", hashpasswd(argv[++i]))) {
				fprintf(stderr, "failed to remove password: %s\n", argv[i]);
				exit(1);
			}
		} else {
			fprintf(stderr, "unsupported option: %s\n", argv[i]);
			exit(1);
		}
	}

	return i;
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

	char *lptr = NULL;
	size_t n;
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
	if (getuid())
		return 1;

	if (!label || !data)
		return 1;

	char tmpfname[32];
	sprintf(tmpfname, "/tmp/escl%x\n", getpid());

	// write conf (with modifications) to tmpfile.
	FILE *tmpfp = fopen(tmpfname, "w");
	if (!(tmpfp = fopen(tmpfname, "w")))
		return 1;

	FILE *fp = fopen(CONF_FILE, "r");
	if (!fp) {
		fclose(tmpfp);
		return 1;
	}

	char *labeldata = malloc(strlen(label) + strlen(data) + 3);
	sprintf(labeldata, "%s %s\n", label, data);

	char *lptr = NULL;
	size_t n;
	while (getline(&lptr, &n, fp) != -1) {
		if (strcmp(labeldata, lptr))
			fputs(lptr, tmpfp);
	}

	free(lptr);

	/* copy tmpfile back into conf. */
	if (!(tmpfp = freopen(tmpfname, "r", tmpfp))) {
		free(labeldata);
		return 1;
	}

	lptr = NULL;
	if (!(fp = freopen(CONF_FILE, "w", fp))) {
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
