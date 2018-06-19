#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>


#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <libgen.h>
#include <fcntl.h>

#include "argconfig.h"
#include "sed-opal.h"
#include "plugin.h"

const char *devicename;
//extern struct command *commands[];

#define ARRAY_SIZE(x) ((size_t)(sizeof(x) / sizeof(x[0])))

#include "sed.h"

const char * const opal_errors[] = {
	"Success",
	"Not Authorized",
	"Unknown Error",
	"SP Busy",
	"SP Failed",
	"SP Disabled",
	"SP Frozen",
	"No Sessions Available",
	"Uniqueness Conflict",
	"Insufficient Space",
	"Insufficient Rows",
	"Invalid Function",
	"Invalid Parameter",
	"Invalid Reference",
	"Unknown Error",
	"TPER Malfunction",
	"Transaction Failure",
	"Response Overflow",
	"Authority Locked Out",
};

static int opal_error_to_human(int error)
{
	if (error == 0x3f) {
		printf("Failed\n");
		return error;
	}

	if (error >= ARRAY_SIZE(opal_errors) || error < 0) {
	       printf("Unknown Error");
	       printf("errno %s\n", strerror(errno));
	       return error;
	}

	printf("%s\n", opal_errors[error]);
	return error;
}

static int get_user(char *user, enum opal_user *who)
{
	unsigned int unum = 0;
	char *error;

	if (strlen(user) < 5) {
		fprintf(stderr, "Incorrect User, please provide userN/Admin1\n");
		return -EINVAL;
	}
	if (!strncasecmp(user, "admin", 5))
		*who = OPAL_ADMIN1;
	else if (!strncasecmp(user, "user", 4)) {
		unum = strtol(&user[4], &error, 10);
		if (error == &user[4]) {
			fprintf(stderr, "Failed to parse user # from string\n");
			return -EINVAL;
		}
		if (unum < OPAL_USER1 || unum > OPAL_USER9) {
			fprintf(stderr, "Incorrect User, please provide userN\n");
			return -EINVAL;
		}
		*who = unum;
	}
	else {
		fprintf(stderr, "Incorrect User, please provide userN/Admin1\n");
		return -EINVAL;
	}
	return 0;
}

static int get_lock(char *lock, enum opal_lock_state *lstate)
{
	if (strlen(lock) < 2) {
		fprintf(stderr, "Invalid Lock state\n");
		return EINVAL;
	}

	if (!strncasecmp(lock, "RW", 2))
		*lstate = OPAL_RW;
	else if(!strncasecmp(lock, "RO", 2))
		*lstate = OPAL_RO;
	else if(!strncasecmp(lock, "LK", 2))
		*lstate = OPAL_LK;
	else {
		fprintf(stderr, "Invalid Lock state\n");
		return EINVAL;
	}
	return 0;
}

static int do_generic_lkul(int fd, int lr, char *user, char *lock_type, char *password,
				unsigned long ioctl_cmd)
{
	bool sum = 0;
	struct opal_lock_unlock oln = { };

	if ( (!sum && user == NULL) || lock_type == NULL || password == NULL) {
		fprintf(stderr, "Need to supply user, lock type and password!\n");
		return EINVAL;
	}

	oln.session.sum = sum;
	if (!sum)
		if (get_user(user, &oln.session.who))
			return EINVAL;

	if (get_lock(lock_type, &oln.l_state))
		return EINVAL;

	oln.session.opal_key.key_len = snprintf((char *)oln.session.opal_key.key,
						sizeof(oln.session.opal_key.key),
						"%s", password);
	if (oln.session.opal_key.key_len == 0) {
		oln.session.opal_key.key_len = 1;
		oln.session.opal_key.key[0] = 0;
	}
	oln.session.opal_key.lr = lr;
	return opal_error_to_human(ioctl(fd, ioctl_cmd, &oln));
}

static int do_generic_opal(int fd, int lr, char *password, unsigned long ioctl_cmd)
{
	struct opal_key pw = { };

	if (password == NULL) {
		fprintf(stderr, "Must Provide a password for this command\n");
		return EINVAL;
	}

	pw.key_len = snprintf((char *)pw.key, sizeof(pw.key), "%s", password);
	pw.lr = lr;

	int ret = ioctl(fd, ioctl_cmd, &pw);
	printf("ioctl return value is : %s \n", strerror(ret));
	ret = opal_error_to_human(ioctl(fd, ioctl_cmd, &pw));
	perror("ioctl");
	return ret;
}

int sed_save(int fd, int lr, char *user, char *lock_type, char *password)
{
	return do_generic_lkul(fd, lr, user, lock_type, password, IOC_OPAL_SAVE);
}


int sed_lock_unlock(int fd, int lr, char *user, char *lock_type, char *password)
{
	return do_generic_lkul(fd, lr, user, lock_type, password, IOC_OPAL_LOCK_UNLOCK);
}

int sed_ownership(int fd, int lr, char *password)
{
	return do_generic_opal(fd, lr, password, IOC_OPAL_TAKE_OWNERSHIP);
}

int sed_activatelsp(int fd, char *password, char *lr_str)
{
	bool sum = 0;
	struct opal_lr_act opal_activate = { 0 };
	unsigned long parsed;
	size_t count = 0;
	char *num, *errchk;

	if (password == NULL || (sum && !lr_str)) {
		fprintf(stderr, "Must Provide a password, and a LR string if SUM \n");
		return EINVAL;
	}

	opal_activate.sum = sum;
	fprintf(stderr, "Sum is %d\n", sum);
	if (!lr_str)
		opal_activate.num_lrs = 1;
	else {
		num = strtok(lr_str, ",");
		while (num != NULL && count < OPAL_MAX_LRS) {
			parsed = strtoul(num, &errchk, 10);
			if (errchk == num)
				continue;
			opal_activate.lr[count] = parsed;
			fprintf(stderr, "added %lu to lr at index %zu\n", parsed, count);
			num = strtok(NULL, ",");
			count++;
		}
		opal_activate.num_lrs = count;
	}

	opal_activate.key.key_len = snprintf((char *)opal_activate.key.key,
					     sizeof(opal_activate.key.key),
					     "%s", password);

	return opal_error_to_human(ioctl(fd, IOC_OPAL_ACTIVATE_LSP,
					 &opal_activate));
}

int sed_reverttper(int fd, int lr, char *password)
{
	return do_generic_opal(fd, lr, password, IOC_OPAL_REVERT_TPR);
}

int sed_setuplr(int fd, int lr, char *user, char *password,
		size_t range_start, size_t range_length)
{
	struct opal_user_lr_setup setup = { };
	bool sum = 0;
	bool RLE = 0;
	bool WLE = 0;

	if (range_start == ~0 || range_length == ~0 || (!sum && user == NULL) ||
	    password == NULL) {

		    fprintf(stderr, "Incorrect parameters, please try again\n");
		    return EINVAL;
	}

	if (!sum)
		if (get_user(user, &setup.session.who))
			return -EINVAL;

	setup.session.sum = sum;

	setup.RLE = RLE;
	setup.WLE = WLE;

	setup.range_start = range_start;
	setup.range_length = range_length;

	setup.session.opal_key.key_len = snprintf((char *)setup.session.opal_key.key,
						  sizeof(setup.session.opal_key.key),
						  "%s", password);
	if (setup.session.opal_key.key_len == 0) {
		setup.session.opal_key.key_len = 1;
		setup.session.opal_key.key[0] = 0;
	}
	setup.session.opal_key.lr = lr;
	return opal_error_to_human(ioctl(fd, IOC_OPAL_LR_SETUP, &setup));
}

int sed_add_usr_to_lr(int fd, int lr, char *user, char *lock_type, char *password)
{
	return do_generic_lkul(fd, lr, user, lock_type, password, IOC_OPAL_ADD_USR_TO_LR);
}

int sed_shadowmbr(int fd, char *password)
{
	struct opal_mbr_data mbr = { };
	bool enable_mbr = 0;

	if (password == NULL) {
		fprintf(stderr, "Need ADMIN1 password for mbr shadow enable/disable\n");
		return EINVAL;
	}

	if (enable_mbr)
		mbr.enable_disable = OPAL_MBR_ENABLE;
	else
		mbr.enable_disable = OPAL_MBR_DISABLE;


	mbr.key.key_len = snprintf((char *)(char *)mbr.key.key,
				   sizeof(mbr.key.key),
				   "%s", password);
	return opal_error_to_human(ioctl(fd, IOC_OPAL_ENABLE_DISABLE_MBR, &mbr));
}

int sed_setpw(int fd, char *user_for_pw, char *new_password,
		char *lsp_authority, char *authority_pw)
{
	struct opal_new_pw pw = { };
	bool sum = 0;

	if (user_for_pw == NULL || lsp_authority == NULL ||
	    new_password == NULL || authority_pw == NULL) {
		fprintf(stderr, "Invalid arguments, please try again\n");
		return EINVAL;
	}

	if (get_user(user_for_pw, &pw.new_user_pw.who))
		return -EINVAL;
	if (get_user(lsp_authority, &pw.session.who))
		return -EINVAL;

	pw.session.sum = sum;

	pw.session.opal_key.lr = pw.session.who - 1;
	pw.session.opal_key.key_len = snprintf((char *)(char *)pw.session.opal_key.key,
					       sizeof(pw.session.opal_key.key),
					       "%s", authority_pw);
	/* In sum When we want to set a password as a user we start a
	 * session as that user. The user, however doesn't have a password.
	 * The spec states we send a NULL password. It's hard to send the NULL
	 * Character from cmd line so we let them leave the pw blank and fix
	 * it up here.
	 */
	if (pw.session.opal_key.key_len == 0) {
		pw.session.opal_key.key_len = 1;
		pw.session.opal_key.key[0] = 0;
	}

	pw.new_user_pw.opal_key.lr = pw.new_user_pw.who - 1;
	pw.new_user_pw.opal_key.key_len =
		snprintf((char *)(char *)pw.new_user_pw.opal_key.key,
			 sizeof(pw.new_user_pw.opal_key.key),
			 "%s", new_password);

	return opal_error_to_human(ioctl(fd, IOC_OPAL_SET_PW, &pw));
}

int sed_enable_user(int fd, char *user, char *password)
{
	struct opal_session_info usr = { };

	if (user == NULL || password == NULL) {
		fprintf(stderr, "Invalid arguments for %s\n", __func__);
		return EINVAL;
	}

	if (get_user(user, &usr.who))
		return EINVAL;

	if (usr.who == OPAL_ADMIN1) {
		fprintf(stderr, "Opal Admin is already activated by default!\n");
		return EINVAL;
	}
	usr.opal_key.key_len = snprintf((char *)usr.opal_key.key, sizeof(usr.opal_key.key),
				   "%s", password);
	usr.opal_key.lr = 0;
	return opal_error_to_human(ioctl(fd, IOC_OPAL_ACTIVATE_USR, &usr));
}

int sed_erase_lr(int fd, int lr, char *user, char *password)
{
	bool sum = 0;
	struct opal_session_info session;

	if ( (!sum && user == NULL) || password == NULL) {
		fprintf(stderr, "Need to supply user, lock type and password!\n");
		return EINVAL;
	}

	session.sum = sum;
	if (!sum)
		if (get_user(user, &session.who))
			return EINVAL;


	session.opal_key.key_len = snprintf((char *)session.opal_key.key,
					    sizeof(session.opal_key.key),
					    "%s", password);
	session.opal_key.lr = lr;
	return opal_error_to_human(ioctl(fd, IOC_OPAL_ERASE_LR, &session));
}

int sed_secure_erase_lr(int fd, int lr, char *user, char *password)
{
	struct opal_session_info usr = { };

	if (user == NULL || password == NULL) {
		fprintf(stderr, "Invalid arguments for %s\n", __func__);
		return EINVAL;
	}

	if (get_user(user, &usr.who))
		return EINVAL;

	usr.opal_key.key_len = snprintf((char *)usr.opal_key.key, sizeof(usr.opal_key.key),
				   "%s", password);
	usr.opal_key.lr = 0;
	return opal_error_to_human(ioctl(fd, IOC_OPAL_SECURE_ERASE_LR, &usr));
}
