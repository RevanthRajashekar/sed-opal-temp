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

static const char *devicename;
static const char *lr_d = "The locking range we wish to unlock.";
static const char *user_d = "User Authority to unlock as User[1..9] or Admin1";
static const char *pw_d = "The password up to 254 characters";
static const char *sum_d = "Specify whether to unlock in sum or in Opal SSC mode";
static const char *key_d = "Specify whether to store the password in secure Kernel Key Ring";
static const char *lt_d = "String specifying how to lock/unlock/etc: RW/RO/LK";

//extern struct command *commands[];

#define CREATE_CMD
#include "sed-builtin.h"


#include "sed.h"

static struct plugin builtin = {
	.commands = commands,
	.name = NULL,
	.desc = NULL,
	.next = NULL,
	.tail = &builtin,
};

struct config {
		__u8 lr;
		char *user;
		char *lock_type;
		char *password;
		bool sum;
		int  fd;
};

struct config2 {
		__u8 lr;
		char *password;
		int  fd;
};

static struct program sed_opal = {
	.name = "sed-opal",
	.version = "1.0",
	.usage = "<command> [<device>] [<args>]",
	.desc = "The '<device>' must be a block device. "\
		"(ex: /dev/nvme0n1).",
	.extensions = &builtin,
};

static int open_dev(char *dev)
{
	int err, fd;
	struct stat _stat;

	devicename = basename(dev);
	err = open(dev, O_RDONLY);
	if (err < 0)
		goto perror;
	fd = err;

	err = fstat(fd, &_stat);
	if (err < 0)
		goto perror;
	if (!S_ISBLK(_stat.st_mode)) {
		fprintf(stderr, "%s is not a block device!\n", dev);
		return -ENODEV;
	}
	return fd;

perror:
	perror(dev);
	return err;
}

static int check_arg_dev(int argc, char **argv)
{
	if (optind >= argc) {
		errno = EINVAL;
		perror(argv[0]);
		return -EINVAL;
	}
	return 0;
}

static int get_dev(int argc, char **argv)
{
	int ret;

	ret = check_arg_dev(argc, argv);
	if (ret) {
		fprintf(stderr, "expected nvme device (ex: /dev/nvme0), none provided\n");
		return ret;
	}

	return open_dev(argv[optind]);
}

static int parse_and_open(int argc, char **argv, const char *desc,
			  const struct argconfig_commandline_options *clo,
			  void *cfg, size_t size)
{
	int ret;

	ret = argconfig_parse(argc, argv, desc, clo, cfg, size);
	if (ret)
		return ret;

	return get_dev(argc, argv);
}

static struct config *__do_generic_lkul(int argc, char **argv, struct command *cmd,
			   struct plugin *plugin, const char *desc)
{
	struct config *cfg = (struct config*)malloc(sizeof(struct config));
	const struct argconfig_commandline_options command_line_options[] = {
		{"lr", 'l', "NUM",       CFG_POSITIVE, &cfg->lr, required_argument, lr_d},
		{"user", 'u', "FMT",     CFG_STRING, &cfg->user, required_argument, user_d},
		{"locktype", 't', "FMT", CFG_STRING, &cfg->lock_type, required_argument, lt_d},
		{"password", 'p', "FMT", CFG_STRING, &cfg->password, required_argument, pw_d},
		{"sum",      's', ""   , CFG_NONE, &cfg->sum, no_argument, sum_d},
		{NULL}
	};

	cfg->fd = parse_and_open(argc, argv, desc, command_line_options, cfg, sizeof(cfg));

	if (cfg->fd < 0){
		free(cfg);
		return NULL;
	}

	return cfg;
}

static struct config2 *__do_generic_opal(int argc, char **argv, struct command *cmd,
			   struct plugin *plugin, const char *desc)
{
	struct config2 *cfg = (struct config2*)malloc(sizeof(struct config2));
	const struct argconfig_commandline_options command_line_options[] = {
		{"lr", 'l', "NUM",       CFG_POSITIVE, &cfg->lr, required_argument, lr_d},
		{"password", 'p', "FMT", CFG_STRING, &cfg->password, required_argument, pw_d},
		{NULL}
	};

	cfg->fd = parse_and_open(argc, argv, desc, command_line_options, cfg, sizeof(cfg));

	if (cfg->fd < 0){
		free(cfg);
		return NULL;
	}

	return cfg;
}

static int __sed_save(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "This method saves our password in the kernel. " \
		"This allows us to unlock the device after a suspent-to-ram";
	key_d = "ARGUMENT NOT USED";
	struct config *cfg = __do_generic_lkul(argc, argv, cmd, plugin, desc);
	if (cfg == NULL)
		return EINVAL;

	return sed_save(cfg->fd, cfg->lr, cfg->user, cfg->lock_type, cfg->password);
}

static int __sed_lock_unlock(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Lock Or Unlock a locking range.";

	struct config *cfg = __do_generic_lkul(argc, argv, cmd, plugin, desc);
	if (cfg == NULL)
		return EINVAL;

	return sed_lock_unlock(cfg->fd, cfg->lr, cfg->user, cfg->lock_type, cfg->password);
}

static int __sed_ownership(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Bring a controller out of a Factory inactive state "\
		"by setting the ADMIN CPIN password\n";
	struct config2 *cfg = __do_generic_opal(argc, argv, cmd, plugin, desc);

	if (cfg == NULL)
		return EINVAL;

	return sed_ownership(cfg->fd, cfg->lr, cfg->password);
}

static int __sed_activatelsp(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Activate the Locking SP. If you want to activate in sum provide a LR  > 0";
	const char *lrstr = "A list of lrs separated by , which you want to "\
		"activate. If you want to activate in normal mode provide an "\
		"empty string, If activiating in SUM do 1,2,3 if you want to activate"\
		"Those ranges, 1,5,4 etc...";

	struct config {
                bool sum;
		char *password;
		char *lr_str;
	};
	struct config cfg = { };
	const struct argconfig_commandline_options command_line_options[] = {
		{"password", 'p', "FMT", CFG_STRING, &cfg.password, required_argument, pw_d},
		{"lr_str", 'l', "FMT", CFG_STRING, &cfg.lr_str, required_argument, lrstr},
		{"sum",    's', ""   , CFG_NONE, &cfg.sum, no_argument, sum_d},
		{NULL}
	};

	int fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0)
		return EINVAL;

	return sed_activatelsp(fd, cfg.password, cfg.lr_str);
}

static int __sed_reverttper(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	char *desc = "Revert the TPer to factory State. *THIS WILL ERASE ALL YOUR DATA*";
	struct config2 *cfg = __do_generic_opal(argc, argv, cmd, plugin, desc);
	if (cfg == NULL)
		return EINVAL;

	return sed_reverttper(cfg->fd, cfg->lr, cfg->password);
}

static int __sed_setuplr(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Set up a locking range.";
	const char *rle_d = "Enable read locking on this LR";
	const char *wle_d = "Enable Write locking on this LR";
	const char *rs_d = "Where the Locking range should start";
	const char *rl_d = "Length of the Locking range";

	int fd;

	struct config {
		__u8 lr;
		char *user;
		char *password;
		bool sum;
		bool RLE;
		bool WLE;
		size_t range_start;
		size_t range_length;
	};

	struct config cfg = {
		.range_start = 0,
		.range_length = 0,
		.WLE = false,
		.RLE = false
	};
	const struct argconfig_commandline_options command_line_options[] = {
		{"lr", 'l', "NUM",       CFG_POSITIVE, &cfg.lr, required_argument, lr_d},
		{"user", 'u', "FMT",     CFG_STRING, &cfg.user, required_argument, user_d},
		{"password", 'p', "FMT", CFG_STRING, &cfg.password, required_argument, pw_d},
		{"sum",      's', ""   , CFG_NONE, &cfg.sum, no_argument, sum_d},
		{"readLockEnabled", 'r', "", CFG_NONE, &cfg.RLE, no_argument, rle_d},
		{"writeLockEnabled", 'w', "", CFG_NONE, &cfg.WLE, no_argument, wle_d},
		{"rangeStart", 'z', "NUM", CFG_POSITIVE, &cfg.range_start, required_argument, rs_d},
		{"rangeLength", 'y', "NUM", CFG_POSITIVE, &cfg.range_length, required_argument, rl_d},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0)
		return EINVAL;

	return sed_setuplr(fd, cfg.lr, cfg.user, cfg.password, cfg.range_start, cfg.range_length);
}

static int __sed_add_usr_to_lr(int argc, char **argv, struct command *cmd,struct plugin *plugin)
{
	const char *desc = "Add user to Locking range. Non-sum only!";
	user_d = "User to add to the locking range";
	pw_d = "Admin1 Password";
	sum_d = key_d = "THIS FLAG IS UNUSED";

	struct config *cfg = __do_generic_lkul(argc, argv, cmd, plugin, desc);
	if (cfg == NULL)
		return EINVAL;

	return sed_add_usr_to_lr(cfg->fd, cfg->lr, cfg->user, NULL, cfg->password);
}

static int __sed_shadowmbr(int argc, char **argv, struct command *cmd,
			 struct plugin *plugin)
{

	const char *desc = "Enable or Disable the MBR Shadow";
	const char *mbr_d = "Enable or Disable the MBR Shadow";
	struct config {
		char *password;
		bool enable_mbr;
	};
	struct config cfg = { };
	const struct argconfig_commandline_options command_line_options[] = {
		{"password", 'p', "FMT", CFG_STRING, &cfg.password, required_argument, pw_d},
		{"enable_mbr", 'e', "NUM", CFG_NONE, &cfg.enable_mbr, no_argument, mbr_d},
		{NULL}
	};
	int fd;

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0)
		return EINVAL;

	return sed_shadowmbr(fd, cfg.password);
}

static int __sed_setpw(int argc, char **argv, struct command *cmd,
	      struct plugin *plugin)
{
	const char *newpw_d = "The new password";
	const char *lspa_d  = "The Authority to use when starting a session to the Locking SP";
	const char *apw_d   = "The Password for the Authority when starting a session to the Locking SP";
	const char *_user_d = "The User to change the password for. If Changing password for SUM Remember LR 1 == User2; LR 2 == User3  LR N == UserN+1";
	const char *desc = "Set password for a specific User/Admin. See Man page/Documentation on how to properly use this command";
	sum_d = "Whether to set the password for a sum user or a Opal SSC user";

	struct config {
		char *lsp_authority;
		char *user_for_pw;
		char *new_password;
		char *authority_pw;
		bool sum;
	};

	struct config cfg = { 0 };
	const struct argconfig_commandline_options command_line_options[] = {
		{"user", 'u', "FMT",     CFG_STRING, &cfg.user_for_pw, required_argument, _user_d},
		{"newUserPW", 'n', "FMT", CFG_STRING, &cfg.new_password, required_argument, newpw_d},
		{"lspAuthority", 'p', "FMT", CFG_STRING, &cfg.lsp_authority, required_argument, lspa_d},
		{"authorityPW", 'a', "FMT", CFG_STRING, &cfg.authority_pw, required_argument, apw_d},
		{"sum",      's', ""   , CFG_NONE, &cfg.sum, no_argument, sum_d},
		{NULL}
	};
	int fd;

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0)
		return EINVAL;

	return sed_setpw(fd, cfg.user_for_pw, cfg.new_password, cfg.lsp_authority, cfg.authority_pw);
}

static int __sed_enable_user(int argc, char **argv, struct command *cmd,
			   struct plugin *plugin)
{
	const char *desc = "Enable a user in the Locking SP";
	struct config {
		char *user;
		char *password;
	};
	struct config cfg = { };
	user_d = "User we want to enable";
	pw_d = "Admin1 Password";
	const struct argconfig_commandline_options command_line_options[] = {
		{"user", 'u', "FMT",     CFG_STRING, &cfg.user, required_argument, user_d},
		{"password", 'p', "FMT", CFG_STRING, &cfg.password, required_argument, pw_d},
		{NULL}
	};
	int fd;

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0)
		return EINVAL;

	return sed_enable_user(fd, cfg.user, cfg.password);
}

static int __sed_erase_lr(int argc, char **argv, struct command *cmd,
		 struct plugin *plugin)
{
	const char *desc = "Erase a Locking Range: *THIS ERASES YOUR DATA!*";
	struct config {
		__u8 lr;
		char *user;
		char *password;
		bool sum;
	};

	struct config cfg = { 0 };
	const struct argconfig_commandline_options command_line_options[] = {
		{"lr", 'l', "NUM",       CFG_POSITIVE, &cfg.lr, required_argument, lr_d},
		{"user", 'u', "FMT",     CFG_STRING, &cfg.user, required_argument, user_d},
		{"password", 'p', "FMT", CFG_STRING, &cfg.password, required_argument, pw_d},
		{"sum",      's', ""   , CFG_NONE, &cfg.sum, no_argument, sum_d},
		{NULL}
	};

	int fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0)
		return EINVAL;

	return sed_erase_lr(fd, cfg.lr, cfg.user, cfg.password);
}


static int __sed_secure_erase_lr(int argc, char **argv, struct command *cmd,
			struct plugin *plugin)
{
	const char *desc = "Secure erase a Locking Range: *THIS DELETES YOUR DATA*";
	struct config {
		char *user;
		char *password;
		__u8   lr;
		bool sum;
	};
	struct config cfg = {  };
	user_d = "Authority to start the session as.";
	pw_d = "Authority Password.";
	const struct argconfig_commandline_options command_line_options[] = {
		{"user", 'u', "FMT",     CFG_STRING, &cfg.user, required_argument, user_d},
		{"password", 'p', "FMT", CFG_STRING, &cfg.password, required_argument, pw_d},
		{"lr", 'l', "NUM",       CFG_POSITIVE, &cfg.lr, required_argument, lr_d},
		{"sum",      's', ""   , CFG_NONE, &cfg.sum, no_argument, sum_d},
		{NULL}
	};
	int fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0)
		return EINVAL;

	return sed_secure_erase_lr(fd, cfg.lr, cfg.user, cfg.password);
}

int main(int argc, char **argv)
{
	int ret;

	builtin.commands = commands;
	sed_opal.extensions->parent = &sed_opal;
	if (argc < 2) {
		general_help(&builtin);
		return EXIT_FAILURE;
	}

	ret = handle_plugin(argc - 1, &argv[1], sed_opal.extensions);
	if (ret == -ENOTTY)
		general_help(&builtin);

	return ret;
}
