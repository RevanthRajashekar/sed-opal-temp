int sed_save(int fd, int lr, char *user, char *lock_type, char *password);
int sed_lock_unlock(int fd, int lr, char *user, char *lock_type, char *password);
int sed_ownership(int fd, int lr, char *password);
int sed_activatelsp(int fd, char *password, char *lr_str);
int sed_reverttper(int fd, int lr, char *password);
int sed_setuplr(int fd, int lr, char *user, char *password, size_t range_start, size_t range_length);
int sed_add_usr_to_lr(int fd, int lr, char *user, char *lock_type, char *password);
int sed_shadowmbr(int fd, char *password);
int sed_setpw(int fd, char *user_for_pw, char *new_password, char *lsp_authority, char *authority_pw);
int sed_enable_user(int fd, char *user, char *password);
int sed_erase_lr(int fd, int lr, char *user, char *password);
int sed_secure_erase_lr(int fd, int lr, char *user, char *password);

