#undef CMD_INC_FILE
#define CMD_INC_FILE sed-builtin

#if !defined(SED_BUILTIN) || defined(CMD_HEADER_MULTI_READ)
#define SED_BUILTIN



#include "cmd.h"
COMMAND_LIST(
	ENTRY("sed-save", "Save Password to unlock LR during resume-from-suspen", __sed_save)
	ENTRY("sed-lock-state", "Lock or Unlock the locking range", __sed_lock_unlock)
	ENTRY("sed-ownership", "Bring a controller out of a factory setting", __sed_ownership)
	ENTRY("sed-activatelsp", "Activate the Locking SP", __sed_activatelsp)
	ENTRY("sed-reverttper", "Revert the TPer to Factory settings *THIS WILL ERASE YOUR DATA*", __sed_reverttper)
	ENTRY("sed-setuplr", "Set up locking ranges", __sed_setuplr)
	ENTRY("sed-addusertolr", "Add Users to Locking ranges", __sed_add_usr_to_lr)
	ENTRY("sed-shadowMBR", "Enable or Disable Shadow MBR", __sed_shadowmbr)
	ENTRY("sed-setpw", "Set Password for UserN/Admin1", __sed_setpw)
	ENTRY("sed-enable-user", "Enable a user in the Locking SP", __sed_enable_user)
	ENTRY("sed-eraselr", "Erase a locking range", __sed_erase_lr)
	ENTRY("sed-secure-eraselr", "Erase a locking range", __sed_secure_erase_lr)
);
#endif
#include "define_cmd.h"
