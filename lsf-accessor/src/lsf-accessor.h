#ifndef __LSF_ACCESSOR_H__
#define __LSF_ACCESSOR_H__

#include <stdio.h>
#include <stdlib.h>

#define LSF_ACCESSOR_VERSION       "0.0.1"
#define LSF_PASSPHRASE_DIR "/var/tmp/lsf/.passphrase"

typedef enum {
  LSF_ACCESSOR_OPT_INSERT,
  LSF_ACCESSOR_OPT_DELETE,
  LSF_ACCESSOR_OPT_UPDATE
} LSF_ACCESSOR_OPT;

typedef enum {
  LSF_ACCESSOR_FIELD_PUBLIC_KEY,
  LSF_ACCESSOR_FIELD_SETTINGS, 
  LSF_ACCESSOR_FIELD_HASH_CHECK,
  LSF_ACCESSOR_FIELD_START_CMD,
  LSF_ACCESSOR_FIELD_STOP_CMD,
  LSF_ACCESSOR_FIELD_APP_USING,
  LSF_ACCESSOR_FIELD_EXE_TYPE,
  LSF_ACCESSOR_FIELD_PRIVATE_KEY,
  LSF_ACCESSOR_FIELD_PERMISSION,
  LSF_ACCESSOR_FIELD_DISPLAY_NAME,
  LSF_ACCESSOR_FIELD_ABS_PATH,
  LSF_ACCESSOR_FIELD_AUTO_UPDATE,
  LSF_ACCESSOR_FIELD_EXP,
  LSF_ACCESSOR_FIELD_DBUS_NAME,
  LSF_ACCESSOR_FIELD_NUMS
} LSF_ACCESSOR_FIELD;

const char *lsf_accessor_key[] = { "public_key", "settings",
                           "hash_check", "start_cmd",
                           "stop_cmd", "app_using",
                           "exe_type", "private_key",
                           "permission", "display_name",
                           "abs_path", "auto_update",
                           "exp", "dbus_name" };

const char *lsf_modules[] = { "kr.gooroom.ghub", "kr.gooroom.gauth", "kr.gooroom.gcontroller",
                              "kr.gooroom.agent", "kr.gooroom.controlcenter",
                              "kr.gooroom.gfim", NULL };

char *lsf_accessor_value[LSF_ACCESSOR_FIELD_NUMS] = { NULL, NULL,
                                      "false", NULL,
                                      "", "true",
                                      "non systemd service", NULL,
                                      "root", NULL,
                                      NULL, "false",
                                      "12", NULL };

#endif
