#include "lsf-accessor.h"
#include "lsf-crypto-common.h"
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <json-c/json_object.h>
#include <json-c/json_util.h>
#include <json-c/json_tokener.h>

struct json_object *whitelist_obj;
struct json_object *public_key_obj;

int lsf_accessor_insert (char *dbus_name) {
  struct json_object *iter_obj;
  struct json_object *app_obj;
  struct json_object *key_obj;
  struct json_object *target_obj;
  char *passphrase = NULL;
  int cnt;
  int i, j;
  int md = 0;
  int ma = 0;
  int ms = 0;
  FILE *fp = NULL;
  char passphrase_file[BUFSIZ];

  json_object_object_get_ex (whitelist_obj, "policy", &iter_obj);
  for (i = 0; i < json_object_array_length (iter_obj); i++) {
    app_obj = json_object_array_get_idx (iter_obj, i);
    json_object_object_get_ex (app_obj, "dbus_name", &target_obj);
    if (!strcmp (dbus_name, json_object_get_string (target_obj))) {
      fprintf (stdout, "%s is already exist in whitelist, you may use update command.\n", dbus_name);
      return -1;
    }
  }

  if (!lsf_accessor_value[LSF_ACCESSOR_FIELD_DISPLAY_NAME]) {
    md = 1;
    lsf_accessor_value[LSF_ACCESSOR_FIELD_DISPLAY_NAME] = (char *) malloc (sizeof (char) * BUFSIZ);
    for (i = 0, j = 0; dbus_name[i]; i++) {
      if (dbus_name[i] == '.')
        j = 0;
      else
        lsf_accessor_value[LSF_ACCESSOR_FIELD_DISPLAY_NAME][j++] = dbus_name[i];
    }
    lsf_accessor_value[LSF_ACCESSOR_FIELD_DISPLAY_NAME][j] = '\0';
  }

  if (!lsf_accessor_value[LSF_ACCESSOR_FIELD_ABS_PATH]) {
    ma = 1;
    lsf_accessor_value[LSF_ACCESSOR_FIELD_ABS_PATH] = (char *) malloc (sizeof (char) * BUFSIZ);
    snprintf (lsf_accessor_value[LSF_ACCESSOR_FIELD_ABS_PATH], BUFSIZ, "/usr/bin/%s", lsf_accessor_value[LSF_ACCESSOR_FIELD_DISPLAY_NAME]);
  }

  if (!lsf_accessor_value[LSF_ACCESSOR_FIELD_START_CMD]) {
    ms = 1;
    lsf_accessor_value[LSF_ACCESSOR_FIELD_START_CMD] = (char *) malloc (sizeof (char) * BUFSIZ);
    snprintf (lsf_accessor_value[LSF_ACCESSOR_FIELD_START_CMD], BUFSIZ, "/usr/bin/%s", lsf_accessor_value[LSF_ACCESSOR_FIELD_DISPLAY_NAME]);
  }

  if (access (LSF_PASSPHRASE_DIR, F_OK))
    mkdir (LSF_PASSPHRASE_DIR, S_IRUSR | S_IWUSR | S_IXUSR);

  lsf_generate_encrypted_rsa_key (&lsf_accessor_value[LSF_ACCESSOR_FIELD_PUBLIC_KEY], &lsf_accessor_value[LSF_ACCESSOR_FIELD_PRIVATE_KEY], &passphrase);
  snprintf (passphrase_file, BUFSIZ, "%s/%s", LSF_PASSPHRASE_DIR, dbus_name);
  fp = fopen (passphrase_file, "w");
  fprintf (fp, "%s", passphrase);
  fclose (fp);
  chmod (passphrase_file, S_IRUSR);
  chown (passphrase_file, getpwnam ("root")->pw_uid, getgrnam ("root")->gr_gid);

  json_object_object_get_ex (whitelist_obj, "total_app_count", &iter_obj);
  cnt = json_object_get_int (iter_obj);
  json_object_object_del (whitelist_obj, "total_app_count");
  json_object_object_add (whitelist_obj, "total_app_count", json_object_new_int (cnt+1));

  json_object_object_get_ex (whitelist_obj, "policy_count", &iter_obj);
  cnt = json_object_get_int (iter_obj);
  json_object_object_del (whitelist_obj, "policy_count");
  json_object_object_add (whitelist_obj, "policy_count", json_object_new_int (cnt+1));

  json_object_object_get_ex (whitelist_obj, "policy", &iter_obj);
  app_obj = json_object_new_object ();
  for (i = 0; i < LSF_ACCESSOR_FIELD_NUMS; i++) {
    if (i == LSF_ACCESSOR_FIELD_SETTINGS)
      json_object_object_add (app_obj, lsf_accessor_key[i], json_object_new_object ());
    else
      json_object_object_add (app_obj, lsf_accessor_key[i], json_object_new_string (lsf_accessor_value[i]));
  }
  json_object_array_add (iter_obj, app_obj);

  json_object_object_get_ex (public_key_obj, "policy", &iter_obj);
  key_obj = json_object_new_object ();
  json_object_object_add (key_obj, lsf_accessor_key[LSF_ACCESSOR_FIELD_DBUS_NAME], json_object_new_string (lsf_accessor_value[LSF_ACCESSOR_FIELD_DBUS_NAME]));
  json_object_object_add (key_obj, lsf_accessor_key[LSF_ACCESSOR_FIELD_PUBLIC_KEY], json_object_new_string (lsf_accessor_value[LSF_ACCESSOR_FIELD_PUBLIC_KEY]));
  json_object_object_add (key_obj, lsf_accessor_key[LSF_ACCESSOR_FIELD_ABS_PATH], json_object_new_string (lsf_accessor_value[LSF_ACCESSOR_FIELD_ABS_PATH]));
  json_object_object_add (key_obj, lsf_accessor_key[LSF_ACCESSOR_FIELD_SETTINGS], json_object_new_object ());
  json_object_array_add (iter_obj, key_obj);

  if (md)
    free (lsf_accessor_value[LSF_ACCESSOR_FIELD_DISPLAY_NAME]);
  if (ma) 
    free (lsf_accessor_value[LSF_ACCESSOR_FIELD_ABS_PATH]);
  if (ms)
    free (lsf_accessor_value[LSF_ACCESSOR_FIELD_START_CMD]);
  free (lsf_accessor_value[LSF_ACCESSOR_FIELD_PUBLIC_KEY]);
  free (lsf_accessor_value[LSF_ACCESSOR_FIELD_PRIVATE_KEY]);
  free (passphrase);

  return 0;
}

int lsf_accessor_delete (char *dbus_name) {
  struct json_object *iter_obj;
  struct json_object *app_obj;
  struct json_object *target_obj;
  struct json_object *new_policy;
  struct json_object *new_pubset;
  char passphrase_file[BUFSIZ];
  int cnt;
  int i;
  int exist = 0;
  
  new_policy = json_object_new_array ();
  json_object_object_get_ex (whitelist_obj, "policy", &iter_obj);
  for (i = 0; i < json_object_array_length (iter_obj); i++) {
    app_obj = json_object_array_get_idx (iter_obj, i);
    json_object_object_get_ex (app_obj, "dbus_name", &target_obj);
    if (!strcmp (dbus_name, json_object_get_string (target_obj)))
      exist = 1;
    else
      json_object_array_add (new_policy, json_tokener_parse (json_object_to_json_string (app_obj)));
  }

  if (!exist) {
    fprintf (stdout, "%s is not in the whitelist.\n", dbus_name);
    return -1;
  }

  exist = 0;
  new_pubset = json_object_new_array ();
  json_object_object_get_ex (public_key_obj, "policy", &iter_obj);
  for (i = 0; i < json_object_array_length (iter_obj); i++) {
    app_obj = json_object_array_get_idx (iter_obj, i);
    json_object_object_get_ex (app_obj, "dbus_name", &target_obj);
    if (!strcmp (dbus_name, json_object_get_string (target_obj)))
      exist = 1;
    else
      json_object_array_add (new_pubset, json_tokener_parse (json_object_to_json_string (app_obj)));
  }

  if (!exist) {
    fprintf (stdout, "%s is not in the public key set.\n", dbus_name);
    return -1;
  }

  json_object_object_get_ex (whitelist_obj, "total_app_count", &iter_obj);
  cnt = json_object_get_int (iter_obj);
  json_object_object_del (whitelist_obj, "total_app_count");
  json_object_object_add (whitelist_obj, "total_app_count", json_object_new_int (cnt-1));

  json_object_object_get_ex (whitelist_obj, "policy_count", &iter_obj);
  cnt = json_object_get_int (iter_obj);
  json_object_object_del (whitelist_obj, "policy_count");
  json_object_object_add (whitelist_obj, "policy_count", json_object_new_int (cnt-1));

  json_object_object_del (whitelist_obj, "policy");
  json_object_object_add (whitelist_obj, "policy", new_policy);

  json_object_object_del (public_key_obj, "policy");
  json_object_object_add (public_key_obj, "policy", new_pubset);

  snprintf (passphrase_file, BUFSIZ, "%s/%s", LSF_PASSPHRASE_DIR, dbus_name);
  remove (passphrase_file);

  return 0;
}

int lsf_accessor_get (char *dbus_name) {
  FILE *fp = NULL;
  char passphrase_file[BUFSIZ] = { 0, };
  char passphrase[BUFSIZ] = { 0, };

  snprintf (passphrase_file, BUFSIZ, "%s/%s", LSF_PASSPHRASE_DIR, dbus_name);
  if (access (passphrase_file, F_OK)) {
    fprintf (stdout, "Cannot Get passphrase (%s)\n", dbus_name);
    return -1;
  } else {
    fp = fopen (passphrase_file, "r");
    fgets (passphrase, BUFSIZ, fp);
    fprintf (stdout, "passphrase: %s\n", passphrase);
    fclose (fp);
  }
  return 0;
}


int lsf_accessor_update (char *dbus_name) {
  lsf_accessor_delete (dbus_name);
  return lsf_accessor_insert (dbus_name);
}

void lsf_accessor_usage (void) {
  fprintf (stdout, "lsf-accessor %s\nUsage: lsf-accessor <command> [options...] <dbus-name>\n\n", LSF_ACCESSOR_VERSION);
  fprintf (stdout, "commands:\n");
  fprintf (stdout, "  insert - Insert new security app to policy\n");
  fprintf (stdout, "  delete - Delete security app from policy\n");
  fprintf (stdout, "  update - Update security app policy\n");
  fprintf (stdout, "  get    - Get security app passphrase\n\n");
  fprintf (stdout, "options:\n");
  fprintf (stdout, "  -h, --help         Help\n");
  fprintf (stdout, "  -p, --permission   App permission\n");
  fprintf (stdout, "  -d, --diplay-name  App display name\n");
  fprintf (stdout, "  -a, --abs-path     Abs path\n");
  fprintf (stdout, "  -e, --exp          Exp\n");
  fprintf (stdout, "  -l, --launch-cmd   App launch command\n");
  fprintf (stdout, "  -k, --kill-cmd     App stop command\n");
  fprintf (stdout, "  -f, --file         Base policy file\n");
}

int is_lsf_modules (char *dbus_name) {
  int i;

  for (i = 0; lsf_modules[i]; i++)
    if (!strcmp (lsf_modules[i], dbus_name))
      return 1;
  return 0;
}

int main (int argc, char *argv[]) {
  int i;
  char *whitelist_file = "/var/tmp/lsf/private/whitelist.policy";
  char *public_key_file = "/var/tmp/lsf/public/public_key.set";

  if (getuid () != getpwnam ("root")->pw_uid) {
    fprintf (stdout, "Permission denied. Only superuser can operate lsf-accessor.\n");
    exit (EXIT_SUCCESS);
  }

  if (argc < 3
      || !strcmp (argv[1], "-h")
      || !strcmp (argv[1], "--help")) {
    lsf_accessor_usage ();
    exit (EXIT_SUCCESS);
  }

  for (i = 2; i < argc; i++) {
    if (argv[i][0] == '-') {
      if (!strcmp (argv[i], "-p") || !strcmp (argv[i], "--permission"))
        lsf_accessor_value[LSF_ACCESSOR_FIELD_PERMISSION] = argv[(i++)+1];
      else if (!strcmp (argv[i], "-d") || !strcmp (argv[i], "--display-name"))
        lsf_accessor_value[LSF_ACCESSOR_FIELD_DISPLAY_NAME] = argv[(i++)+1];
      else if (!strcmp (argv[i], "-a") || !strcmp (argv[i], "--abs-path"))
        lsf_accessor_value[LSF_ACCESSOR_FIELD_ABS_PATH] = argv[(i++)+1];
      else if (!strcmp (argv[i], "-e") || !strcmp (argv[i], "--exp"))
        lsf_accessor_value[LSF_ACCESSOR_FIELD_EXP] = argv[(i++)+1];
      else if (!strcmp (argv[i], "-l") || !strcmp (argv[i], "--launch-cmd"))
        lsf_accessor_value[LSF_ACCESSOR_FIELD_START_CMD] = argv[(i++)+1];
      else if (!strcmp (argv[i], "-k") || !strcmp (argv[i], "--kill-cmd"))
        lsf_accessor_value[LSF_ACCESSOR_FIELD_STOP_CMD] = argv[(i++)+1];
      else if (!strcmp (argv[i], "-f") || !strcmp (argv[i], "--file"))
        whitelist_file = argv[(i++)+1];
      else {
        lsf_accessor_usage ();
        exit (EXIT_SUCCESS);
      }
    } else {
      lsf_accessor_value[LSF_ACCESSOR_FIELD_DBUS_NAME] = argv[i];
      break;
    }
  }

  whitelist_obj = json_object_from_file (whitelist_file);
  public_key_obj = json_object_from_file (public_key_file);

  if (!strcmp (argv[1], "insert"))
    lsf_accessor_insert (argv[i]);
  else if (!strcmp (argv[1], "delete")) {
    if (is_lsf_modules (argv[i])) 
      fprintf (stdout, "** Cannot Delete %s **\n", argv[i]);
    else
      lsf_accessor_delete (argv[i]);
  } else if (!strcmp (argv[1], "update")) {
    if (is_lsf_modules (argv[i]))
      fprintf (stdout, "** Cannot Update %s **\n", argv[i]);
    else
      lsf_accessor_update (argv[i]);
  } else if (!strcmp (argv[1], "get")) {
    if (is_lsf_modules (argv[i]))
      fprintf (stdout, "** Cannot Get passphrase (%s) **\n", argv[i]);
    else
      lsf_accessor_get (argv[i]);
  } else {
    lsf_accessor_usage ();
    exit (EXIT_FAILURE);
  }

  json_object_to_file ("/var/tmp/lsf/private/whitelist.policy", whitelist_obj);
  json_object_to_file ("/var/tmp/lsf/public/public_key.set", public_key_obj);

  exit (EXIT_SUCCESS);
}
