#include "lsf-mockpanel.h"
#include <pwd.h>
#include <limits.h>
#include <webkit2/webkit2.h>
#include <lsf/lsf-main.h>
#include <lsf/lsf-util.h>
#include <lsf/lsf-auth.h>
#include <lsf/lsf-dbus.h>
#include <json-c/json_object.h>
#include <json-c/json_tokener.h>
#include <json-c/json_util.h>

gchar *symm_key;
gchar *access_token;

GtkWidget *web_view[MAX_APP_NUM];
GtkWidget *app_book;

static char *
get_app_name (char *dbus_name)
{
  int i, j;
  char *app_name = (char *) malloc (sizeof (char) * 255);
  for (i = 0, j = 0; dbus_name[i]; i++) {
    if (dbus_name[i] == '.')
      j = 0;
    else
      app_name[j++] = dbus_name[i];
  }
  app_name[j] = '\0';
  return app_name;
}

static void
page_changed_callback (GtkNotebook *notebook,
                       GtkWidget   *page,
                       guint        page_num,
                       gpointer     user_data)
{
  webkit_web_view_run_javascript (WEBKIT_WEB_VIEW (web_view[page_num]),
                                  "localStorage.clear()", NULL, NULL, NULL);
  webkit_web_view_run_javascript (WEBKIT_WEB_VIEW (web_view[page_num]),
                                  "lsfGetSettings()", NULL, NULL, NULL);
}

static void
lsf_msg_handler (WebKitUserContentManager *manager,
                 WebKitJavascriptResult   *js_result,
                 gpointer                  user_data)
{
  struct json_object *req_obj;
  struct json_object *resp_obj;
  struct json_object *prop_obj;
  lsf_user_data_t app_data;
  const char *app_settings;
  const char *method;
  JSCValue *val = webkit_javascript_result_get_js_value (js_result);
  char *req_msg = NULL;
  char *response = NULL;
  char script[JSON_FILE_BUF_SIZE] = { 0, };
  int ret;
  int app_num;

  gchar *app_dbus_name = (gchar *) user_data;

  req_obj = json_tokener_parse (jsc_value_to_string (val));
  if (!req_obj)
    return;

  json_object_object_get_ex (req_obj, "method", &prop_obj);
  method = json_object_get_string (prop_obj);

  req_msg = (char *) calloc (1, JSON_FILE_BUF_SIZE);
  if (!strcmp (method, "lsf_set_settings"))
  {
    json_object_object_get_ex (req_obj, "app_conf", &prop_obj);
    app_settings = json_object_get_string (prop_obj);
    snprintf (req_msg,
              JSON_FILE_BUF_SIZE,
              "{ \"to\": \"%s\",\
                 \"from\": \"%s\",\
                 \"access_token\": \"%s\",\
                 \"function\": \"%s\",\
                 \"app_conf\": %s }",
              app_dbus_name,
              LSF_MOCKPANEL_DBUS_NAME,
              access_token,
              method,
              app_settings);
    ret = lsf_send_message (symm_key, req_msg, &response);
  }
  else if (!strcmp (method, "lsf_get_settings"))
  {
    snprintf (req_msg,
              JSON_FILE_BUF_SIZE,
              "{ \"to\": \"%s\",\
                 \"from\": \"%s\",\
                 \"access_token\": \"%s\",\
                 \"function\": \"%s\" }",
              app_dbus_name,
              LSF_MOCKPANEL_DBUS_NAME,
              access_token,
              method);
    ret = lsf_send_message (symm_key, req_msg, &response);
  }
  fprintf (stdout, "\n-- request message: %s\n", req_msg);
  json_object_put (req_obj);
  free (req_msg);

  if (ret == LSF_MESSAGE_RE_AUTH)
  { 
    ret = lsf_auth (&app_data, LSF_MOCKPANEL_PASSPHRASE);
    if (ret == LSF_AUTH_STAT_OK)
    {
      symm_key = g_strdup (app_data.symm_key);
      access_token = g_strdup (app_data.access_token);
    }
  }
  else if (ret == LSF_MESSAGE_RESP_OK)
  {
    fprintf (stdout, "\n++ return message: %s\n", response);
    resp_obj = json_tokener_parse (response);
    snprintf (script, JSON_FILE_BUF_SIZE,
              "localStorage.setItem('lsfMsg', '%s')",
              json_object_get_string (resp_obj));
    app_num = gtk_notebook_get_current_page (GTK_NOTEBOOK (app_book));
    webkit_web_view_run_javascript (WEBKIT_WEB_VIEW (web_view[app_num]),
                                    script, NULL, NULL, NULL);
    json_object_put (resp_obj);
  }

  if (response)
    free (response);
}

static void
activate (GtkApplication *app,
          gpointer        user_data)
{
  GtkWidget *window;
  GtkWidget *scrolled_window;
  WebKitUserScript *lsf_api;
  WebKitUserContentManager *manager;
  const char *script;
  GDir *dir = NULL;
  const gchar *app_dir;
  gchar *app_dbus_name;
  gchar *app_name;
  gchar *app_html;
  int app_num = 0;
  
  window = gtk_application_window_new (app);
  gtk_window_set_title (GTK_WINDOW (window), LSF_MOCKPANEL_NAME);
  gtk_window_set_default_size (GTK_WINDOW (window), LSF_MOCKPANEL_WIDTH, LSF_MOCKPANEL_HEIGHT);
  gtk_window_set_position (GTK_WINDOW (window), GTK_WIN_POS_CENTER_ALWAYS);

  app_book = gtk_notebook_new ();
  gtk_container_add (GTK_CONTAINER (window), GTK_WIDGET (app_book));

  script = "function lsfGetSettings() {\
              let obj = { method: \"lsf_get_settings\" };\
              window.webkit.messageHandlers.lsfInterface.postMessage(JSON.stringify(obj));\
              return JSON.parse(localStorage.getItem('lsfMsg')); }\
            function lsfSetSettings(arg) {\
              let obj = { method: \"lsf_set_settings\",\
                          app_conf: arg };\
              window.webkit.messageHandlers.lsfInterface.postMessage(JSON.stringify(obj));\
              localStorage.removeItem('lsfMsg');\
              return lsfGetSettings(); }\
            window.addEventListener('unload', function(e) { localStorage.clear(); });";
  lsf_api = webkit_user_script_new (script, 0, 0, NULL, NULL);

  dir = g_dir_open (LSF_CC_PANEL_DIR, 0, NULL);
  while ((app_dir = g_dir_read_name (dir)) != NULL) {
    app_dbus_name = g_strdup (app_dir);
    manager = webkit_user_content_manager_new ();
    webkit_user_content_manager_add_script (manager, lsf_api);
    g_signal_connect (manager, "script-message-received::lsfInterface", G_CALLBACK (lsf_msg_handler), (gpointer) app_dbus_name);
    webkit_user_content_manager_register_script_message_handler (manager, "lsfInterface");

    app_name = get_app_name (app_dbus_name);
    app_html = g_strconcat ("file://", LSF_CC_PANEL_DIR, "/", app_dbus_name, "/html/panel.html", NULL);
    scrolled_window = gtk_scrolled_window_new (NULL, NULL);
    web_view[app_num] = webkit_web_view_new_with_user_content_manager (manager);
    webkit_web_view_run_javascript (WEBKIT_WEB_VIEW (web_view[app_num]),
                                    "localStorage.clear()", NULL, NULL, NULL);
    webkit_web_view_load_uri (WEBKIT_WEB_VIEW (web_view[app_num]), app_html);
    gtk_container_add (GTK_CONTAINER (scrolled_window), web_view[app_num++]);
    gtk_notebook_append_page (GTK_NOTEBOOK (app_book), scrolled_window, gtk_label_new (app_name));
    g_free (app_name);
    g_free (app_html);
  }
  g_dir_close (dir);
  g_signal_connect_after (GTK_NOTEBOOK (app_book), "switch-page", G_CALLBACK (page_changed_callback), NULL);

  gtk_widget_show_all (window);
}

static void
remove_localstorage (void)
{
  char *home_dir = NULL;
  char *localstorage_dir = NULL;
  GDir *dir = NULL;
  const char *dir_file = NULL;
  char *target_file = NULL;

  if (!(home_dir = getenv ("HOME"))) {
    home_dir = getpwuid (getuid ())->pw_dir;
  }
  localstorage_dir = g_strconcat (home_dir, "/.local/share/webkitgtk/localstorage", NULL);

  dir = g_dir_open (localstorage_dir, 0, NULL);
  if (dir) {
    while ((dir_file = g_dir_read_name (dir))) {
      target_file = g_strconcat (localstorage_dir, "/", dir_file, NULL);
      remove (target_file);
      g_free (target_file);
    }
  }
  g_dir_close (dir);

  g_free (localstorage_dir);
}

int
main (int    argc,
      char **argv)
{
  GtkApplication *app;
  lsf_user_data_t app_data;
  int status;

  status = lsf_auth (&app_data, LSF_MOCKPANEL_PASSPHRASE);
  if (status == LSF_AUTH_STAT_OK) {
    symm_key = g_strdup (app_data.symm_key);
    access_token = g_strdup (app_data.access_token);

    app = gtk_application_new (LSF_MOCKPANEL_DBUS_NAME, G_APPLICATION_FLAGS_NONE);
    g_signal_connect (app, "activate", G_CALLBACK (activate), NULL);
  
    status = g_application_run (G_APPLICATION (app), 0, NULL);

    g_object_unref (app);

  } else 
    fprintf (stdout, "Authentication FAILURE\n");

  remove_localstorage ();

  return status;
}
