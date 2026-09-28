#define _GNU_SOURCE
#define POLKIT_AGENT_I_KNOW_API_IS_SUBJECT_TO_CHANGE
#include <gtk/gtk.h>
#include <polkitagent/polkitagent.h>
#include <glib-unix.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#define READ_ACTION "io.github.from-nibly.agent-keyring.read"
#define MAX_CHOICES 16U
#define MAX_TIMEOUT 3600U
#define MAX_MESSAGE 65536U

typedef struct {
    gint pid;
    guint64 start_time;
    guint uid;
    guint timeout;
    const gchar *request_id;
    const gchar *once_message;
    const gchar *run_message;
} Options;

typedef struct App App;
typedef struct Challenge Challenge;

typedef struct {
    GObject *(*create)(PolkitIdentity *, const gchar *);
    void (*initiate)(GObject *);
    void (*response)(GObject *, const gchar *);
    void (*cancel)(GObject *);
} SessionOps;

struct App {
    Options options;
    const SessionOps *ops;
    GtkWidget *window, *once, *run, *identities, *entry, *submit;
    GtkWidget *message, *prompt, *status;
    Challenge *active;
    GHashTable *cookies;
    guint sequence, accepted_sequence;
    gboolean run_scope, frozen, stopped, changing_identity;
    gint output_fd, exit_status;
    gint64 deadline;
    gpointer registration;
    PolkitAuthority *authority;
    GDBusConnection *bus;
    gchar *authority_owner;
    gulong owner_handler, bus_handler;
    guint stdin_watch, deadline_watch, subject_watch;
};

struct Challenge {
    gint refs;
    App *app;
    guint sequence;
    GTask *task;
    GCancellable *cancellable;
    gulong cancel_handler;
    GPtrArray *identities;
    gchar *cookie;
    GObject *session;
    gboolean done, waiting;
};

typedef struct { PolkitAgentListener parent; App *app; } ApprovalListener;
typedef struct { PolkitAgentListenerClass parent; } ApprovalListenerClass;
GType approval_listener_get_type(void);
G_DEFINE_TYPE(ApprovalListener, approval_listener, POLKIT_AGENT_TYPE_LISTENER)

static void app_stop(App *app);
static void challenge_finish(Challenge *c, gboolean cancelled);
static void start_identity(Challenge *c, guint index);

static gboolean parse_uint(const gchar *text, guint64 max, guint64 *out)
{
    guint64 n = 0;
    if (text == NULL || *text == '\0') return FALSE;
    for (const gchar *p = text; *p != '\0'; ++p) {
        if (*p < '0' || *p > '9' || n > (max - (guint)(*p - '0')) / 10)
            return FALSE;
        n = n * 10 + (guint)(*p - '0');
    }
    if (n == 0 || n > max) return FALSE;
    *out = n;
    return TRUE;
}

/* No GTK option parser: reject unknown, duplicate and missing argv entries. */
static gboolean parse_options(int argc, char **argv, Options *out)
{
    Options o = {0};
    guint seen = 0;
    if (argc != 15) return FALSE;
    for (int i = 1; i < argc; i += 2) {
        guint bit;
        guint64 n;
        const gchar *key = argv[i], *value = argv[i + 1];
        if (strcmp(key, "--pid") == 0) {
            bit = 1U;
            if (!parse_uint(value, G_MAXINT, &n)) return FALSE;
            o.pid = (gint)n;
        } else if (strcmp(key, "--start-time") == 0) {
            bit = 2U;
            if (!parse_uint(value, G_MAXUINT64, &o.start_time)) return FALSE;
        } else if (strcmp(key, "--uid") == 0) {
            bit = 4U;
            if (!parse_uint(value, G_MAXINT, &n)) return FALSE;
            o.uid = (guint)n;
        } else if (strcmp(key, "--request-id") == 0) {
            bit = 8U;
            if (strlen(value) != 32) return FALSE;
            for (guint j = 0; j < 32; ++j)
                if (!g_ascii_isdigit(value[j]) && !(value[j] >= 'a' && value[j] <= 'f'))
                    return FALSE;
            o.request_id = value;
        } else if (strcmp(key, "--once-message") == 0 || strcmp(key, "--run-message") == 0) {
            bit = strcmp(key, "--once-message") == 0 ? 16U : 32U;
            if (*value == '\0' || strlen(value) > MAX_MESSAGE || !g_utf8_validate(value, -1, NULL))
                return FALSE;
            if (bit == 16U) o.once_message = value; else o.run_message = value;
        } else if (strcmp(key, "--timeout-seconds") == 0) {
            bit = 64U;
            if (!parse_uint(value, MAX_TIMEOUT, &n)) return FALSE;
            o.timeout = (guint)n;
        } else return FALSE;
        if ((seen & bit) != 0) return FALSE;
        seen |= bit;
    }
    if (seen != 127U) return FALSE;
    *out = o;
    return TRUE;
}

static gchar *expected_message(const App *app)
{
    return g_strdup_printf("%s\n\nRequest: %s/%u",
        app->run_scope ? app->options.run_message : app->options.once_message,
        app->options.request_id, app->sequence);
}

static void wipe(gchar *data, gsize length)
{
    volatile gchar *p = (volatile gchar *)data;
    while (length-- != 0) *p++ = 0;
}

static void clear_entry(App *app)
{
    gtk_entry_set_text(GTK_ENTRY(app->entry), "");
    gtk_entry_set_visibility(GTK_ENTRY(app->entry), FALSE);
    gtk_widget_set_sensitive(app->entry, FALSE);
    gtk_widget_set_sensitive(app->submit, FALSE);
}

static gboolean emit_record(App *app, const gchar *record)
{
    gsize left = strlen(record);
    while (left > 0) {
        ssize_t n = write(app->output_fd, record, left);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { app_stop(app); return FALSE; }
        record += n;
        left -= (gsize)n;
    }
    return TRUE;
}

static gboolean emit_choice(App *app)
{
    gchar record[32];
    g_snprintf(record, sizeof record, "CHOICE %u %s\n", app->sequence,
               app->run_scope ? "run" : "once");
    return emit_record(app, record);
}

static Challenge *challenge_ref(Challenge *c)
{
    g_atomic_int_inc(&c->refs);
    return c;
}

static void challenge_unref(gpointer data)
{
    Challenge *c = data;
    if (!g_atomic_int_dec_and_test(&c->refs)) return;
    g_assert(c->done && c->session == NULL && c->cancel_handler == 0);
    g_clear_object(&c->cancellable);
    g_clear_object(&c->task);
    g_ptr_array_unref(c->identities);
    g_free(c->cookie);
    g_free(c);
}

static gboolean current(Challenge *c, GObject *session)
{
    return !c->done && !c->app->stopped && c->app->active == c &&
           c->sequence == c->app->sequence && c->session == session;
}

/* Invalidate BEFORE cancel: polkit can emit completed synchronously here. */
static void stop_session(Challenge *c)
{
    GObject *session = c->session;
    c->session = NULL;
    c->waiting = FALSE;
    if (session == NULL) return;
    c->app->ops->cancel(session);
    g_signal_handlers_disconnect_by_data(session, c);
    g_object_unref(session);
}

static void challenge_finish(Challenge *c, gboolean cancelled)
{
    if (c->done) return;
    challenge_ref(c);
    c->done = TRUE;
    gboolean was_active = c->app->active == c;
    if (was_active) {
        c->app->active = NULL;
        clear_entry(c->app);
    }
    if (c->cancel_handler != 0) {
        g_cancellable_disconnect(c->cancellable, c->cancel_handler);
        c->cancel_handler = 0;
    }
    stop_session(c);
    if (cancelled)
        g_task_return_new_error(c->task, G_IO_ERROR, G_IO_ERROR_CANCELLED, "Approval cancelled");
    else
        g_task_return_boolean(c->task, TRUE);
    g_clear_object(&c->task);
    if (was_active) challenge_unref(c); /* app's ownership */
    challenge_unref(c);
}

static gboolean cancelled_idle(gpointer data)
{
    Challenge *c = data;
    if (!c->done) {
        App *app = c->app;
        gboolean was_active = app->active == c;
        challenge_finish(c, TRUE);
        if (was_active) app_stop(app);
    }
    return G_SOURCE_REMOVE;
}

static void cancelled_cb(GCancellable *cancellable, gpointer data)
{
    (void)cancellable;
    /* GCancellable may fire off-thread. Never disconnect from inside its callback. */
    g_idle_add_full(G_PRIORITY_HIGH, cancelled_idle, challenge_ref(data), challenge_unref);
}

static void session_request(GObject *session, const gchar *prompt, gboolean echo_on, gpointer data)
{
    Challenge *c = data;
    if (!current(c, session) || g_cancellable_is_cancelled(c->cancellable)) return;
    App *app = c->app;
    clear_entry(app);
    gtk_label_set_text(GTK_LABEL(app->prompt), prompt);
    gtk_entry_set_visibility(GTK_ENTRY(app->entry), echo_on);
    c->waiting = TRUE;
    gtk_widget_set_sensitive(app->entry, TRUE);
    gtk_widget_set_sensitive(app->submit, TRUE);
    gtk_widget_grab_focus(app->entry);
}

static void session_info(GObject *session, const gchar *text, gpointer data)
{
    Challenge *c = data;
    if (current(c, session)) gtk_label_set_text(GTK_LABEL(c->app->status), text);
}

static void session_completed(GObject *session, gboolean gained, gpointer data)
{
    Challenge *c = data;
    if (!current(c, session)) return;
    challenge_ref(c);
    App *app = c->app;
    /* Transfer the owned emitter reference locally; do not cancel a completion. */
    c->session = NULL;
    g_signal_handlers_disconnect_by_data(session, c);
    gtk_label_set_text(GTK_LABEL(app->status), gained ? "Waiting for the requesting service…" : "Authentication failed.");
    challenge_finish(c, FALSE);
    /* Helper success is not authorization and must not close the listener. */
    g_object_unref(session);
    challenge_unref(c);
}

static void start_identity(Challenge *c, guint index)
{
    if (c->done || c->app->frozen || index >= c->identities->len) return;
    challenge_ref(c);
    clear_entry(c->app);
    stop_session(c);
    if (g_cancellable_is_cancelled(c->cancellable)) {
        challenge_finish(c, TRUE);
        app_stop(c->app);
        challenge_unref(c);
        return;
    }
    c->session = c->app->ops->create(g_ptr_array_index(c->identities, index), c->cookie);
    if (c->session == NULL) {
        app_stop(c->app);
        challenge_unref(c);
        return;
    }
    g_signal_connect(c->session, "request", G_CALLBACK(session_request), c);
    g_signal_connect(c->session, "show-info", G_CALLBACK(session_info), c);
    g_signal_connect(c->session, "show-error", G_CALLBACK(session_info), c);
    g_signal_connect(c->session, "completed", G_CALLBACK(session_completed), c);
    /* initiate may synchronously complete. Hold both emitter and callback state. */
    GObject *session = g_object_ref(c->session);
    c->app->ops->initiate(session);
    g_object_unref(session);
    challenge_unref(c);
}

static void submit_response(GtkWidget *widget, gpointer data)
{
    (void)widget;
    App *app = data;
    Challenge *c = app->active;
    if (app->stopped || c == NULL || !c->waiting || c->session == NULL ||
        g_cancellable_is_cancelled(c->cancellable)) return;
    challenge_ref(c);
    GObject *session = g_object_ref(c->session);
    app->frozen = TRUE;
    gtk_widget_set_sensitive(app->once, FALSE);
    gtk_widget_set_sensitive(app->run, FALSE);
    gtk_widget_set_sensitive(app->identities, FALSE);
    c->waiting = FALSE;
    gchar *response = g_strdup(gtk_entry_get_text(GTK_ENTRY(app->entry)));
    gsize length = strlen(response);
    clear_entry(app);
    /* Freeze/clear first, including Enter; response may emit the next PAM prompt. */
    app->ops->response(session, response);
    wipe(response, length);
    g_free(response);
    g_object_unref(session);
    challenge_unref(c);
}

static void identity_changed(GtkComboBox *combo, gpointer data)
{
    App *app = data;
    gint index = gtk_combo_box_get_active(combo);
    if (!app->stopped && !app->changing_identity && !app->frozen && app->active != NULL && index >= 0)
        start_identity(app->active, (guint)index);
}

static void scope_changed(GtkToggleButton *button, gpointer data)
{
    App *app = data;
    if (!gtk_toggle_button_get_active(button) || app->stopped) return;
    gboolean run = GTK_WIDGET(button) == app->run;
    if (app->frozen || run == app->run_scope) return;
    if (app->sequence >= MAX_CHOICES) { app_stop(app); return; }
    ++app->sequence;
    app->run_scope = run;
    /* Root must invalidate the old check before its cancellation can finish. */
    if (!emit_choice(app)) return;
    if (app->active != NULL) challenge_finish(app->active, TRUE);
    clear_entry(app);
    app->changing_identity = TRUE;
    gtk_combo_box_text_remove_all(GTK_COMBO_BOX_TEXT(app->identities));
    app->changing_identity = FALSE;
    gtk_widget_set_sensitive(app->identities, FALSE);
    gtk_label_set_text(GTK_LABEL(app->message), run ? app->options.run_message : app->options.once_message);
    gtk_label_set_text(GTK_LABEL(app->prompt), "");
    gtk_label_set_text(GTK_LABEL(app->status), "Waiting for administrator authentication…");
    if (app->sequence == MAX_CHOICES) {
        gtk_widget_set_sensitive(app->once, FALSE);
        gtk_widget_set_sensitive(app->run, FALSE);
    }
}

static gboolean matches_challenge(App *app, const gchar *action, const gchar *message,
                                  PolkitDetails *details, const gchar *cookie, GList *identities)
{
    if (app->stopped || app->frozen || app->sequence == 0 ||
        app->accepted_sequence == app->sequence || app->active != NULL ||
        action == NULL || strcmp(action, READ_ACTION) != 0 || message == NULL ||
        details == NULL || cookie == NULL || *cookie == '\0' || strlen(cookie) > 4096 ||
        g_hash_table_contains(app->cookies, cookie) || identities == NULL) return FALSE;
    gchar pid[32];
    g_snprintf(pid, sizeof pid, "%d", app->options.pid);
    if (g_strcmp0(polkit_details_lookup(details, "polkit.subject-pid"), pid) != 0) return FALSE;
    gchar *expected = expected_message(app);
    gboolean matches = strcmp(message, expected) == 0;
    g_free(expected);
    if (!matches) return FALSE;
    guint count = 0;
    for (GList *it = identities; it != NULL; it = it->next) {
        if (!POLKIT_IS_UNIX_USER(it->data) || ++count > 64) return FALSE;
    }
    return TRUE;
}

static void begin_authentication(PolkitAgentListener *listener, const gchar *action,
                                const gchar *message, const gchar *icon,
                                PolkitDetails *details, const gchar *cookie, GList *identities,
                                GCancellable *cancellable, GAsyncReadyCallback callback, gpointer data)
{
    (void)icon;
    App *app = ((ApprovalListener *)listener)->app;
    GTask *task = g_task_new(listener, cancellable, callback, data);
    if (cancellable == NULL || g_cancellable_is_cancelled(cancellable) ||
        !matches_challenge(app, action, message, details, cookie, identities)) {
        g_task_return_new_error(task, G_IO_ERROR, G_IO_ERROR_CANCELLED, "Unexpected approval challenge");
        g_object_unref(task);
        return;
    }
    Challenge *c = g_new0(Challenge, 1);
    c->refs = 1;
    c->app = app;
    c->sequence = app->sequence;
    c->task = task;
    c->cancellable = g_object_ref(cancellable);
    c->cookie = g_strdup(cookie);
    c->identities = g_ptr_array_new_with_free_func(g_object_unref);
    for (GList *it = identities; it != NULL; it = it->next)
        g_ptr_array_add(c->identities, g_object_ref(it->data));
    app->active = c;
    app->accepted_sequence = app->sequence;
    g_hash_table_add(app->cookies, g_strdup(cookie));
    c->cancel_handler = g_cancellable_connect(cancellable, G_CALLBACK(cancelled_cb), c, NULL);
    gtk_label_set_text(GTK_LABEL(app->message), message);
    gtk_label_set_text(GTK_LABEL(app->status), "Authenticate as an offered administrator.");
    app->changing_identity = TRUE;
    gtk_combo_box_text_remove_all(GTK_COMBO_BOX_TEXT(app->identities));
    for (guint i = 0; i < c->identities->len; ++i) {
        PolkitUnixUser *user = g_ptr_array_index(c->identities, i);
        const gchar *name = polkit_unix_user_get_name(user);
        gchar *label = g_strdup_printf("%s (UID %d)", name != NULL ? name : "Administrator",
                                       polkit_unix_user_get_uid(user));
        gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(app->identities), label);
        g_free(label);
    }
    gtk_combo_box_set_active(GTK_COMBO_BOX(app->identities), 0);
    app->changing_identity = FALSE;
    gtk_widget_set_sensitive(app->identities, c->identities->len > 1);
    start_identity(c, 0);
}

static gboolean finish_authentication(PolkitAgentListener *listener, GAsyncResult *result, GError **error)
{
    g_return_val_if_fail(g_task_is_valid(result, listener), FALSE);
    return g_task_propagate_boolean(G_TASK(result), error);
}

static void approval_listener_init(ApprovalListener *listener) { listener->app = NULL; }
static void approval_listener_class_init(ApprovalListenerClass *klass)
{
    PolkitAgentListenerClass *parent = POLKIT_AGENT_LISTENER_CLASS(klass);
    parent->initiate_authentication = begin_authentication;
    parent->initiate_authentication_finish = finish_authentication;
}

static GObject *real_create(PolkitIdentity *identity, const gchar *cookie)
{
    return G_OBJECT(polkit_agent_session_new(identity, cookie));
}
static void real_initiate(GObject *session) { polkit_agent_session_initiate(POLKIT_AGENT_SESSION(session)); }
static void real_response(GObject *session, const gchar *response) { polkit_agent_session_response(POLKIT_AGENT_SESSION(session), response); }
static void real_cancel(GObject *session) { polkit_agent_session_cancel(POLKIT_AGENT_SESSION(session)); }
static const SessionOps real_ops = {real_create, real_initiate, real_response, real_cancel};

static void app_stop(App *app)
{
    if (app->stopped) return;
    app->stopped = TRUE;
    /* The manager/launcher may retain stdout, so EOF is not a timely cancel
     * signal. Notify root before any blocking PAM or bus cleanup. */
    emit_record(app, "CANCEL\n");
    if (app->output_fd >= 0) close(app->output_fd);
    app->output_fd = -1;
    if (app->active != NULL) challenge_finish(app->active, TRUE);
    /* Disconnect libpolkit's built-in automatic re-registration on owner loss. */
    if (app->registration != NULL) {
        gpointer registration = app->registration;
        app->registration = NULL;
        polkit_agent_listener_unregister(registration);
    }
    if (app->window != NULL) {
        clear_entry(app);
        gtk_widget_hide(app->window);
    }
    if (gtk_main_level() > 0) gtk_main_quit();
}

static gboolean window_closed(GtkWidget *window, GdkEvent *event, gpointer data)
{
    (void)window; (void)event;
    app_stop(data);
    return TRUE;
}
static void cancel_clicked(GtkButton *button, gpointer data) { (void)button; app_stop(data); }

static GtkWidget *text_label(const gchar *text)
{
    GtkWidget *label = gtk_label_new(text);
    gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
    gtk_label_set_xalign(GTK_LABEL(label), 0);
    gtk_label_set_max_width_chars(GTK_LABEL(label), 72);
    return label;
}

static void app_init(App *app, const Options *options, const SessionOps *ops, gint output_fd)
{
    memset(app, 0, sizeof *app);
    app->options = *options;
    app->ops = ops;
    app->output_fd = output_fd;
    app->exit_status = 1;
    app->sequence = 1;
    app->deadline = g_get_monotonic_time() + (gint64)options->timeout * G_USEC_PER_SEC;
    app->cookies = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    app->window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(app->window), "Agent Keyring — Administrator Approval");
    gtk_window_set_default_size(GTK_WINDOW(app->window), 580, -1);
    gtk_container_set_border_width(GTK_CONTAINER(app->window), 20);
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_container_add(GTK_CONTAINER(app->window), box);
    app->message = text_label(options->once_message);
    app->once = gtk_radio_button_new_with_label(NULL, "Allow once");
    app->run = gtk_radio_button_new_with_label_from_widget(GTK_RADIO_BUTTON(app->once), "Allow for this agent run");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(app->once), TRUE);
    app->identities = gtk_combo_box_text_new();
    gtk_widget_set_tooltip_text(app->identities, "Administrator identity offered by the system");
    app->prompt = text_label("");
    app->entry = gtk_entry_new();
    gtk_entry_set_max_length(GTK_ENTRY(app->entry), 4096);
    gtk_entry_set_input_purpose(GTK_ENTRY(app->entry), GTK_INPUT_PURPOSE_PASSWORD);
    app->status = text_label("Waiting for administrator authentication…");
    app->submit = gtk_button_new_with_label("Authenticate");
    GtkWidget *cancel = gtk_button_new_with_label("Cancel");
    GtkWidget *widgets[] = {app->message, app->once, app->run,
        app->identities, app->prompt, app->entry, app->status, app->submit, cancel};
    for (guint i = 0; i < G_N_ELEMENTS(widgets); ++i)
        gtk_box_pack_start(GTK_BOX(box), widgets[i], FALSE, FALSE, 0);
    clear_entry(app);
    gtk_widget_set_sensitive(app->identities, FALSE);
    g_signal_connect(app->once, "toggled", G_CALLBACK(scope_changed), app);
    g_signal_connect(app->run, "toggled", G_CALLBACK(scope_changed), app);
    g_signal_connect(app->identities, "changed", G_CALLBACK(identity_changed), app);
    g_signal_connect(app->entry, "activate", G_CALLBACK(submit_response), app);
    g_signal_connect(app->submit, "clicked", G_CALLBACK(submit_response), app);
    g_signal_connect(cancel, "clicked", G_CALLBACK(cancel_clicked), app);
    g_signal_connect(app->window, "delete-event", G_CALLBACK(window_closed), app);
}

static gboolean subject_alive(const Options *options)
{
    gchar *path = g_strdup_printf("/proc/%d", options->pid);
    struct stat st;
    gboolean ok = stat(path, &st) == 0 && st.st_uid == options->uid;
    gchar *stat_path = g_strconcat(path, "/stat", NULL), *text = NULL;
    if (ok) ok = g_file_get_contents(stat_path, &text, NULL, NULL);
    if (ok) {
        gchar *end = strrchr(text, ')');
        ok = end != NULL && end[1] == ' ';
        if (ok) {
            gchar **fields = g_strsplit(end + 2, " ", -1);
            guint64 start = 0;
            ok = g_strv_length(fields) > 19 && strcmp(fields[0], "Z") != 0 &&
                 strcmp(fields[0], "X") != 0 &&
                 parse_uint(fields[19], G_MAXUINT64, &start) && start == options->start_time;
            g_strfreev(fields);
        }
    }
    g_free(text); g_free(stat_path); g_free(path);
    return ok;
}

static gboolean subject_tick(gpointer data)
{
    App *app = data;
    if (!subject_alive(&app->options) || g_get_monotonic_time() >= app->deadline)
        app_stop(app);
    return G_SOURCE_CONTINUE;
}
static gboolean deadline_cb(gpointer data) { app_stop(data); return G_SOURCE_CONTINUE; }

static gboolean liveness_intact(gint fd)
{
    struct pollfd watch = {.fd = fd, .events = POLLIN};
    gint result;
    do { result = poll(&watch, 1, 0); } while (result < 0 && errno == EINTR);
    return result == 0;
}

static gboolean stdin_ready(gint fd, GIOCondition condition, gpointer data)
{
    App *app = data;
    if ((condition & (G_IO_IN | G_IO_HUP)) != 0) {
        gchar byte;
        ssize_t n;
        do { n = read(fd, &byte, 1); } while (n < 0 && errno == EINTR);
        if (n == 0) app->exit_status = 0;
    }
    app_stop(app); /* Any data, EOF, HUP or error violates/ends liveness. */
    return G_SOURCE_CONTINUE;
}

static void authority_changed(GObject *object, GParamSpec *spec, gpointer data)
{
    (void)object; (void)spec;
    App *app = data;
    gchar *owner = polkit_authority_get_owner(app->authority);
    if (owner == NULL || g_strcmp0(owner, app->authority_owner) != 0) app_stop(app);
    g_free(owner);
}
static void bus_closed(GDBusConnection *bus, gboolean remote, GError *error, gpointer data)
{
    (void)bus; (void)remote; (void)error;
    app_stop(data);
}

static void app_clear(App *app)
{
    app_stop(app);
    if (app->stdin_watch != 0) g_source_remove(app->stdin_watch);
    if (app->deadline_watch != 0) g_source_remove(app->deadline_watch);
    if (app->subject_watch != 0) g_source_remove(app->subject_watch);
    if (app->owner_handler != 0) g_signal_handler_disconnect(app->authority, app->owner_handler);
    if (app->bus_handler != 0) g_signal_handler_disconnect(app->bus, app->bus_handler);
    /* Drain already-queued cancellation closures while App is still alive. */
    while (g_main_context_iteration(NULL, FALSE)) {}
    gtk_widget_destroy(app->window);
    g_clear_object(&app->authority);
    g_clear_object(&app->bus);
    g_free(app->authority_owner);
    g_hash_table_unref(app->cookies);
}

/* Reserve a private CLOEXEC protocol writer, then silence library stdout too. */
static gint harden_process(void)
{
    struct rlimit core = {0, 0};
    if (setrlimit(RLIMIT_CORE, &core) != 0 || prctl(PR_SET_DUMPABLE, 0) != 0) return -1;
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) return -1;
    for (gint fd = 0; fd <= 2; ++fd) {
        gint flags = fcntl(fd, F_GETFD);
        if (flags < 0 || fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0) return -1;
    }
    gint output = fcntl(STDOUT_FILENO, F_DUPFD_CLOEXEC, 3);
    gint null_fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
    if (output < 0 || null_fd < 0) {
        if (output >= 0) close(output);
        if (null_fd >= 0) close(null_fd);
        return -1;
    }
    gboolean ok = dup3(null_fd, STDOUT_FILENO, O_CLOEXEC) >= 0 &&
                  dup3(null_fd, STDERR_FILENO, O_CLOEXEC) >= 0;
    close(null_fd);
    if (!ok) { close(output); return -1; }
    g_unsetenv("POLKIT_DEBUG");
    g_unsetenv("G_MESSAGES_DEBUG");
    return output;
}

int main(int argc, char **argv)
{
    gint64 started = g_get_monotonic_time();
    gint output_fd = harden_process();
    Options options;
    if (output_fd < 0) return 1;
    if (!parse_options(argc, argv, &options) || getuid() == 0 ||
        getuid() != options.uid || geteuid() != options.uid ||
        prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 0 || !subject_alive(&options) ||
        !liveness_intact(STDIN_FILENO) || !gtk_init_check(NULL, NULL)) {
        close(output_fd);
        return 1;
    }
    App app;
    app_init(&app, &options, &real_ops, output_fd);
    app.deadline = started + (gint64)options.timeout * G_USEC_PER_SEC;
    ApprovalListener *listener = g_object_new(approval_listener_get_type(), NULL);
    listener->app = &app;
    app.stdin_watch = g_unix_fd_add(STDIN_FILENO, G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL, stdin_ready, &app);
    app.deadline_watch = g_timeout_add_seconds(options.timeout, deadline_cb, &app);
    app.subject_watch = g_timeout_add(250, subject_tick, &app);
    app.authority = polkit_authority_get_sync(NULL, NULL);
    app.bus = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, NULL);
    if (app.authority == NULL || app.bus == NULL) goto cleanup;
    g_dbus_connection_set_exit_on_close(app.bus, FALSE);
    app.authority_owner = polkit_authority_get_owner(app.authority);
    if (app.authority_owner == NULL) goto cleanup;
    /* Install BEFORE register(), ahead of libpolkit's auto-reconnect handler. */
    app.owner_handler = g_signal_connect(app.authority, "notify::owner", G_CALLBACK(authority_changed), &app);
    app.bus_handler = g_signal_connect(app.bus, "closed", G_CALLBACK(bus_closed), &app);
    PolkitSubject *subject = polkit_unix_process_new_for_owner(options.pid, options.start_time, (gint)options.uid);
    app.registration = polkit_agent_listener_register(POLKIT_AGENT_LISTENER(listener),
        POLKIT_AGENT_REGISTER_FLAGS_NONE, subject,
        "/io/github/from_nibly/AgentKeyring/AuthenticationAgent", NULL, NULL);
    g_object_unref(subject);
    if (app.registration == NULL || app.stopped || !subject_alive(&options) ||
        !liveness_intact(STDIN_FILENO) || g_get_monotonic_time() >= app.deadline) goto cleanup;
    authority_changed(NULL, NULL, &app);
    if (app.stopped) goto cleanup;
    gtk_widget_show_all(app.window);
    if (emit_record(&app, "READY\n") && emit_choice(&app)) gtk_main();
cleanup:
    /* A synchronous registration may have returned after stop was observed. */
    if (app.registration != NULL && app.stopped) {
        polkit_agent_listener_unregister(app.registration);
        app.registration = NULL;
    }
    app_clear(&app);
    g_object_unref(listener);
    return app.exit_status;
}
