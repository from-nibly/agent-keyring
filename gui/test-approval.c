/* Include the implementation to exercise private state without a test-only
 * production mode. No test calls the real main, registration, or SessionOps. */
int approval_program_main(int argc, char **argv);
#define main approval_program_main
#include "approval.c"
#undef main
#include <sys/wait.h>

typedef struct { GObject parent; gboolean completed; } FakeSession;
typedef struct { GObjectClass parent; } FakeSessionClass;
GType fake_session_get_type(void);
G_DEFINE_TYPE(FakeSession, fake_session, G_TYPE_OBJECT)
static guint fake_signals[4];
static guint creates, cancels, responses;
static gint selected_uid;
static App *responding_app;
static gboolean respond_next_prompt, initiate_complete;
static gint cancel_probe_fd = -1;
static const gchar *cancel_probe_expected;

static void fake_session_init(FakeSession *self) { self->completed = FALSE; }
static void fake_session_class_init(FakeSessionClass *klass)
{
    GType type = G_TYPE_FROM_CLASS(klass);
    fake_signals[0] = g_signal_new("request", type, G_SIGNAL_RUN_LAST, 0, NULL, NULL, NULL,
                                  G_TYPE_NONE, 2, G_TYPE_STRING, G_TYPE_BOOLEAN);
    fake_signals[1] = g_signal_new("show-info", type, G_SIGNAL_RUN_LAST, 0, NULL, NULL, NULL,
                                  G_TYPE_NONE, 1, G_TYPE_STRING);
    fake_signals[2] = g_signal_new("show-error", type, G_SIGNAL_RUN_LAST, 0, NULL, NULL, NULL,
                                  G_TYPE_NONE, 1, G_TYPE_STRING);
    fake_signals[3] = g_signal_new("completed", type, G_SIGNAL_RUN_LAST, 0, NULL, NULL, NULL,
                                  G_TYPE_NONE, 1, G_TYPE_BOOLEAN);
}
static GObject *fake_create(PolkitIdentity *identity, const gchar *cookie)
{
    g_assert_nonnull(cookie);
    ++creates;
    selected_uid = polkit_unix_user_get_uid(POLKIT_UNIX_USER(identity));
    return g_object_new(fake_session_get_type(), NULL);
}
static void fake_initiate(GObject *session)
{
    if (initiate_complete)
        g_signal_emit(session, fake_signals[3], 0, FALSE);
    else
        g_signal_emit(session, fake_signals[0], 0, "Password:", FALSE);
}
static void fake_cancel(GObject *session)
{
    ++cancels;
    if (cancel_probe_fd >= 0) {
        gchar buffer[128] = {0};
        ssize_t n = read(cancel_probe_fd, buffer, sizeof buffer - 1);
        g_assert_cmpint(n, ==, (ssize_t)strlen(cancel_probe_expected));
        g_assert_cmpstr(buffer, ==, cancel_probe_expected);
        cancel_probe_fd = -1;
    }
    ((FakeSession *)session)->completed = TRUE;
    /* Deliberately synchronous, like polkit_agent_session_cancel. */
    g_signal_emit(session, fake_signals[3], 0, FALSE);
}
static void fake_response(GObject *session, const gchar *response)
{
    ++responses;
    g_assert_cmpstr(response, ==, "credential-canary");
    g_assert_true(responding_app->frozen);
    g_assert_false(gtk_widget_get_sensitive(responding_app->once));
    g_assert_false(gtk_widget_get_sensitive(responding_app->run));
    g_assert_false(gtk_widget_get_sensitive(responding_app->identities));
    g_assert_cmpstr(gtk_entry_get_text(GTK_ENTRY(responding_app->entry)), ==, "");
    g_assert_false(gtk_widget_get_sensitive(responding_app->entry));
    if (respond_next_prompt)
        g_signal_emit(session, fake_signals[0], 0, "One-time code:", TRUE);
    else
        g_signal_emit(session, fake_signals[3], 0, TRUE);
}
static const SessionOps fake_ops = {fake_create, fake_initiate, fake_response, fake_cancel};

typedef struct {
    App app;
    ApprovalListener *listener;
    int pipefd[2];
    guint finished, handled, cancelled;
} Fixture;

static const Options test_options = {
    .pid = 1234, .start_time = 6789, .uid = 1000, .timeout = 60,
    .request_id = "0123456789abcdef0123456789abcdef",
    .once_message = "Secret: github.api_token\nAgent: pi\nProcess ID: 1234\nStarted (ticks): 6789\nSecret version: 1\nAccess: this one request",
    .run_message = "Secret: github.api_token\nAgent: pi\nProcess ID: 1234\nStarted (ticks): 6789\nSecret version: 1\nAccess: agent process and live descendants until exit"
};

static void drain(void) { while (g_main_context_iteration(NULL, FALSE)) {} }
static guint windows(void)
{
    GList *list = gtk_window_list_toplevels();
    guint n = 0;
    for (GList *it = list; it != NULL; it = it->next)
        if (gtk_window_get_window_type(GTK_WINDOW(it->data)) == GTK_WINDOW_TOPLEVEL) ++n;
    g_list_free(list);
    return n;
}
static void fixture_init_options(Fixture *f, const Options *options)
{
    memset(f, 0, sizeof *f);
    creates = cancels = responses = 0;
    respond_next_prompt = initiate_complete = FALSE;
    cancel_probe_fd = -1;
    g_assert_cmpint(pipe2(f->pipefd, O_CLOEXEC | O_NONBLOCK), ==, 0);
    app_init(&f->app, options, &fake_ops, f->pipefd[1]);
    responding_app = &f->app;
    f->listener = g_object_new(approval_listener_get_type(), NULL);
    f->listener->app = &f->app;
    gtk_widget_show_all(f->app.window);
    g_assert_true(emit_record(&f->app, "READY\n"));
    g_assert_true(emit_choice(&f->app));
    g_assert_cmpuint(windows(), ==, 1);
}
static void fixture_init(Fixture *f) { fixture_init_options(f, &test_options); }

static void fixture_clear(Fixture *f)
{
    app_clear(&f->app);
    g_object_unref(f->listener);
    close(f->pipefd[0]); /* app_clear owns/closes the write end. */
    drain();
    g_assert_cmpuint(windows(), ==, 0);
}
static void task_completed(GObject *source, GAsyncResult *result, gpointer data)
{
    Fixture *f = data;
    GError *error = NULL;
    ++f->finished;
    if (finish_authentication(POLKIT_AGENT_LISTENER(source), result, &error)) ++f->handled;
    else {
        g_assert_error(error, G_IO_ERROR, G_IO_ERROR_CANCELLED);
        ++f->cancelled;
    }
    g_clear_error(&error);
}
static void offer(Fixture *f, GCancellable *cancel, const gchar *action,
                  const gchar *message, const gchar *pid, const gchar *cookie)
{
    PolkitDetails *details = polkit_details_new();
    if (pid != NULL) polkit_details_insert(details, "polkit.subject-pid", pid);
    /* Requester's identity is deliberately NOT the selected administrator. */
    GList *identities = NULL;
    identities = g_list_append(identities, polkit_unix_user_new(0));
    identities = g_list_append(identities, polkit_unix_user_new(65534));
    begin_authentication(POLKIT_AGENT_LISTENER(f->listener), action, message, "ignored",
                         details, cookie, identities, cancel, task_completed, f);
    g_list_free_full(identities, g_object_unref);
    g_object_unref(details);
}
static GCancellable *offer_current(Fixture *f, const gchar *cookie)
{
    GCancellable *cancel = g_cancellable_new();
    gchar *message = expected_message(&f->app);
    offer(f, cancel, READ_ACTION, message, "1234", cookie);
    g_free(message);
    return cancel;
}
static gchar *records(Fixture *f)
{
    gchar buffer[1024];
    ssize_t n = read(f->pipefd[0], buffer, sizeof buffer - 1);
    g_assert_cmpint(n, >=, 0);
    buffer[n] = '\0';
    return g_strdup(buffer);
}

static void assert_display(App *app, const gchar *message)
{
    gchar **lines = g_strsplit(message, "\n", -1);
    GList *children = gtk_container_get_children(GTK_CONTAINER(app->message));
    g_assert_cmpuint(g_list_length(children), ==, g_strv_length(lines));
    guint i = 0;
    for (GList *it = children; it != NULL; it = it->next, ++i) {
        GtkLabel *label = GTK_LABEL(it->data);
        g_assert_false(gtk_label_get_use_markup(label));
        g_assert_cmpstr(gtk_label_get_text(label), ==, lines[i]);
        g_assert_true(gtk_label_get_line_wrap(label));
        g_assert_cmpint(gtk_label_get_line_wrap_mode(label), ==, PANGO_WRAP_WORD_CHAR);
        g_assert_cmpint(gtk_label_get_ellipsize(label), ==, PANGO_ELLIPSIZE_NONE);
        if (i == 0) {
            PangoAttrList *attrs = gtk_label_get_attributes(label);
            g_assert_nonnull(attrs);
            PangoAttrIterator *iter = pango_attr_list_get_iterator(attrs);
            PangoAttribute *weight = pango_attr_iterator_get(iter, PANGO_ATTR_WEIGHT);
            PangoAttribute *scale = pango_attr_iterator_get(iter, PANGO_ATTR_SCALE);
            g_assert_nonnull(weight);
            g_assert_nonnull(scale);
            g_assert_cmpint(((PangoAttrInt *)weight)->value, ==, PANGO_WEIGHT_BOLD);
            g_assert_cmpfloat(((PangoAttrFloat *)scale)->value, >, 1.0);
            GSList *all = pango_attr_iterator_get_attrs(iter);
            g_assert_cmpuint(g_slist_length(all), ==, 2);
            g_slist_free_full(all, (GDestroyNotify)pango_attribute_destroy);
            pango_attr_iterator_destroy(iter);
        }
    }
    g_list_free(children);
    g_strfreev(lines);
}

static void test_dialog_layout(void)
{
    Fixture f; fixture_init(&f);
    drain();
    GtkWindow *window = GTK_WINDOW(f.app.window);
    g_assert_cmpint(gtk_window_get_type_hint(window), ==, GDK_WINDOW_TYPE_HINT_DIALOG);
    g_assert_cmpint(gdk_window_get_type_hint(gtk_widget_get_window(f.app.window)), ==,
                    GDK_WINDOW_TYPE_HINT_DIALOG);
    g_assert_false(gtk_window_get_resizable(window));
    g_assert_true(gtk_window_get_modal(window));
    g_assert_cmpstr(gdk_get_program_class(), ==, "AgentKeyringApproval");
    guchar *wm_class = NULL;
    gint length = 0;
    g_assert_true(gdk_property_get(gtk_widget_get_window(f.app.window),
        gdk_atom_intern_static_string("WM_CLASS"), gdk_atom_intern_static_string("STRING"),
        0, 1024, FALSE, NULL, NULL, &length, &wm_class));
    g_assert_cmpint(length, >, 0);
    gsize class_offset = strlen((const gchar *)wm_class) + 1;
    g_assert_cmpuint(class_offset, <, (gsize)length);
    g_assert_cmpstr((const gchar *)wm_class + class_offset, ==, "AgentKeyringApproval");
    g_free(wm_class);
    GtkWidget *actions = gtk_widget_get_parent(f.app.submit);
    g_assert_true(GTK_IS_BUTTON_BOX(actions));
    g_assert_cmpint(gtk_orientable_get_orientation(GTK_ORIENTABLE(actions)), ==,
                    GTK_ORIENTATION_HORIZONTAL);
    GList *buttons = gtk_container_get_children(GTK_CONTAINER(actions));
    g_assert_cmpuint(g_list_length(buttons), ==, 2);
    g_assert_cmpstr(gtk_button_get_label(GTK_BUTTON(buttons->data)), ==, "Cancel");
    g_assert_true(buttons->next->data == f.app.submit);
    g_assert_cmpstr(gtk_button_get_label(GTK_BUTTON(f.app.submit)), ==, "Authenticate");
    assert_display(&f.app, test_options.once_message);
    g_signal_emit_by_name(buttons->data, "clicked");
    g_assert_true(f.app.stopped);
    g_list_free(buttons);
    fixture_clear(&f);
}

static void test_long_literal_message(void)
{
    gchar *key = g_strnfill(240, 'x');
    gchar *message = g_strdup_printf("Secret: <b>clé&%s</b>\nAgent: <i>pi</i>\nProcess ID: 1234\nStarted (ticks): 6789\nSecret version: 1\nAccess: this one request", key);
    Options options = test_options;
    options.once_message = message;
    Fixture f; fixture_init_options(&f, &options);
    drain();
    assert_display(&f.app, message);
    GList *children = gtk_container_get_children(GTK_CONTAINER(f.app.message));
    GtkWidget *heading = children->data;
    PangoLayout *layout = gtk_label_get_layout(GTK_LABEL(heading));
    g_assert_cmpint(pango_layout_get_line_count(layout), >, 1);
    gint width, height;
    pango_layout_get_pixel_size(layout, &width, &height);
    g_assert_cmpint(width, <=, gtk_widget_get_allocated_width(heading));
    g_assert_cmpint(height, <=, gtk_widget_get_allocated_height(heading));
    g_assert_cmpint(gtk_widget_get_allocated_width(f.app.window), <, 1024);
    g_assert_cmpint(gtk_widget_get_allocated_height(f.app.window), <, 768);
    g_list_free(children);
    GCancellable *cancel = offer_current(&f, "literal-message");
    g_assert_nonnull(f.app.active);
    assert_display(&f.app, message);
    fixture_clear(&f);
    g_object_unref(cancel);
    g_free(message); g_free(key);
}

static void test_options_parser(void)
{
    char *argv[] = {"approval", "--pid", "1234", "--start-time", "6789",
        "--uid", "1000", "--request-id", "0123456789abcdef0123456789abcdef",
        "--once-message", "one $ % \\ \n", "--run-message", "run", "--timeout-seconds", "60"};
    Options o;
    g_assert_true(parse_options(15, argv, &o));
    g_assert_cmpstr(o.once_message, ==, "one $ % \\ \n");
    g_assert_false(parse_options(14, argv, &o));
    const gchar *invalid[] = {"0", "-1", "+1", "1x", " 1", "18446744073709551616", ""};
    for (guint i = 0; i < G_N_ELEMENTS(invalid); ++i) {
        guint64 n;
        g_assert_false(parse_uint(invalid[i], G_MAXUINT64, &n));
    }
    guint64 n = 0;
    g_assert_true(parse_uint("18446744073709551615", G_MAXUINT64, &n));
    g_assert_cmpuint(n, ==, G_MAXUINT64);
    argv[1] = "--uid";
    g_assert_false(parse_options(15, argv, &o));
    argv[1] = "--pid";
    argv[8] = "0123456789ABCDEF0123456789abcdef";
    g_assert_false(parse_options(15, argv, &o));
    argv[8] = "0123456789abcdef0123456789abcdef";
    argv[14] = "3601";
    g_assert_false(parse_options(15, argv, &o));
}

static void test_correlation(void)
{
    Fixture f; fixture_init(&f);
    gchar *message = expected_message(&f.app);
    gchar *full_message = g_strconcat(test_options.once_message,
        "\n\nRequest: 0123456789abcdef0123456789abcdef/1", NULL);
    g_assert_cmpstr(message, ==, full_message);
    g_free(full_message);
    assert_display(&f.app, test_options.once_message);
    GCancellable *cancel = g_cancellable_new();
    offer(&f, cancel, "foreign.action", message, "1234", "a");
    offer(&f, cancel, READ_ACTION, "wrong message", "1234", "b");
    offer(&f, cancel, READ_ACTION, message, "01234", "c");
    offer(&f, cancel, READ_ACTION, message, NULL, "d");
    offer(&f, cancel, READ_ACTION, test_options.once_message, "1234", "no-nonce");
    gchar *wrong_request = g_strconcat(test_options.once_message,
        "\n\nRequest: fedcba9876543210fedcba9876543210/1", NULL);
    offer(&f, cancel, READ_ACTION, wrong_request, "1234", "wrong-request");
    g_free(wrong_request);
    g_assert_null(f.app.active);
    g_assert_cmpuint(creates, ==, 0);
    offer(&f, cancel, READ_ACTION, message, "1234", "accepted");
    Challenge *first = f.app.active;
    g_assert_nonnull(first);
    assert_display(&f.app, test_options.once_message);
    offer(&f, cancel, READ_ACTION, message, "1234", "duplicate");
    g_assert_true(f.app.active == first);
    g_assert_cmpuint(creates, ==, 1);
    drain();
    g_assert_cmpuint(f.cancelled, ==, 7);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(f.app.run), TRUE);
    assert_display(&f.app, test_options.run_message);
    offer(&f, cancel, READ_ACTION, message, "1234", "stale");
    g_free(message);
    message = expected_message(&f.app);
    offer(&f, cancel, READ_ACTION, message, "1234", "accepted"); /* reused cookie */
    g_assert_null(f.app.active);
    offer(&f, cancel, READ_ACTION, message, "1234", "new-cookie");
    g_assert_nonnull(f.app.active);
    assert_display(&f.app, test_options.run_message);
    g_assert_cmpuint(windows(), ==, 1);
    g_free(message);
    fixture_clear(&f);
    g_object_unref(cancel);
    g_assert_cmpuint(f.finished, ==, 11);
}

static void test_rejected_identity_and_precancel(void)
{
    Fixture f; fixture_init(&f);
    GCancellable *cancel = g_cancellable_new();
    PolkitDetails *details = polkit_details_new();
    polkit_details_insert(details, "polkit.subject-pid", "1234");
    gchar *message = expected_message(&f.app);
    GList *identities = g_list_append(NULL, polkit_unix_group_new(0));
    begin_authentication(POLKIT_AGENT_LISTENER(f.listener), READ_ACTION, message, NULL,
                         details, "unsupported-identity", identities, cancel, task_completed, &f);
    g_list_free_full(identities, g_object_unref);
    begin_authentication(POLKIT_AGENT_LISTENER(f.listener), READ_ACTION, message, NULL,
                         details, "empty-identities", NULL, cancel, task_completed, &f);
    g_cancellable_cancel(cancel);
    offer(&f, cancel, READ_ACTION, message, "1234", "pre-cancelled");
    drain();
    g_assert_cmpuint(f.cancelled, ==, 3);
    g_assert_cmpuint(creates, ==, 0);
    g_assert_null(f.app.active);
    g_assert_false(f.app.stopped);
    g_object_unref(details); g_object_unref(cancel); g_free(message);
    fixture_clear(&f);
}

static void test_control_precedes_session_cancellation(void)
{
    Fixture f; fixture_init(&f);
    GCancellable *first = offer_current(&f, "first-ordering");
    cancel_probe_fd = f.pipefd[0];
    cancel_probe_expected = "READY\nCHOICE 1 once\nCHOICE 2 run\n";
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(f.app.run), TRUE);
    g_assert_cmpint(cancel_probe_fd, ==, -1);
    GCancellable *second = offer_current(&f, "second-ordering");
    cancel_probe_fd = f.pipefd[0];
    cancel_probe_expected = "CANCEL\n";
    app_stop(&f.app);
    g_assert_cmpint(cancel_probe_fd, ==, -1);
    g_assert_cmpint(f.app.output_fd, ==, -1);
    fixture_clear(&f);
    g_object_unref(first); g_object_unref(second);
}

static void test_generations_stale_callbacks(void)
{
    Fixture f; fixture_init(&f);
    GCancellable *old_cancel = offer_current(&f, "generation-one");
    Challenge *old = challenge_ref(f.app.active);
    GObject *old_session = g_object_ref(old->session);
    gtk_entry_set_text(GTK_ENTRY(f.app.entry), "credential-canary");
    GtkWidget *window = f.app.window;
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(f.app.run), TRUE);
    g_assert_true(old->done);
    g_assert_cmpstr(gtk_entry_get_text(GTK_ENTRY(f.app.entry)), ==, "");
    g_assert_false(gtk_widget_get_sensitive(f.app.entry));
    GCancellable *new_cancel = offer_current(&f, "generation-two");
    Challenge *new = f.app.active;
    gtk_entry_set_text(GTK_ENTRY(f.app.entry), "current-buffer");
    g_cancellable_cancel(old_cancel);
    g_signal_emit(old_session, fake_signals[3], 0, TRUE);
    session_completed(old_session, TRUE, old);
    session_request(old_session, "stale prompt", TRUE, old);
    session_info(old_session, "stale info", old);
    drain();
    g_assert_true(f.app.active == new);
    g_assert_false(f.app.stopped);
    g_assert_cmpstr(gtk_entry_get_text(GTK_ENTRY(f.app.entry)), ==, "current-buffer");
    g_assert_true(f.app.window == window);
    g_assert_cmpuint(windows(), ==, 1);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(f.app.once), TRUE);
    GCancellable *third = offer_current(&f, "generation-three");
    g_assert_cmpuint(f.app.active->sequence, ==, 3);
    assert_display(&f.app, test_options.once_message);
    gchar *output = records(&f);
    g_assert_cmpstr(output, ==, "READY\nCHOICE 1 once\nCHOICE 2 run\nCHOICE 3 once\n");
    g_free(output);
    g_object_unref(old_session); challenge_unref(old);
    fixture_clear(&f);
    g_assert_cmpuint(f.finished, ==, 3);
    g_assert_cmpuint(f.cancelled, ==, 3);
    g_object_unref(old_cancel); g_object_unref(new_cancel); g_object_unref(third);
}

static void test_identity_enter_multiple_prompts(void)
{
    Fixture f; fixture_init(&f);
    GCancellable *cancel = offer_current(&f, "identity-pam");
    g_assert_cmpint(selected_uid, ==, 0);
    GObject *old = g_object_ref(f.app.active->session);
    gtk_entry_set_text(GTK_ENTRY(f.app.entry), "discard-on-identity-change");
    gtk_combo_box_set_active(GTK_COMBO_BOX(f.app.identities), 1);
    g_assert_cmpint(selected_uid, ==, 65534);
    g_assert_cmpuint(cancels, ==, 1);
    g_assert_cmpstr(gtk_entry_get_text(GTK_ENTRY(f.app.entry)), ==, "");
    g_assert_false(gtk_entry_get_visibility(GTK_ENTRY(f.app.entry)));
    g_signal_emit(old, fake_signals[3], 0, FALSE);
    g_assert_nonnull(f.app.active);
    respond_next_prompt = TRUE;
    gtk_entry_set_text(GTK_ENTRY(f.app.entry), "credential-canary");
    g_signal_emit_by_name(f.app.entry, "activate");
    g_assert_cmpuint(responses, ==, 1);
    g_assert_true(f.app.frozen);
    g_assert_true(gtk_entry_get_visibility(GTK_ENTRY(f.app.entry)));
    g_assert_true(gtk_widget_get_sensitive(f.app.entry));
    g_assert_cmpstr(gtk_label_get_text(GTK_LABEL(f.app.prompt)), ==, "One-time code:");
    g_assert_cmpstr(gtk_entry_get_text(GTK_ENTRY(f.app.entry)), ==, "");
    gtk_combo_box_set_active(GTK_COMBO_BOX(f.app.identities), 0);
    g_assert_cmpuint(creates, ==, 2); /* frozen, even on a programmatic signal */
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(f.app.run), TRUE);
    g_assert_cmpuint(f.app.sequence, ==, 1);
    assert_display(&f.app, test_options.once_message);
    respond_next_prompt = FALSE;
    gtk_entry_set_text(GTK_ENTRY(f.app.entry), "credential-canary");
    g_signal_emit_by_name(f.app.submit, "clicked");
    drain();
    g_assert_null(f.app.active);
    g_assert_cmpuint(f.handled, ==, 1);
    g_assert_false(f.app.stopped); /* remain alive for root, never treat helper as grant */
    g_assert_true(gtk_widget_get_visible(f.app.window));
    g_assert_cmpstr(gtk_entry_get_text(GTK_ENTRY(f.app.entry)), ==, "");
    gchar *output = records(&f);
    g_assert_cmpstr(output, ==, "READY\nCHOICE 1 once\n");
    g_assert_null(strstr(output, "credential-canary"));
    g_assert_null(strstr(output, "identity-pam"));
    g_free(output);
    g_object_unref(old);
    fixture_clear(&f); g_object_unref(cancel);
}

static gpointer cancel_thread(gpointer data) { g_cancellable_cancel(data); return NULL; }
static void test_cancellation(void)
{
    Fixture f; fixture_init(&f);
    GCancellable *cancel = offer_current(&f, "cancel-current");
    gtk_entry_set_text(GTK_ENTRY(f.app.entry), "credential-canary");
    GThread *thread = g_thread_new("fake-authority-cancel", cancel_thread, cancel);
    g_thread_join(thread);
    g_signal_emit_by_name(f.app.entry, "activate"); /* cancelled before idle dispatch */
    g_assert_cmpuint(responses, ==, 0);
    drain();
    g_assert_true(f.app.stopped);
    g_assert_null(f.app.active);
    g_assert_cmpuint(f.cancelled, ==, 1);
    g_assert_cmpuint(cancels, ==, 1);
    fixture_clear(&f); g_object_unref(cancel);
    g_assert_cmpuint(f.finished, ==, 1);
}

static void test_queued_old_cancellation(void)
{
    Fixture f; fixture_init(&f);
    GCancellable *cancel = offer_current(&f, "queued-old");
    g_cancellable_cancel(cancel); /* schedules an idle retaining the old challenge */
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(f.app.run), TRUE);
    GCancellable *next = offer_current(&f, "queued-new");
    Challenge *current_challenge = f.app.active;
    drain();
    g_assert_false(f.app.stopped);
    g_assert_true(f.app.active == current_challenge);
    g_assert_cmpuint(f.finished, ==, 1);
    fixture_clear(&f);
    g_assert_cmpuint(f.finished, ==, 2);
    g_object_unref(cancel); g_object_unref(next);
}

static void test_sync_initiate_complete(void)
{
    Fixture f; fixture_init(&f);
    initiate_complete = TRUE;
    GCancellable *cancel = offer_current(&f, "sync-completion");
    drain();
    g_assert_null(f.app.active);
    g_assert_false(f.app.stopped);
    g_assert_cmpuint(f.handled, ==, 1);
    fixture_clear(&f); g_object_unref(cancel);
}

static void test_choice_limit(void)
{
    Fixture f; fixture_init(&f);
    for (guint n = 2; n <= MAX_CHOICES; ++n) {
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(n % 2 == 0 ? f.app.run : f.app.once), TRUE);
        g_assert_cmpuint(f.app.sequence, ==, n);
        g_assert_cmpuint(windows(), ==, 1);
    }
    g_assert_false(gtk_widget_get_sensitive(f.app.once));
    g_assert_false(gtk_widget_get_sensitive(f.app.run));
    gchar *output = records(&f);
    g_assert_nonnull(strstr(output, "CHOICE 16 run\n"));
    g_assert_null(strstr(output, "CHOICE 17"));
    g_free(output);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(f.app.once), TRUE);
    g_assert_true(f.app.stopped);
    fixture_clear(&f);
}

static void test_liveness_and_deadline(void)
{
    for (guint mode = 0; mode < 5; ++mode) {
        Fixture f; fixture_init(&f);
        GCancellable *cancel = offer_current(&f, "liveness");
        int pipefd[2];
        g_assert_cmpint(pipe2(pipefd, O_CLOEXEC), ==, 0);
        g_assert_true(liveness_intact(pipefd[0]));
        if (mode == 0) {
            close(pipefd[1]);
            g_assert_false(liveness_intact(pipefd[0]));
            stdin_ready(pipefd[0], G_IO_HUP, &f.app);
            g_assert_cmpint(f.app.exit_status, ==, 0);
        } else if (mode == 1) {
            g_assert_cmpint(write(pipefd[1], "x", 1), ==, 1);
            g_assert_false(liveness_intact(pipefd[0]));
            stdin_ready(pipefd[0], G_IO_IN, &f.app);
            close(pipefd[1]);
            g_assert_cmpint(f.app.exit_status, ==, 1);
        } else {
            close(pipefd[1]);
            if (mode == 2) deadline_cb(&f.app);
            else if (mode == 3) subject_tick(&f.app);
            else bus_closed(NULL, TRUE, NULL, &f.app);
        }
        close(pipefd[0]);
        drain();
        g_assert_true(f.app.stopped);
        g_assert_cmpuint(f.cancelled, ==, 1);
        fixture_clear(&f); g_object_unref(cancel);
    }
}

static void test_subject_identity(void)
{
    Options options = test_options;
    options.pid = getpid();
    options.uid = getuid();
    gchar *text = NULL;
    g_assert_true(g_file_get_contents("/proc/self/stat", &text, NULL, NULL));
    gchar *end = strrchr(text, ')');
    g_assert_nonnull(end);
    gchar **fields = g_strsplit(end + 2, " ", -1);
    g_assert_cmpuint(g_strv_length(fields), >, 19);
    g_assert_true(parse_uint(fields[19], G_MAXUINT64, &options.start_time));
    g_strfreev(fields); g_free(text);
    g_assert_true(subject_alive(&options));
    ++options.start_time;
    g_assert_false(subject_alive(&options));
    --options.start_time;
    options.uid = options.uid == 1 ? 2 : 1;
    g_assert_false(subject_alive(&options));
}

static void test_hardening_streams(void)
{
    /* Isolate stdio/prctl/rlimit changes, not GTK or authentication, in a child. */
    int pipefd[2];
    g_assert_cmpint(pipe(pipefd), ==, 0);
    pid_t child = fork();
    g_assert_cmpint(child, >=, 0);
    if (child == 0) {
        close(pipefd[0]);
        if (dup2(pipefd[1], STDOUT_FILENO) < 0 || dup2(pipefd[1], STDERR_FILENO) < 0) _exit(2);
        close(pipefd[1]);
        int protocol = harden_process();
        if (protocol < 0 || prctl(PR_GET_DUMPABLE) != 0) _exit(3);
        for (int fd = 0; fd < 3; ++fd)
            if ((fcntl(fd, F_GETFD) & FD_CLOEXEC) == 0) _exit(4);
        if ((fcntl(protocol, F_GETFD) & FD_CLOEXEC) == 0) _exit(5);
        struct rlimit limit;
        if (getrlimit(RLIMIT_CORE, &limit) != 0 || limit.rlim_cur != 0 || limit.rlim_max != 0) _exit(6);
        if (write(STDOUT_FILENO, "credential-canary", 17) != 17 ||
            write(STDERR_FILENO, "PAM-cookie-canary", 17) != 17) _exit(7);
        if (write(protocol, "READY\n", 6) != 6) _exit(8);
        close(protocol);
        _exit(0);
    }
    close(pipefd[1]);
    gchar bytes[256] = {0};
    ssize_t n = read(pipefd[0], bytes, sizeof bytes - 1);
    g_assert_cmpint(n, ==, 6);
    g_assert_cmpstr(bytes, ==, "READY\n");
    int status;
    g_assert_cmpint(waitpid(child, &status, 0), ==, child);
    g_assert_true(WIFEXITED(status));
    g_assert_cmpint(WEXITSTATUS(status), ==, 0);
    close(pipefd[0]);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_set_prgname("AgentKeyringApproval");
    gdk_set_program_class("AgentKeyringApproval");
    gtk_init(&argc, &argv);
    g_test_add_func("/approval/dialog-layout", test_dialog_layout);
    g_test_add_func("/approval/long-literal-message", test_long_literal_message);
    g_test_add_func("/approval/options-parser", test_options_parser);
    g_test_add_func("/approval/correlation", test_correlation);
    g_test_add_func("/approval/rejected-identity-precancel", test_rejected_identity_and_precancel);
    g_test_add_func("/approval/control-before-session-cancel", test_control_precedes_session_cancellation);
    g_test_add_func("/approval/generations-stale-callbacks", test_generations_stale_callbacks);
    g_test_add_func("/approval/identity-enter-multiple-prompts", test_identity_enter_multiple_prompts);
    g_test_add_func("/approval/cancellation", test_cancellation);
    g_test_add_func("/approval/queued-old-cancellation", test_queued_old_cancellation);
    g_test_add_func("/approval/synchronous-initiate-completion", test_sync_initiate_complete);
    g_test_add_func("/approval/choice-limit", test_choice_limit);
    g_test_add_func("/approval/liveness-deadline", test_liveness_and_deadline);
    g_test_add_func("/approval/subject-identity", test_subject_identity);
    g_test_add_func("/approval/hardening-control-streams", test_hardening_streams);
    return g_test_run();
}
