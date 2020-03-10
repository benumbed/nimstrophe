
import nimstrophe/strophe

proc version_handler(conn: ptr xmpp_conn_t, stanza: ptr xmpp_stanza_t, ctx: ptr xmpp_ctx_t) = 

    # xmpp_stanza_t *reply, *query, *name, *version, *text
    var reply, query, name, version, text: ptr xmpp_stanza_t

    reply = xmpp_stanza_reply(stanza)
    discard xmpp_stanza_set_type(reply, "result")

    query = xmpp_stanza_new(ctx)
    discard xmpp_stanza_set_name(query, "query")
    let ns = xmpp_stanza_get_ns(xmpp_stanza_get_children(stanza))
    if ns.len != 0:
        discard xmpp_stanza_set_ns(query, ns)

    name = xmpp_stanza_new(ctx)
    discard xmpp_stanza_set_name(name, "name")
    discard xmpp_stanza_add_child(query, name)
    discard xmpp_stanza_release(name)

    text = xmpp_stanza_new(ctx)
    discard xmpp_stanza_set_text(text, "libstrophe example bot")
    discard xmpp_stanza_add_child(name, text)
    discard xmpp_stanza_release(text)

    version = xmpp_stanza_new(ctx)
    discard xmpp_stanza_set_name(version, "version")
    discard xmpp_stanza_add_child(query, version)
    discard xmpp_stanza_release(version)

    text = xmpp_stanza_new(ctx)
    discard xmpp_stanza_set_text(text, "1.0")
    discard xmpp_stanza_add_child(version, text)
    discard xmpp_stanza_release(text)

    discard xmpp_stanza_add_child(reply, query)
    discard xmpp_stanza_release(query)

    xmpp_send(conn, reply)
    discard xmpp_stanza_release(reply)


proc conn_handler(conn: ptr xmpp_conn_t, status: xmpp_conn_event_t, error: cint, stream_error: ptr xmpp_stream_error_t, ctx: ptr xmpp_ctx_t) =

    if status == XMPP_CONN_CONNECT:
        xmpp_handler_add(conn, cast[xmpp_handler](version_handler), "jabber:iq:version", "iq", nil, ctx);
        # xmpp_handler_add(conn, message_handler, NULL, "message", NULL, ctx);

        # Send initial <presence/> so that we appear online to contacts
        let pres = xmpp_presence_new(ctx);
        xmpp_send(conn, pres);
        discard xmpp_stanza_release(pres);
    else:
        xmpp_stop(ctx);

    return
    
xmpp_initialize()

var log = xmpp_get_default_logger(XMPP_LEVEL_DEBUG)
let ctx = xmpp_ctx_new(nil, log)

let conn = xmpp_conn_new(ctx)

# let jid: cstring = "andromeda_test@xmpp-01.grid.bunker"
# let pass: cstring = "temp123!"

xmpp_conn_set_jid(conn, "jid@example.com")
xmpp_conn_set_pass(conn, "xxxx")

discard xmpp_connect_client(conn, nil, 0, cast[xmpp_conn_handler](conn_handler), ctx)

xmpp_run(ctx)

discard xmpp_conn_release(conn)
xmpp_ctx_free(ctx)


xmpp_shutdown()
