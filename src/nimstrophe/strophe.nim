##  strophe.h
## * strophe XMPP client library C API
## *
## * Copyright (C) 2005-2009 Collecta, Inc.
## *
## *  This software is provided AS-IS with no warranty, either express or
## *  implied.
## *
## *  This software is dual licensed under the MIT and GPLv3 licenses.
##
## * @file
##   Strophe public C API definitions.
##

{.deadCodeElim: on.}
const
  libstrophelib* = "libstrophe.so.0.0.0"

##  namespace defines
## * @def XMPP_NS_CLIENT
##   Namespace definition for 'jabber:client'.
##

const
  XMPP_NS_CLIENT* = "jabber:client"

## * @def XMPP_NS_COMPONENT
##   Namespace definition for 'jabber:component:accept'.
##

const
  XMPP_NS_COMPONENT* = "jabber:component:accept"

## * @def XMPP_NS_STREAMS
##   Namespace definition for 'http://etherx.jabber.org/streams'.
##

const
  XMPP_NS_STREAMS* = "http://etherx.jabber.org/streams"

## * @def XMPP_NS_STREAMS_IETF
##   Namespace definition for 'urn:ietf:params:xml:ns:xmpp-streams'.
##

const
  XMPP_NS_STREAMS_IETF* = "urn:ietf:params:xml:ns:xmpp-streams"

## * @def XMPP_NS_TLS
##   Namespace definition for 'url:ietf:params:xml:ns:xmpp-tls'.
##

const
  XMPP_NS_TLS* = "urn:ietf:params:xml:ns:xmpp-tls"

## * @def XMPP_NS_SASL
##   Namespace definition for 'urn:ietf:params:xml:ns:xmpp-sasl'.
##

const
  XMPP_NS_SASL* = "urn:ietf:params:xml:ns:xmpp-sasl"

## * @def XMPP_NS_BIND
##   Namespace definition for 'urn:ietf:params:xml:ns:xmpp-bind'.
##

const
  XMPP_NS_BIND* = "urn:ietf:params:xml:ns:xmpp-bind"

## * @def XMPP_NS_SESSION
##   Namespace definition for 'urn:ietf:params:xml:ns:xmpp-session'.
##

const
  XMPP_NS_SESSION* = "urn:ietf:params:xml:ns:xmpp-session"

## * @def XMPP_NS_AUTH
##   Namespace definition for 'jabber:iq:auth'.
##

const
  XMPP_NS_AUTH* = "jabber:iq:auth"

## * @def XMPP_NS_DISCO_INFO
##   Namespace definition for 'http://jabber.org/protocol/disco#info'.
##

const
  XMPP_NS_DISCO_INFO* = "http://jabber.org/protocol/disco#info"

## * @def XMPP_NS_DISCO_ITEMS
##   Namespace definition for 'http://jabber.org/protocol/disco#items'.
##

const
  XMPP_NS_DISCO_ITEMS* = "http://jabber.org/protocol/disco#items"

## * @def XMPP_NS_ROSTER
##   Namespace definition for 'jabber:iq:roster'.
##

const
  XMPP_NS_ROSTER* = "jabber:iq:roster"

## * @def XMPP_NS_REGISTER
##   Namespace definition for 'jabber:iq:register'.
##

const
  XMPP_NS_REGISTER* = "jabber:iq:register"

##  error defines
## * @def XMPP_EOK
##   Success error code.
##

const
  XMPP_EOK* = 0

## * @def XMPP_EMEM
##   Memory related failure error code.
##
##   This is returned on allocation errors and signals that the host may
##   be out of memory.
##

const
  XMPP_EMEM* = -1

## * @def XMPP_EINVOP
##   Invalid operation error code.
##
##   This error code is returned when the operation was invalid and signals
##   that the Strophe API is being used incorrectly.
##

const
  XMPP_EINVOP* = -2

## * @def XMPP_EINT
##   Internal failure error code.
##

const
  XMPP_EINT* = -3

##  initialization and shutdown

proc xmpp_initialize*() {.cdecl, importc: "xmpp_initialize", dynlib: libstrophelib.}
proc xmpp_shutdown*() {.cdecl, importc: "xmpp_shutdown", dynlib: libstrophelib.}
##  version

proc xmpp_version_check*(major: cint; minor: cint): cint {.cdecl,
    importc: "xmpp_version_check", dynlib: libstrophelib.}
##  run-time contexts
##  user-replaceable memory allocator

type
  xmpp_mem_t* {.extern: "_xmpp_mem_t"} = object

##  user-replaceable log object

type
  xmpp_log_t* {.extern: "_xmpp_log_t".} = object

##  opaque run time context containing the above hooks

type
  xmpp_ctx_t* {.extern: "_xmpp_ctx_t".} = object

proc xmpp_ctx_new*(mem: ptr xmpp_mem_t; log: ptr xmpp_log_t): ptr xmpp_ctx_t {.cdecl,
    importc: "xmpp_ctx_new", dynlib: libstrophelib.}
proc xmpp_ctx_free*(ctx: ptr xmpp_ctx_t) {.cdecl, importc: "xmpp_ctx_free",
                                       dynlib: libstrophelib.}
##  free some blocks returned by other APIs, for example the
##    buffer you get from xmpp_stanza_to_text

proc xmpp_free*(ctx: ptr xmpp_ctx_t; p: pointer) {.cdecl, importc: "xmpp_free",
    dynlib: libstrophelib.}

type
  xmpp_log_level_t* {.size: sizeof(cint).} = enum
    XMPP_LEVEL_DEBUG, XMPP_LEVEL_INFO, XMPP_LEVEL_WARN, XMPP_LEVEL_ERROR
  xmpp_conn_type_t* {.size: sizeof(cint).} = enum
    XMPP_UNKNOWN, XMPP_CLIENT, XMPP_COMPONENT
  xmpp_log_handler* = proc (userdata: pointer; level: xmpp_log_level_t; area: cstring;
                         msg: cstring) {.cdecl.}



# type
#   xmpp_log_t* {.bycopy.} = object
#     handler*: xmpp_log_handler
#     userdata*: pointer


##  return a default logger filtering at a given level

proc xmpp_get_default_logger*(level: xmpp_log_level_t): ptr xmpp_log_t {.cdecl,
    importc: "xmpp_get_default_logger", dynlib: libstrophelib.}
##  connection
##  opaque connection object

type
  xmpp_conn_t* {.extern: "_xmpp_conn_t".} = object
  xmpp_stanza_t* {.extern: "_xmpp_conn_t".} = object

##  connection flags

const
  XMPP_CONN_FLAG_DISABLE_TLS* = (1 shl 0)
  XMPP_CONN_FLAG_MANDATORY_TLS* = (1 shl 1)
  XMPP_CONN_FLAG_LEGACY_SSL* = (1 shl 2)

## * @def XMPP_CONN_FLAG_TRUST_TLS
##   Trust server's certificate even if it is invalid.
##

const
  XMPP_CONN_FLAG_TRUST_TLS* = (1 shl 3)

## * @def XMPP_CONN_FLAG_LEGACY_AUTH
##   Enable legacy authentication support.
##

const
  XMPP_CONN_FLAG_LEGACY_AUTH* = (1 shl 4)

##  connect callback

type
  xmpp_conn_event_t* {.size: sizeof(cint).} = enum
    XMPP_CONN_CONNECT, XMPP_CONN_RAW_CONNECT, XMPP_CONN_DISCONNECT, XMPP_CONN_FAIL
  xmpp_error_type_t* {.size: sizeof(cint).} = enum
    XMPP_SE_BAD_FORMAT, XMPP_SE_BAD_NS_PREFIX, XMPP_SE_CONFLICT,
    XMPP_SE_CONN_TIMEOUT, XMPP_SE_HOST_GONE, XMPP_SE_HOST_UNKNOWN,
    XMPP_SE_IMPROPER_ADDR, XMPP_SE_INTERNAL_SERVER_ERROR, XMPP_SE_INVALID_FROM,
    XMPP_SE_INVALID_ID, XMPP_SE_INVALID_NS, XMPP_SE_INVALID_XML,
    XMPP_SE_NOT_AUTHORIZED, XMPP_SE_POLICY_VIOLATION, XMPP_SE_REMOTE_CONN_FAILED,
    XMPP_SE_RESOURCE_CONSTRAINT, XMPP_SE_RESTRICTED_XML, XMPP_SE_SEE_OTHER_HOST,
    XMPP_SE_SYSTEM_SHUTDOWN, XMPP_SE_UNDEFINED_CONDITION,
    XMPP_SE_UNSUPPORTED_ENCODING, XMPP_SE_UNSUPPORTED_STANZA_TYPE,
    XMPP_SE_UNSUPPORTED_VERSION, XMPP_SE_XML_NOT_WELL_FORMED
  xmpp_stream_error_t* {.bycopy.} = object
    `type`*: xmpp_error_type_t
    text*: cstring
    stanza*: ptr xmpp_stanza_t

  xmpp_conn_handler* = proc (conn: ptr xmpp_conn_t; event: xmpp_conn_event_t;
                          error: cint; stream_error: ptr xmpp_stream_error_t;
                          userdata: pointer) {.cdecl.}



proc xmpp_send_error*(conn: ptr xmpp_conn_t; `type`: xmpp_error_type_t; text: cstring) {.
    cdecl, importc: "xmpp_send_error", dynlib: libstrophelib.}
proc xmpp_conn_new*(ctx: ptr xmpp_ctx_t): ptr xmpp_conn_t {.cdecl,
    importc: "xmpp_conn_new", dynlib: libstrophelib.}
proc xmpp_conn_clone*(conn: ptr xmpp_conn_t): ptr xmpp_conn_t {.cdecl,
    importc: "xmpp_conn_clone", dynlib: libstrophelib.}
proc xmpp_conn_release*(conn: ptr xmpp_conn_t): cint {.cdecl,
    importc: "xmpp_conn_release", dynlib: libstrophelib.}
proc xmpp_conn_get_flags*(conn: ptr xmpp_conn_t): clong {.cdecl,
    importc: "xmpp_conn_get_flags", dynlib: libstrophelib.}
proc xmpp_conn_set_flags*(conn: ptr xmpp_conn_t; flags: clong): cint {.cdecl,
    importc: "xmpp_conn_set_flags", dynlib: libstrophelib.}
proc xmpp_conn_get_jid*(conn: ptr xmpp_conn_t): cstring {.cdecl,
    importc: "xmpp_conn_get_jid", dynlib: libstrophelib.}
proc xmpp_conn_get_bound_jid*(conn: ptr xmpp_conn_t): cstring {.cdecl,
    importc: "xmpp_conn_get_bound_jid", dynlib: libstrophelib.}
proc xmpp_conn_set_jid*(conn: ptr xmpp_conn_t; jid: cstring) {.cdecl,
    importc: "xmpp_conn_set_jid", dynlib: libstrophelib.}
proc xmpp_conn_get_pass*(conn: ptr xmpp_conn_t): cstring {.cdecl,
    importc: "xmpp_conn_get_pass", dynlib: libstrophelib.}
proc xmpp_conn_set_pass*(conn: ptr xmpp_conn_t; pass: cstring) {.cdecl,
    importc: "xmpp_conn_set_pass", dynlib: libstrophelib.}
proc xmpp_conn_get_context*(conn: ptr xmpp_conn_t): ptr xmpp_ctx_t {.cdecl,
    importc: "xmpp_conn_get_context", dynlib: libstrophelib.}
proc xmpp_conn_disable_tls*(conn: ptr xmpp_conn_t) {.cdecl,
    importc: "xmpp_conn_disable_tls", dynlib: libstrophelib.}
proc xmpp_conn_is_secured*(conn: ptr xmpp_conn_t): cint {.cdecl,
    importc: "xmpp_conn_is_secured", dynlib: libstrophelib.}
proc xmpp_conn_set_keepalive*(conn: ptr xmpp_conn_t; timeout: cint; interval: cint) {.
    cdecl, importc: "xmpp_conn_set_keepalive", dynlib: libstrophelib.}
proc xmpp_conn_is_connecting*(conn: ptr xmpp_conn_t): cint {.cdecl,
    importc: "xmpp_conn_is_connecting", dynlib: libstrophelib.}
proc xmpp_conn_is_connected*(conn: ptr xmpp_conn_t): cint {.cdecl,
    importc: "xmpp_conn_is_connected", dynlib: libstrophelib.}
proc xmpp_conn_is_disconnected*(conn: ptr xmpp_conn_t): cint {.cdecl,
    importc: "xmpp_conn_is_disconnected", dynlib: libstrophelib.}
proc xmpp_connect_client*(conn: ptr xmpp_conn_t; altdomain: cstring; altport: cushort;
                         callback: xmpp_conn_handler; userdata: pointer): cint {.
    cdecl, importc: "xmpp_connect_client", dynlib: libstrophelib.}
proc xmpp_connect_component*(conn: ptr xmpp_conn_t; server: cstring; port: cushort;
                            callback: xmpp_conn_handler; userdata: pointer): cint {.
    cdecl, importc: "xmpp_connect_component", dynlib: libstrophelib.}
proc xmpp_connect_raw*(conn: ptr xmpp_conn_t; altdomain: cstring; altport: cushort;
                      callback: xmpp_conn_handler; userdata: pointer): cint {.cdecl,
    importc: "xmpp_connect_raw", dynlib: libstrophelib.}
proc xmpp_conn_open_stream_default*(conn: ptr xmpp_conn_t): cint {.cdecl,
    importc: "xmpp_conn_open_stream_default", dynlib: libstrophelib.}
proc xmpp_conn_open_stream*(conn: ptr xmpp_conn_t; attributes: cstringArray;
                           attributes_len: csize): cint {.cdecl,
    importc: "xmpp_conn_open_stream", dynlib: libstrophelib.}
proc xmpp_conn_tls_start*(conn: ptr xmpp_conn_t): cint {.cdecl,
    importc: "xmpp_conn_tls_start", dynlib: libstrophelib.}
proc xmpp_disconnect*(conn: ptr xmpp_conn_t) {.cdecl, importc: "xmpp_disconnect",
    dynlib: libstrophelib.}
proc xmpp_send*(conn: ptr xmpp_conn_t; stanza: ptr xmpp_stanza_t) {.cdecl,
    importc: "xmpp_send", dynlib: libstrophelib.}
proc xmpp_send_raw_string*(conn: ptr xmpp_conn_t; fmt: cstring) {.varargs, cdecl,
    importc: "xmpp_send_raw_string", dynlib: libstrophelib.}
proc xmpp_send_raw*(conn: ptr xmpp_conn_t; data: cstring; len: csize) {.cdecl,
    importc: "xmpp_send_raw", dynlib: libstrophelib.}
##  handlers
##  if the handle returns false it is removed

type
  xmpp_timed_handler* = proc (conn: ptr xmpp_conn_t; userdata: pointer): cint {.cdecl.}

proc xmpp_timed_handler_add*(conn: ptr xmpp_conn_t; handler: xmpp_timed_handler;
                            period: culong; userdata: pointer) {.cdecl,
    importc: "xmpp_timed_handler_add", dynlib: libstrophelib.}
proc xmpp_timed_handler_delete*(conn: ptr xmpp_conn_t; handler: xmpp_timed_handler) {.
    cdecl, importc: "xmpp_timed_handler_delete", dynlib: libstrophelib.}
##  if the handler returns false it is removed

type
  xmpp_handler* = proc (conn: ptr xmpp_conn_t; stanza: ptr xmpp_stanza_t;
                     userdata: pointer): cint {.cdecl.}

proc xmpp_handler_add*(conn: ptr xmpp_conn_t; handler: xmpp_handler; ns: cstring;
                      name: cstring; `type`: cstring; userdata: pointer) {.cdecl,
    importc: "xmpp_handler_add", dynlib: libstrophelib.}
proc xmpp_handler_delete*(conn: ptr xmpp_conn_t; handler: xmpp_handler) {.cdecl,
    importc: "xmpp_handler_delete", dynlib: libstrophelib.}
proc xmpp_id_handler_add*(conn: ptr xmpp_conn_t; handler: xmpp_handler; id: cstring;
                         userdata: pointer) {.cdecl,
    importc: "xmpp_id_handler_add", dynlib: libstrophelib.}
proc xmpp_id_handler_delete*(conn: ptr xmpp_conn_t; handler: xmpp_handler; id: cstring) {.
    cdecl, importc: "xmpp_id_handler_delete", dynlib: libstrophelib.}
##
## void xmpp_register_stanza_handler(conn, stanza, xmlns, type, handler)
##
##  stanzas
##  allocate and initialize a blank stanza

proc xmpp_stanza_new*(ctx: ptr xmpp_ctx_t): ptr xmpp_stanza_t {.cdecl,
    importc: "xmpp_stanza_new", dynlib: libstrophelib.}
##  clone a stanza

proc xmpp_stanza_clone*(stanza: ptr xmpp_stanza_t): ptr xmpp_stanza_t {.cdecl,
    importc: "xmpp_stanza_clone", dynlib: libstrophelib.}
##  copies a stanza and all children

proc xmpp_stanza_copy*(stanza: ptr xmpp_stanza_t): ptr xmpp_stanza_t {.cdecl,
    importc: "xmpp_stanza_copy", dynlib: libstrophelib.}
##  free a stanza object and it's contents

proc xmpp_stanza_release*(stanza: ptr xmpp_stanza_t): cint {.cdecl,
    importc: "xmpp_stanza_release", dynlib: libstrophelib.}
proc xmpp_stanza_get_context*(stanza: ptr xmpp_stanza_t): ptr xmpp_ctx_t {.cdecl,
    importc: "xmpp_stanza_get_context", dynlib: libstrophelib.}
proc xmpp_stanza_is_text*(stanza: ptr xmpp_stanza_t): cint {.cdecl,
    importc: "xmpp_stanza_is_text", dynlib: libstrophelib.}
proc xmpp_stanza_is_tag*(stanza: ptr xmpp_stanza_t): cint {.cdecl,
    importc: "xmpp_stanza_is_tag", dynlib: libstrophelib.}
##  marshall a stanza into text for transmission or display

proc xmpp_stanza_to_text*(stanza: ptr xmpp_stanza_t; buf: cstringArray;
                         buflen: ptr csize): cint {.cdecl,
    importc: "xmpp_stanza_to_text", dynlib: libstrophelib.}
proc xmpp_stanza_get_children*(stanza: ptr xmpp_stanza_t): ptr xmpp_stanza_t {.cdecl,
    importc: "xmpp_stanza_get_children", dynlib: libstrophelib.}
proc xmpp_stanza_get_child_by_name*(stanza: ptr xmpp_stanza_t; name: cstring): ptr xmpp_stanza_t {.
    cdecl, importc: "xmpp_stanza_get_child_by_name", dynlib: libstrophelib.}
proc xmpp_stanza_get_child_by_ns*(stanza: ptr xmpp_stanza_t; ns: cstring): ptr xmpp_stanza_t {.
    cdecl, importc: "xmpp_stanza_get_child_by_ns", dynlib: libstrophelib.}
proc xmpp_stanza_get_child_by_name_and_ns*(stanza: ptr xmpp_stanza_t; name: cstring;
    ns: cstring): ptr xmpp_stanza_t {.cdecl, importc: "xmpp_stanza_get_child_by_name_and_ns",
                                  dynlib: libstrophelib.}
proc xmpp_stanza_get_next*(stanza: ptr xmpp_stanza_t): ptr xmpp_stanza_t {.cdecl,
    importc: "xmpp_stanza_get_next", dynlib: libstrophelib.}
proc xmpp_stanza_add_child*(stanza: ptr xmpp_stanza_t; child: ptr xmpp_stanza_t): cint {.
    cdecl, importc: "xmpp_stanza_add_child", dynlib: libstrophelib.}
proc xmpp_stanza_add_child_ex*(stanza: ptr xmpp_stanza_t; child: ptr xmpp_stanza_t;
                              do_clone: cint): cint {.cdecl,
    importc: "xmpp_stanza_add_child_ex", dynlib: libstrophelib.}
proc xmpp_stanza_get_attribute*(stanza: ptr xmpp_stanza_t; name: cstring): cstring {.
    cdecl, importc: "xmpp_stanza_get_attribute", dynlib: libstrophelib.}
proc xmpp_stanza_get_attribute_count*(stanza: ptr xmpp_stanza_t): cint {.cdecl,
    importc: "xmpp_stanza_get_attribute_count", dynlib: libstrophelib.}
proc xmpp_stanza_get_attributes*(stanza: ptr xmpp_stanza_t; attr: cstringArray;
                                attrlen: cint): cint {.cdecl,
    importc: "xmpp_stanza_get_attributes", dynlib: libstrophelib.}
##  concatenate all child text nodes.  this function
##  returns a string that must be freed by the caller

proc xmpp_stanza_get_text*(stanza: ptr xmpp_stanza_t): cstring {.cdecl,
    importc: "xmpp_stanza_get_text", dynlib: libstrophelib.}
proc xmpp_stanza_get_text_ptr*(stanza: ptr xmpp_stanza_t): cstring {.cdecl,
    importc: "xmpp_stanza_get_text_ptr", dynlib: libstrophelib.}
proc xmpp_stanza_get_name*(stanza: ptr xmpp_stanza_t): cstring {.cdecl,
    importc: "xmpp_stanza_get_name", dynlib: libstrophelib.}
##  set_attribute adds/replaces attributes

proc xmpp_stanza_set_attribute*(stanza: ptr xmpp_stanza_t; key: cstring;
                               value: cstring): cint {.cdecl,
    importc: "xmpp_stanza_set_attribute", dynlib: libstrophelib.}
proc xmpp_stanza_set_name*(stanza: ptr xmpp_stanza_t; name: cstring): cint {.cdecl,
    importc: "xmpp_stanza_set_name", dynlib: libstrophelib.}
proc xmpp_stanza_set_text*(stanza: ptr xmpp_stanza_t; text: cstring): cint {.cdecl,
    importc: "xmpp_stanza_set_text", dynlib: libstrophelib.}
proc xmpp_stanza_set_text_with_size*(stanza: ptr xmpp_stanza_t; text: cstring;
                                    size: csize): cint {.cdecl,
    importc: "xmpp_stanza_set_text_with_size", dynlib: libstrophelib.}
proc xmpp_stanza_del_attribute*(stanza: ptr xmpp_stanza_t; name: cstring): cint {.
    cdecl, importc: "xmpp_stanza_del_attribute", dynlib: libstrophelib.}
##  common stanza helpers

proc xmpp_stanza_get_ns*(stanza: ptr xmpp_stanza_t): cstring {.cdecl,
    importc: "xmpp_stanza_get_ns", dynlib: libstrophelib.}
proc xmpp_stanza_get_type*(stanza: ptr xmpp_stanza_t): cstring {.cdecl,
    importc: "xmpp_stanza_get_type", dynlib: libstrophelib.}
proc xmpp_stanza_get_id*(stanza: ptr xmpp_stanza_t): cstring {.cdecl,
    importc: "xmpp_stanza_get_id", dynlib: libstrophelib.}
proc xmpp_stanza_get_to*(stanza: ptr xmpp_stanza_t): cstring {.cdecl,
    importc: "xmpp_stanza_get_to", dynlib: libstrophelib.}
proc xmpp_stanza_get_from*(stanza: ptr xmpp_stanza_t): cstring {.cdecl,
    importc: "xmpp_stanza_get_from", dynlib: libstrophelib.}
proc xmpp_stanza_set_ns*(stanza: ptr xmpp_stanza_t; ns: cstring): cint {.cdecl,
    importc: "xmpp_stanza_set_ns", dynlib: libstrophelib.}
proc xmpp_stanza_set_id*(stanza: ptr xmpp_stanza_t; id: cstring): cint {.cdecl,
    importc: "xmpp_stanza_set_id", dynlib: libstrophelib.}
proc xmpp_stanza_set_type*(stanza: ptr xmpp_stanza_t; `type`: cstring): cint {.cdecl,
    importc: "xmpp_stanza_set_type", dynlib: libstrophelib.}
proc xmpp_stanza_set_to*(stanza: ptr xmpp_stanza_t; to: cstring): cint {.cdecl,
    importc: "xmpp_stanza_set_to", dynlib: libstrophelib.}
proc xmpp_stanza_set_from*(stanza: ptr xmpp_stanza_t; `from`: cstring): cint {.cdecl,
    importc: "xmpp_stanza_set_from", dynlib: libstrophelib.}
##  allocate and initialize a stanza in reply to another

proc xmpp_stanza_reply*(stanza: ptr xmpp_stanza_t): ptr xmpp_stanza_t {.cdecl,
    importc: "xmpp_stanza_reply", dynlib: libstrophelib.}
##  stanza subclasses

proc xmpp_message_new*(ctx: ptr xmpp_ctx_t; `type`: cstring; to: cstring; id: cstring): ptr xmpp_stanza_t {.
    cdecl, importc: "xmpp_message_new", dynlib: libstrophelib.}
proc xmpp_message_get_body*(msg: ptr xmpp_stanza_t): cstring {.cdecl,
    importc: "xmpp_message_get_body", dynlib: libstrophelib.}
proc xmpp_message_set_body*(msg: ptr xmpp_stanza_t; text: cstring): cint {.cdecl,
    importc: "xmpp_message_set_body", dynlib: libstrophelib.}
proc xmpp_iq_new*(ctx: ptr xmpp_ctx_t; `type`: cstring; id: cstring): ptr xmpp_stanza_t {.
    cdecl, importc: "xmpp_iq_new", dynlib: libstrophelib.}
proc xmpp_presence_new*(ctx: ptr xmpp_ctx_t): ptr xmpp_stanza_t {.cdecl,
    importc: "xmpp_presence_new", dynlib: libstrophelib.}
proc xmpp_error_new*(ctx: ptr xmpp_ctx_t; `type`: xmpp_error_type_t; text: cstring): ptr xmpp_stanza_t {.
    cdecl, importc: "xmpp_error_new", dynlib: libstrophelib.}
##  jid
##  these return new strings that must be xmpp_free()'d

proc xmpp_jid_new*(ctx: ptr xmpp_ctx_t; node: cstring; domain: cstring;
                  resource: cstring): cstring {.cdecl, importc: "xmpp_jid_new",
    dynlib: libstrophelib.}
proc xmpp_jid_bare*(ctx: ptr xmpp_ctx_t; jid: cstring): cstring {.cdecl,
    importc: "xmpp_jid_bare", dynlib: libstrophelib.}
proc xmpp_jid_node*(ctx: ptr xmpp_ctx_t; jid: cstring): cstring {.cdecl,
    importc: "xmpp_jid_node", dynlib: libstrophelib.}
proc xmpp_jid_domain*(ctx: ptr xmpp_ctx_t; jid: cstring): cstring {.cdecl,
    importc: "xmpp_jid_domain", dynlib: libstrophelib.}
proc xmpp_jid_resource*(ctx: ptr xmpp_ctx_t; jid: cstring): cstring {.cdecl,
    importc: "xmpp_jid_resource", dynlib: libstrophelib.}
##  event loop

proc xmpp_run_once*(ctx: ptr xmpp_ctx_t; timeout: culong) {.cdecl,
    importc: "xmpp_run_once", dynlib: libstrophelib.}
proc xmpp_run*(ctx: ptr xmpp_ctx_t) {.cdecl, importc: "xmpp_run", dynlib: libstrophelib.}
proc xmpp_stop*(ctx: ptr xmpp_ctx_t) {.cdecl, importc: "xmpp_stop",
                                   dynlib: libstrophelib.}
proc xmpp_ctx_set_timeout*(ctx: ptr xmpp_ctx_t; timeout: culong) {.cdecl,
    importc: "xmpp_ctx_set_timeout", dynlib: libstrophelib.}
##  UUID

proc xmpp_uuid_gen*(ctx: ptr xmpp_ctx_t): cstring {.cdecl, importc: "xmpp_uuid_gen",
    dynlib: libstrophelib.}
##  SHA1
## * @def XMPP_SHA1_DIGEST_SIZE
##   Size of the SHA1 message digest.
##

const
  XMPP_SHA1_DIGEST_SIZE* = 20

type
  xmpp_sha1_t* {.importc: "_xmpp_log_t".} = object

proc xmpp_sha1*(ctx: ptr xmpp_ctx_t; data: ptr cuchar; len: csize): cstring {.cdecl,
    importc: "xmpp_sha1", dynlib: libstrophelib.}
proc xmpp_sha1_digest*(data: ptr cuchar; len: csize; digest: ptr cuchar) {.cdecl,
    importc: "xmpp_sha1_digest", dynlib: libstrophelib.}
proc xmpp_sha1_new*(ctx: ptr xmpp_ctx_t): ptr xmpp_sha1_t {.cdecl,
    importc: "xmpp_sha1_new", dynlib: libstrophelib.}
proc xmpp_sha1_free*(sha1: ptr xmpp_sha1_t) {.cdecl, importc: "xmpp_sha1_free",
    dynlib: libstrophelib.}
proc xmpp_sha1_update*(sha1: ptr xmpp_sha1_t; data: ptr cuchar; len: csize) {.cdecl,
    importc: "xmpp_sha1_update", dynlib: libstrophelib.}
proc xmpp_sha1_final*(sha1: ptr xmpp_sha1_t) {.cdecl, importc: "xmpp_sha1_final",
    dynlib: libstrophelib.}
proc xmpp_sha1_to_string*(sha1: ptr xmpp_sha1_t; s: cstring; slen: csize): cstring {.
    cdecl, importc: "xmpp_sha1_to_string", dynlib: libstrophelib.}
proc xmpp_sha1_to_string_alloc*(sha1: ptr xmpp_sha1_t): cstring {.cdecl,
    importc: "xmpp_sha1_to_string_alloc", dynlib: libstrophelib.}
proc xmpp_sha1_to_digest*(sha1: ptr xmpp_sha1_t; digest: ptr cuchar) {.cdecl,
    importc: "xmpp_sha1_to_digest", dynlib: libstrophelib.}
##  Base64

proc xmpp_base64_encode*(ctx: ptr xmpp_ctx_t; data: ptr cuchar; len: csize): cstring {.
    cdecl, importc: "xmpp_base64_encode", dynlib: libstrophelib.}
proc xmpp_base64_decode_str*(ctx: ptr xmpp_ctx_t; base64: cstring; len: csize): cstring {.
    cdecl, importc: "xmpp_base64_decode_str", dynlib: libstrophelib.}
proc xmpp_base64_decode_bin*(ctx: ptr xmpp_ctx_t; base64: cstring; len: csize;
                            `out`: ptr ptr cuchar; outlen: ptr csize) {.cdecl,
    importc: "xmpp_base64_decode_bin", dynlib: libstrophelib.}