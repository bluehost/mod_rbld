/*
 **************************************************************************
 * mod_rbld for Apache 2.x - RBLD module for the Apache web server
 * Copyright 2006 - 2014, Bluehost, Inc. (http://www.bluehost.com)
 *
 * You may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * If any of the files related to licensing are missing or if you have any
 * other questions related to licensing please contact Bluehost, Inc.
 * directly using the email address support@bluehost.com.
 *
 **************************************************************************
 *
 * Authors:
 * Erick Cantwell   <ecantwell@bluehost.com>
 * Spencer Candland <spencer@bluehost.com>
 * Sean Jenkins     <sean@bluehost.com>
 * 
 * http://www.bluehost.com
 * https://github.com/bluehost/mod_rbld
 *
 **************************************************************************
 *
 * Configuration can be done per server as follows:
 *  RBLDEnabled On
 *  RBLDSocketPath /var/tmp/rbld.sock
 *  RBLDDefaultQueryList HBL
 *  RBLDDefaultReturnCode 403
 *  RBLDDefaultMessage "Your custom message goes here"
 *
 * Configuration can be done with .htaccess or directory as follows:
 *  RBLDQueryList HBL
 *  RBLDReturnCode 403
 *  RBLDDefaultMessage "Your custom message goes here"
 *
 * Per-Dir configuration options override server defaults where applicable
 *
 ***************************************************************************
 */

#include <httpd.h>
#include <http_config.h>
#include <http_core.h>
#include <http_log.h>
#include <util_filter.h>
#include <apr_strings.h>
#include <http_request.h>
#include <apr_network_io.h>
/* Needed for client */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h> /* for sockaddr_un */
#include <netinet/in.h>
#include <netdb.h>
#include <ctype.h>
#include <errno.h>

#define MODULE_NAME           "mod_rbld"
#define MODULE_VERSION        "2.0"

module AP_MODULE_DECLARE_DATA rbld_module;

/* Our configuration structs */
typedef enum {
    RBL_UNSET, RBL_DISABLED, RBL_ENABLED
} mod_rbld_status_e;

typedef struct mod_rbld_config_t {
    mod_rbld_status_e enabled;
    char* querylist;
    char* sock_path;
    long returncode;
    const char* message;
    const char* errdocument;
} mod_rbld_config_t;

/* Get the server conf ready */
static void *mod_rbld_create_server_config(apr_pool_t *p, server_rec *s)
{
    mod_rbld_config_t *conf = (mod_rbld_config_t *) apr_pcalloc(p, sizeof(mod_rbld_config_t));
    conf->enabled     = RBL_UNSET;
    conf->returncode  = RBL_UNSET;
    conf->querylist   = NULL;
    conf->sock_path   = NULL;
    conf->message     = NULL;
    conf->errdocument = NULL;

    return conf;
}

/* Get the dir conf ready */
static void *mod_rbld_create_dir_config(apr_pool_t *p, char *s)
{
    mod_rbld_config_t *conf = (mod_rbld_config_t *) apr_pcalloc(p, sizeof(mod_rbld_config_t));
    conf->enabled     = RBL_UNSET;
    conf->returncode  = RBL_UNSET;
    conf->querylist   = NULL;
    conf->sock_path   = NULL;
    conf->message     = NULL;
    conf->errdocument = NULL;

    return conf;
}

/* Merge the server conf */
static void *mod_rbld_merge_server_config(apr_pool_t *p, void *parentv, void *childv)
{
    mod_rbld_config_t *parent = (mod_rbld_config_t *) parentv;
    mod_rbld_config_t *child  = (mod_rbld_config_t *) childv;
    mod_rbld_config_t *conf = apr_pcalloc(p, sizeof(mod_rbld_config_t));

    if(child->enabled == RBL_UNSET) {
        conf->enabled = parent->enabled;
    } else {
        conf->enabled = child->enabled;
    }

    if(child->returncode == RBL_UNSET) {
        conf->returncode = parent->returncode;
    } else {
        conf->returncode = child->returncode;
    }

    if(child->message == NULL) {
        conf->message = apr_pstrdup(p, parent->message);
    } else {
        conf->message = apr_pstrdup(p, child->message);
    }

    if(child->querylist == NULL) {
        conf->querylist = apr_pstrdup(p, parent->querylist);
    } else {
        conf->querylist = apr_pstrdup(p, child->querylist);
    }

    if(child->errdocument == NULL) {
        conf->errdocument = apr_pstrdup(p, parent->errdocument);
    } else {
        conf->errdocument = apr_pstrdup(p, child->errdocument);
    }

    conf->sock_path = parent->sock_path;

    return conf;
}

/* Merge the per-directory conf */
static void *mod_rbld_merge_dir_config(apr_pool_t *p, void *parentv, void *childv)
{
    mod_rbld_config_t *parent = (mod_rbld_config_t *) parentv;
    mod_rbld_config_t *child  = (mod_rbld_config_t *) childv;
    mod_rbld_config_t *conf   = apr_pcalloc(p, sizeof(mod_rbld_config_t));

    if(child->enabled == RBL_UNSET) {
        conf->enabled = parent->enabled;
    } else {
        conf->enabled = child->enabled;
    }

    if(child->returncode == RBL_UNSET) {
        conf->returncode = parent->returncode;
    } else {
        conf->returncode = child->returncode;
    }

    if (child->querylist == NULL) {
        conf->querylist = apr_pstrdup(p, parent->querylist);
    } else {
        conf->querylist = apr_pstrdup(p, child->querylist);
    }

    if (child->message == NULL) {
        conf->message = apr_pstrdup(p, parent->message);
    } else {
        conf->message = apr_pstrdup(p, child->message);
    }

    if (child->errdocument == NULL) {
        conf->errdocument = apr_pstrdup(p, parent->errdocument);
    } else {
        conf->errdocument = apr_pstrdup(p, child->errdocument);
    }

    conf->sock_path = parent->sock_path;
    
    return conf;
}

/* Function to see if mod_rbld should be enabled or not */
static const char *mod_rbld_set_enabled(cmd_parms *cmd, void *dummy, int enabled)
{
    mod_rbld_config_t *conf = ap_get_module_config(cmd->server->module_config, &rbld_module);
    conf->enabled = (enabled) ? RBL_ENABLED : RBL_DISABLED;
    return NULL;
}

/* Function to parse the socket path */
static const char *mod_rbld_parse_sockpath(cmd_parms *cmd, void *dummy, const char *path)
{
    mod_rbld_config_t *conf = (mod_rbld_config_t *)ap_get_module_config(cmd->server->module_config, &rbld_module);
    conf->sock_path = apr_pstrdup(cmd->pool, path);

    return NULL;
}

/* Function to set the query list */
static const char *mod_rbld_parse_querylist(cmd_parms *cmd, void *dirconfig, const char *querylist)
{
    mod_rbld_config_t *dconf = (mod_rbld_config_t *) dirconfig;
    dconf->querylist = apr_pstrdup(cmd->pool, querylist);

    return NULL;
}

/* Function to set the default query list */
static const char *mod_rbld_parse_default_querylist(cmd_parms *cmd, void *dummy, const char *querylist)
{
    mod_rbld_config_t *conf = (mod_rbld_config_t *)ap_get_module_config(cmd->server->module_config, &rbld_module);
    conf->querylist = apr_pstrdup(cmd->pool, querylist);

    return NULL;
}

/*
    Should we use HTTP_FORBIDDEN (403) or HTTP_UNAUTHORIZED (401)?
    According to http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html we should use
    FORBIDDEN, but we might find UNAUTHORIZED less used already, and therefore
    preferrable for our customers for customization.  For now we will default to FORBIDDEN
    unless otherwise specified.
*/

static const char *mod_rbld_parse_returncode(cmd_parms *cmd, void *dirconfig, const char *returncode)
{
    mod_rbld_config_t *dconf = (mod_rbld_config_t *) dirconfig;

    char* tmp = apr_pstrdup(cmd->pool, returncode);
    char* p;
    errno = 0;
    if (dconf->returncode == RBL_UNSET) {
        dconf->returncode = strtol(tmp, &p, 0);
    }

    /* Check for various possible errors */
    if ((errno == ERANGE && (dconf->returncode == LONG_MAX || dconf->returncode == LONG_MIN))
            || (errno != 0 && dconf->returncode == 0)) {
        ap_log_perror(APLOG_MARK, APLOG_ERR, 0, NULL, "[mod_rbld.c] RBLReturnCode must be numeric (401, 403, etc...)");
        /* Default to server conf later */
        dconf->returncode = RBL_UNSET;
    }

    if (p == tmp) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, NULL, "[mod_rbld.c] RBLReturnCode defaults to default");
        /* Default to server conf later */
        dconf->returncode = RBL_UNSET;
    }

    if (dconf->returncode == 0) {
        dconf->returncode = RBL_UNSET;
    }

    return NULL;
}

static const char *mod_rbld_parse_default_returncode(cmd_parms *cmd, void *dummy, const char *returncode)
{
    mod_rbld_config_t *conf = (mod_rbld_config_t *)ap_get_module_config(cmd->server->module_config, &rbld_module);

    char* tmp = apr_pstrdup(cmd->pool, returncode);
    char* p;
    errno = 0;
    if (conf->returncode == RBL_UNSET) {
        conf->returncode = strtol(tmp, &p, 0);
    }

    /* Check for various possible errors */
    if ((errno == ERANGE && (conf->returncode == LONG_MAX || conf->returncode == LONG_MIN))
            || (errno != 0 && conf->returncode == 0)) {
        ap_log_perror(APLOG_MARK, APLOG_ERR, 0, NULL, "[mod_rbld.c] RBLReturnCode must be numeric (401, 403, etc...)");
        ap_log_perror(APLOG_MARK, APLOG_INFO, 0, NULL, "[mod_rbld.c] RBLReturnCode defaults to 403");
        /* Default to 403 */
        conf->returncode = 403;
    }

    if (p == tmp) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, NULL, "[mod_rbld.c] RBLReturnCode defaults to 403");
        /* Default to 403 */
        conf->returncode = 403;
    }

    if (conf->returncode == 0) {
        conf->returncode = 403;
    }

    return NULL;
}

/* Grab the custom message from the client */
static const char *mod_rbld_parse_message(cmd_parms *cmd, void *dirconfig, const char *message)
{
    mod_rbld_config_t *dconf = (mod_rbld_config_t *) dirconfig;
    dconf->message = apr_pstrdup(cmd->pool, message);

    return NULL;
}

/* Grab the default custom message */
static const char *mod_rbld_parse_default_message(cmd_parms *cmd, void *dummy, const char *message)
{
    mod_rbld_config_t *conf = (mod_rbld_config_t *)ap_get_module_config(cmd->server->module_config, &rbld_module);
    conf->message = apr_pstrdup(cmd->pool, message);

    return NULL;
}

/* Grab the custom errordocument */
static const char *mod_rbld_parse_error_doc(cmd_parms *cmd, void *dirconfig, const char *errdocument)
{
    mod_rbld_config_t *dconf = (mod_rbld_config_t *) dirconfig;
    dconf->errdocument = apr_pstrdup(cmd->pool, errdocument);

    return NULL;
}

/* Grab the default error document */
static const char *mod_rbld_parse_default_error_doc(cmd_parms *cmd, void *dummy, const char *errdocument)
{
    mod_rbld_config_t *conf = (mod_rbld_config_t *)ap_get_module_config(cmd->server->module_config, &rbld_module);
    conf->errdocument = apr_pstrdup(cmd->pool, errdocument);

    return NULL;
}

/* Our Configuration */
command_rec mod_rbld_cmds[] = {
    AP_INIT_FLAG("RBLDEnabled",     mod_rbld_set_enabled,      NULL, ACCESS_CONF|RSRC_CONF, "Set to off to disable mod_rbld, Set to on to enable mod_rbld\n"),
    AP_INIT_TAKE1("RBLDSocketPath", mod_rbld_parse_sockpath,   NULL, RSRC_CONF, "The path to the rbld socket.\n"),
    AP_INIT_TAKE1("RBLDQueryList",  mod_rbld_parse_querylist,  NULL, ACCESS_CONF|RSRC_CONF|OR_ALL, "Which rbl we want to query.\n"),
    AP_INIT_TAKE1("RBLDReturnCode", mod_rbld_parse_returncode, NULL, ACCESS_CONF|RSRC_CONF|OR_ALL, "Code that mod_rbld should return with (401, 403, etc...). Defaults to 403\n"),
    AP_INIT_TAKE1("RBLDMessage",    mod_rbld_parse_message,    NULL, ACCESS_CONF|RSRC_CONF|OR_ALL, "Message that is returned to client in browser.\n"),
    AP_INIT_TAKE1("RBLDErrorDocument",        mod_rbld_parse_error_doc,          NULL, ACCESS_CONF|RSRC_CONF|OR_ALL, "Custom error document for mod_rbld.\n"),
    AP_INIT_TAKE1("RBLDDefaultMessage",       mod_rbld_parse_default_message,    NULL, RSRC_CONF, "Default message that is returned to client in browser.\n"),
    AP_INIT_TAKE1("RBLDDefaultQueryList",     mod_rbld_parse_default_querylist,  NULL, RSRC_CONF, "Default rbl we want to query.\n"),
    AP_INIT_TAKE1("RBLDDefaultReturnCode",    mod_rbld_parse_default_returncode, NULL, RSRC_CONF, "Default code that mod_rbld should return with (401, 403, etc...). Defaults to 403\n"),
    AP_INIT_TAKE1("RBLDDefaultErrorDocument", mod_rbld_parse_default_error_doc,  NULL, ACCESS_CONF|RSRC_CONF, "Default error document that mod_rbld can return\n"),
    {NULL}
};

/* Process the request */
static int check_rbld(request_rec *r)
{
    mod_rbld_config_t *conf = (mod_rbld_config_t *)ap_get_module_config(r->server->module_config, &rbld_module);
    mod_rbld_config_t *dconf = (mod_rbld_config_t *)ap_get_module_config(r->per_dir_config, &rbld_module);
    /* make sure that we are enabled.  If we aren't, then we'll pass */
    if (conf->enabled != RBL_ENABLED) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, 0, r, "[mod_rbld.c] Module disabled");

        return DECLINED;
    }

    apr_pool_t *mpool;
    apr_pool_create(&mpool, NULL);

    struct sockaddr_un unix_addr;
    int sd;
    int returncode;
    int reqlength;
    int errdoclength;
    int messagelength;
    char* req = NULL;
    char* errdoc = NULL;
    char* message = NULL;

    /* Set the return code */
    if (dconf->returncode == RBL_UNSET) {
        returncode = conf->returncode;
    } else {
        returncode = dconf->returncode;
    }

    /* Set the custom error document */
    if (dconf->errdocument) {
        errdoclength = (strlen(dconf->errdocument) + 1);
        errdoc = apr_pcalloc(mpool, errdoclength);
        errdoc = apr_pstrdup(mpool, dconf->errdocument);
    } else if (conf->errdocument) {
        errdoclength = (strlen(conf->errdocument) + 1);
        errdoc = apr_pcalloc(mpool, errdoclength);
        errdoc = apr_pstrdup(mpool, conf->errdocument);
    }

    /* Set the message */
    if (dconf->message) {
        messagelength = (strlen(dconf->message) + 1);
        message = apr_pcalloc(mpool, messagelength);
        message = apr_pstrdup(mpool, dconf->message);
    } else if (conf->message) {
        messagelength = (strlen(conf->message) + 1);
        message = apr_pcalloc(mpool, messagelength);
        message = apr_pstrdup(mpool, conf->message);
    }

    /* Create our query
     * Length is (listname + remote_ip + 3)
     * The "3" is for the space, newline, and null terminating character
     */
    if (dconf->querylist) {
        reqlength = (strlen(dconf->querylist) + strlen(r->connection->remote_ip) + 3);
        req = apr_pcalloc(mpool, reqlength);
        apr_snprintf(req, reqlength, "%s %s\n" ,dconf->querylist, r->connection->remote_ip);
    } else {
        reqlength = (strlen(conf->querylist) + strlen(r->connection->remote_ip) + 3);
        req = apr_pcalloc(mpool, reqlength);
        apr_snprintf(req, reqlength, "%s %s\n", conf->querylist, r->connection->remote_ip);
    }

    memset(&unix_addr, 0, sizeof(unix_addr));
    unix_addr.sun_family = AF_UNIX;
    apr_cpystrn(unix_addr.sun_path, conf->sock_path, sizeof unix_addr.sun_path);

    /*
        Check for internal redircts, sub-requests, or possible loops, and let them through.
    */
    if (r->main)
        return DECLINED;
    else if (r->prev)
        return DECLINED;
    else if (r->status == HTTP_FORBIDDEN)
        return DECLINED;

    // Make sure we connect to the socket properly
    if ((sd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "[mod_rbld.c] Unable to create socket, ignoring rbl and loading page.");
        return DECLINED;
    }
    if (connect(sd, (struct sockaddr *)&unix_addr, sizeof(unix_addr)) < 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "[mod_rbld.c] Unable to connect to rbld, ignorning rbl and loading page.");
        return DECLINED;
    }

    // Send request
    if ( write(sd,req,reqlength) < 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "[mod_rbld.c] Unable to communicate with rbld, ignorning rbl and loading page.");
        close(sd);
        return DECLINED;
    }

    /* Debugging crap, please remove me */
    /*ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "[mod_rbld.c] START DEBUG");
    ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "[mod_rbld.c] conf->sock_path:    %s", conf->sock_path);
    ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "[mod_rbld.c] conf->querylist:    %s", conf->querylist);
    ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "[mod_rbld.c] conf->returncode:   %lu", conf->returncode);
    ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "[mod_rbld.c] conf->message:      %s", conf->message);
    ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "[mod_rbld.c] conf->errdocument:  %s", conf->errdocument);
    ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "[mod_rbld.c] dconf->querylist:   %s", dconf->querylist);
    ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "[mod_rbld.c] dconf->returncode:  %lu", dconf->returncode);
    ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "[mod_rbld.c] dconf->message:     %s", dconf->message);
    ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "[mod_rbld.c] dconf->errdocument: %s", dconf->errdocument);
    ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "[mod_rbld.c] END DEBUG");*/

    // Check response
    if ( read(sd,req,1) == 1) {
        ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "[mod_rbld.c] %s is listed in %s", r->connection->remote_ip, conf->querylist);
        close(sd);

        if ((errdoc) && (strlen(errdoc) > 0)) {
            //r->content_type = "text/plain";
            ap_custom_response(r, returncode, errdoc);
            apr_pool_destroy(mpool);
            return returncode;
        }

        if ((message) && (strlen(message) > 0)) {
            r->content_type = "text/plain";
            ap_custom_response(r, returncode, message);
            apr_pool_destroy(mpool);
            return returncode;
        }

        /* 
         * If there is not a custom message or a default message,
         * then we'll just return with the returncode.  This would
         * allow people that already have a custom document for the
         * return code to use their own pages if they want.
        */
        apr_pool_destroy(mpool);
        return returncode;
    }

    /* Not listed, so do nothing */
    close(sd);
    apr_pool_clear(mpool);
    apr_pool_destroy(mpool);
    return DECLINED;

}

static int mod_rbld_init(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                    MODULE_NAME " " MODULE_VERSION " started.");
    ap_add_version_component(p, MODULE_NAME MODULE_VERSION) ;

    return OK;
}

static void mod_rbld_register_hooks(apr_pool_t* pool)
{
    ap_hook_post_config(mod_rbld_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_access_checker(check_rbld, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA rbld_module =
{
    STANDARD20_MODULE_STUFF,
    mod_rbld_create_dir_config,
    mod_rbld_merge_dir_config,
    mod_rbld_create_server_config,
    mod_rbld_merge_server_config,
    mod_rbld_cmds,
    mod_rbld_register_hooks
};
