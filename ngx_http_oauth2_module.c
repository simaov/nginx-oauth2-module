#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <string.h>
#include <curl/curl.h>

ngx_module_t ngx_http_oauth2_module;

typedef struct {
    ngx_str_t oauth2_authorization_endpoint; // required
    ngx_str_t oauth2_token_endpoint;
    ngx_str_t oauth2_response_type;          // required
    ngx_str_t oauth2_client_id;              // required
    ngx_str_t oauth2_client_secret;          // required
    ngx_str_t oauth2_redirect_uri;           // optional
    ngx_str_t oauth2_scope;                  // optional

    ngx_str_t oauth2_authorization_endpoint_request_url;
    ngx_str_t oauth2_token_endpoint_endpoint_post;
} ngx_http_oauth2_loc_conf_t;

typedef struct {
  ngx_str_t string;
  ngx_http_request_t *r;
} string_request_wrapper_t;

static char *ngx_http_oauth2(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_str_t send_request_to_oauth2_token_endpoint(ngx_http_request_t *r, ngx_http_oauth2_loc_conf_t *cf);
static size_t writefunc(void *ptr, size_t size, size_t nmemb, string_request_wrapper_t *wrapper);
static ngx_http_variable_value_t *ngx_get_var_from_query(ngx_str_t *var, ngx_http_request_t *r);
static void ngx_str_concat(u_char *dst, int count, ...);
static void send_curl_post_request(u_char *dst, u_char *post_data, string_request_wrapper_t *wrapper);

static ngx_command_t ngx_http_oauth2_commands[] = {
    {
        ngx_string("oauth2"),
        NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
        ngx_http_oauth2,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },
    {
        ngx_string("oauth2_authorization_endpoint"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_oauth2_loc_conf_t, oauth2_authorization_endpoint),
        NULL
    },
    {
        ngx_string("oauth2_token_endpoint"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_oauth2_loc_conf_t, oauth2_token_endpoint),
        NULL
    },
    {
        ngx_string("oauth2_response_type"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_oauth2_loc_conf_t, oauth2_response_type),
        NULL
    },
    {
        ngx_string("oauth2_client_id"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_oauth2_loc_conf_t, oauth2_client_id),
        NULL
    },
    {
        ngx_string("oauth2_client_secret"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_oauth2_loc_conf_t, oauth2_client_secret),
        NULL
    },
    {
        ngx_string("oauth2_redirect_uri"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_oauth2_loc_conf_t, oauth2_redirect_uri),
        NULL
    },
    {
        ngx_string("oauth2_scope"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_oauth2_loc_conf_t, oauth2_scope),
        NULL
    },
     ngx_null_command
};

static void *ngx_http_oauth2_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_oauth2_loc_conf_t  *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_oauth2_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
    return conf;
}

static char *ngx_http_oauth2_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_oauth2_loc_conf_t *prev = parent;
    ngx_http_oauth2_loc_conf_t *conf = child;

    ngx_conf_merge_str_value(conf->oauth2_authorization_endpoint, prev->oauth2_authorization_endpoint, "");
    ngx_conf_merge_str_value(conf->oauth2_token_endpoint, prev->oauth2_token_endpoint, "");
    ngx_conf_merge_str_value(conf->oauth2_response_type, prev->oauth2_response_type, "");
    ngx_conf_merge_str_value(conf->oauth2_client_id, prev->oauth2_client_id, "");
    ngx_conf_merge_str_value(conf->oauth2_client_secret, prev->oauth2_client_secret, "");
    ngx_conf_merge_str_value(conf->oauth2_redirect_uri, prev->oauth2_redirect_uri, "");
    ngx_conf_merge_str_value(conf->oauth2_scope, prev->oauth2_scope, "");
    
    ngx_str_t response_type = ngx_string("response_type=");
    ngx_str_t client_id = ngx_string("client_id=");
    ngx_str_t redirect_uri = ngx_string("redirect_uri=");
    ngx_str_t scope = ngx_string("scope=");

    int url_len = conf->oauth2_authorization_endpoint.len 
                + conf->oauth2_response_type.len + response_type.len 
                + conf->oauth2_client_id.len + client_id.len 
                + conf->oauth2_redirect_uri.len + redirect_uri.len 
                + conf->oauth2_scope.len + scope.len;
    
    conf->oauth2_authorization_endpoint_request_url.data = ngx_pnalloc(cf->pool, url_len + 4);
    if (conf->oauth2_authorization_endpoint_request_url.data == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->oauth2_authorization_endpoint_request_url.len = ngx_sprintf(conf->oauth2_authorization_endpoint_request_url.data, "%s?%s%s&%s%s&%s%s&%s%s",
                conf->oauth2_authorization_endpoint.data, client_id.data, conf->oauth2_client_id.data, response_type.data, 
                conf->oauth2_response_type.data, redirect_uri.data, conf->oauth2_redirect_uri.data, scope.data, conf->oauth2_scope.data) - conf->oauth2_authorization_endpoint_request_url.data;

    ngx_str_t client_secret = ngx_string("client_secret=");
    
    int post_len = + conf->oauth2_client_id.len + client_id.len
                + conf->oauth2_client_secret.len + client_secret.len 
                + conf->oauth2_redirect_uri.len + redirect_uri.len;
    
    conf->oauth2_token_endpoint_endpoint_post.data = ngx_pnalloc(cf->pool, post_len + 32);
    if (conf->oauth2_token_endpoint_endpoint_post.data == NULL) {
        return NGX_CONF_ERROR;
    }         
    conf->oauth2_token_endpoint_endpoint_post.len = ngx_sprintf(conf->oauth2_token_endpoint_endpoint_post.data, "%s%s&%s%s&%s%s&grant_type=authorization_code",
                client_id.data, conf->oauth2_client_id.data, client_secret.data, conf->oauth2_client_secret.data,
                redirect_uri.data, conf->oauth2_redirect_uri.data) - conf->oauth2_token_endpoint_endpoint_post.data;

    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_oauth2_handler(ngx_http_request_t *r) { 
    if (r->main->internal) {
        return NGX_DECLINED; 
    }

    r->main->internal = 1;

    ngx_http_oauth2_loc_conf_t  *config = ngx_http_get_module_loc_conf(r, ngx_http_oauth2_module);

    ngx_str_t http = ngx_string("http://");

    char *url = ngx_pnalloc(r->pool, config->oauth2_redirect_uri.len);
    strcpy(url, (char *) http.data);
    strcat(url, (char *) r->headers_in.host->value.data);
    strncat(url, (char *) r->uri.data, config->oauth2_redirect_uri.len - (http.len + r->headers_in.host->value.len));

    if (!ngx_strcmp(config->oauth2_redirect_uri.data, (u_char *) url)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "redirect: %s", r->uri.data);
        ngx_str_t response = send_request_to_oauth2_token_endpoint(r, config);   
        if (response.len == 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "token was not received");
        }    

    } else {
        if (r->headers_in.authorization == NULL) {
            ngx_table_elt_t *h;
            h = ngx_list_push(&r->headers_out.headers);
            h->hash = 1;
            ngx_str_set(&h->key, "Location");
            
            h->value.data = config->oauth2_authorization_endpoint_request_url.data;
            h->value.len = config->oauth2_authorization_endpoint_request_url.len;

            return NGX_HTTP_MOVED_TEMPORARILY;
        }
    }
    return NGX_DECLINED;
}

static char *ngx_http_oauth2(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) { 
    ngx_http_core_loc_conf_t  *clcf;
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_oauth2_handler;
    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_oauth2_init_module(ngx_cycle_t *cycle) {
    curl_global_init(CURL_GLOBAL_ALL);
    return NGX_OK;
}

static void ngx_http_oauth2_exit_master(ngx_cycle_t *cycle) {
    curl_global_cleanup();
}

static ngx_http_module_t ngx_http_oauth2_module_ctx = { 
    NULL,                               /* preconfiguration */ 
    NULL,               /* postconfiguration */ 
    NULL,   /* create main configuration */ 
    NULL,                               /* init main configuration */ 
    NULL,                               /* create server configuration */ 
    NULL,                               /* merge server configuration */ 
    ngx_http_oauth2_create_loc_conf,                               /* create location configuration */ 
    ngx_http_oauth2_merge_loc_conf                                /* merge location configuration */ 
}; 

ngx_module_t ngx_http_oauth2_module = { 
    NGX_MODULE_V1, 
    &ngx_http_oauth2_module_ctx,   /* module context */ 
    ngx_http_oauth2_commands,      /* module directives */ 
    NGX_HTTP_MODULE,               /* module type */ 
    NULL,                          /* init master */ 
    ngx_http_oauth2_init_module,                          /* init module */ 
    NULL,                          /* init process */ 
    NULL,                          /* init thread */ 
    NULL,                          /* exit thread */ 
    NULL,                          /* exit process */ 
    &ngx_http_oauth2_exit_master,                          /* exit master */ 
    NGX_MODULE_V1_PADDING 
};

static ngx_str_t send_request_to_oauth2_token_endpoint(ngx_http_request_t *r, ngx_http_oauth2_loc_conf_t *cf) {
    
    ngx_str_t s = ngx_string("code");
    ngx_http_variable_value_t *data;
    data = ngx_get_var_from_query(&s, r);
    
    ngx_str_t str = ngx_string("");

    if (data != NULL && data->not_found != 1) {
        int len = data->len;
        u_char buf[len + 1];
        ngx_memcpy(buf, data->data, len);
        buf[len] = '\0';
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "===> buf: %s", buf);

        ngx_str_t code_str = ngx_string("&code=");
        ngx_str_t buf_str = ngx_string(buf);
        int post_len = cf->oauth2_token_endpoint_endpoint_post.len + code_str.len + buf_str.len;
        
        u_char post[post_len];
        ngx_str_concat(post, 3, &cf->oauth2_token_endpoint_endpoint_post, &code_str, &buf_str);
        string_request_wrapper_t wrapper = {str, r};
        send_curl_post_request(cf->oauth2_token_endpoint.data, post, &wrapper);
    
        return wrapper.string;
    }

    return str;
}

static ngx_http_variable_value_t *ngx_get_var_from_query(ngx_str_t *var, ngx_http_request_t *r) {
    int arg_param_len = var->len + 4 + 1;
    char arg_param_buf[arg_param_len];
    strcpy(arg_param_buf, "arg_");
    strcat(arg_param_buf, (char *) var->data);
    arg_param_buf[arg_param_len] = '\0';

    ngx_str_t argument = ngx_string(arg_param_buf);
    ngx_uint_t id_key = ngx_hash_key(argument.data, argument.len);

    ngx_http_variable_value_t *data;
    data = ngx_http_get_variable(r, &argument, id_key);
    return data;
}

static void ngx_str_concat(u_char *dst, int count, ...) {
    va_list ap;
    va_start(ap, count);         /* Initialize the argument list. */

    int i;
    ngx_str_t *s;
    int shift = 0;
    for (i = 0; i < count; i++) {
        s = va_arg(ap, ngx_str_t *);    /* Get the next argument value. */
        ngx_memcpy(dst + shift, s->data, s->len);
        shift = shift + s->len; 
    }

    va_end(ap);                  /* Clean up. */
}

static size_t writefunc(void *ptr, size_t size, size_t nmemb, string_request_wrapper_t *wrapper) {
  size_t new_len = wrapper->string.len + size*nmemb;
  u_char *d = ngx_pnalloc(wrapper->r->pool, new_len + 1);
  if (d == NULL) {
    ngx_log_error(NGX_LOG_ERR, wrapper->r->connection->log, 0, "wrapper->string.data is NULL");
    return 0;
  }
  ngx_memcpy(d, wrapper->string.data, wrapper->string.len);
  ngx_memcpy(d + wrapper->string.len, ptr, size * nmemb);
  d[new_len] = '\0';
  wrapper->string.data = d;
  wrapper->string.len = new_len;

  return size*nmemb;
}

static void send_curl_post_request(u_char *dst, u_char *post_data, string_request_wrapper_t *wrapper) {
    CURL *curl;
    CURLcode res;
         
    curl = curl_easy_init();
    if(curl) {
        
        curl_easy_setopt(curl, CURLOPT_URL, dst);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, wrapper);
                
        res = curl_easy_perform(curl);
        if(res != CURLE_OK) {
            ngx_log_error(NGX_LOG_ERR, wrapper->r->connection->log, 0, "===> CURL NOT OK!");

        }   
        ngx_log_error(NGX_LOG_ERR, wrapper->r->connection->log, 0, "DATA: %s, LEN: %d", wrapper->string.data, wrapper->string.len); 
        curl_easy_cleanup(curl);
    }
}

// https://www.googleapis.com/oauth2/v3/userinfo?alt=json&access_token=ya29.UQFpwFrksQY-evJ9O9ZXLEuW_TJq4O1zAVMKzNV8K-x6F2_05pbit3gHjjBr-7OLX7jQL6VD6cU1NQ

