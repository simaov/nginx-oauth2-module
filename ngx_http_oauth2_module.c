#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <stdio.h>

#define CLIENT_ID       "client_id"  
#define REDIRECT_URI    "redirect_uri"  
#define RESPONSE_TYPE   "response_type"  
#define SCOPE           "scope"  

ngx_module_t ngx_http_oauth2_module;

typedef struct {
    ngx_str_t oauth2_authorization_endpoint; 	// required
    ngx_str_t oauth2_response_type;				// required
    ngx_str_t oauth2_client_id;					// required
    ngx_str_t oauth2_redirect_uri;				// optional
    ngx_str_t oauth2_scope;						// optional
} oauth2_main_conf_t;



static ngx_command_t ngx_http_oauth2_commands[] = {
    {
        ngx_string("oauth2_authorization_endpoint"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(oauth2_main_conf_t, oauth2_authorization_endpoint),
        NULL
    },
    {
        ngx_string("oauth2_response_type"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(oauth2_main_conf_t, oauth2_response_type),
        NULL
    },
    {
        ngx_string("oauth2_client_id"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(oauth2_main_conf_t, oauth2_client_id),
        NULL
    },
    {
        ngx_string("oauth2_redirect_uri"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(oauth2_main_conf_t, oauth2_redirect_uri),
        NULL
    },
    {
        ngx_string("oauth2_scope"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(oauth2_main_conf_t, oauth2_scope),
        NULL
    },
     ngx_null_command
};


/*
	This function runs when the request is processed. 
	It responsibles for coordinating all of the actions in this module. 
	The function accepts the parsed request and operates on it.
*/
static ngx_int_t ngx_http_oauth2_handler(ngx_http_request_t *r) { 
	// if this func has already been invoked...
	if (r->main->internal) {
		// ...go to the next phase of processing
		return NGX_DECLINED; 
	} 
	
	r->main->internal = 1;
	
	oauth2_main_conf_t *conf = ngx_http_get_module_main_conf(r, ngx_http_oauth2_module);

    ngx_str_t *authorization_endpoint 	= &conf->oauth2_authorization_endpoint;
    // ngx_str_t *token_endpoint 			= &conf->oauth2_token_endpoint;
    ngx_str_t *response_type 			= &conf->oauth2_response_type;
    ngx_str_t *client_id 				= &conf->oauth2_client_id;
    ngx_str_t *redirect_uri 			= &conf->oauth2_redirect_uri;
    ngx_str_t *scope 					= &conf->oauth2_scope;
    // ngx_str_t *state 					= &conf->oauth2_state;
    // ngx_str_t *access_type 				= &conf->oauth2_access_type;

    int request_string_len = authorization_endpoint->len 
                                + response_type->len + sizeof(RESPONSE_TYPE) + 1 
                                + client_id->len + sizeof(CLIENT_ID) + 1 
                                + redirect_uri->len + sizeof(REDIRECT_URI) + 1 
                                + scope->len + sizeof(SCOPE) + 1;

    ngx_table_elt_t *h;
	h = ngx_list_push(&r->headers_out.headers);
	h->hash = 1;
	ngx_str_set(&h->key, "Location");
    
    h->value.data = ngx_pnalloc(r->pool, request_string_len);
    h->value.len = ngx_sprintf(h->value.data, "%s?%s=%s&%s=%s&%s=%s&%s=%s", authorization_endpoint->data, CLIENT_ID, client_id->data, RESPONSE_TYPE, 
        response_type->data, REDIRECT_URI, redirect_uri->data, SCOPE, scope->data) - h->value.data;
	
	return NGX_HTTP_MOVED_TEMPORARILY;
}

/*
	The init function is responsible for wiring the handler function to the proper phase in the NGINX life-cycle.
*/
static ngx_int_t ngx_http_oauth2_init(ngx_conf_t *cf) { 
	ngx_http_handler_pt *h;
	ngx_http_core_main_conf_t *cmcf; 

	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module); 
	h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers); 

	if (h == NULL) { 
		return NGX_ERROR; 
	} 

	*h = ngx_http_oauth2_handler; 

	return NGX_OK; 
}

static void* ngx_http_oauth2_create_main_conf(ngx_conf_t *cf) {
    oauth2_main_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(oauth2_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    return conf;
}

static ngx_http_module_t ngx_http_oauth2_module_ctx = { 
	NULL, 								/* preconfiguration */ 
	ngx_http_oauth2_init, 				/* postconfiguration */ 
	ngx_http_oauth2_create_main_conf, 	/* create main configuration */ 
	NULL, 								/* init main configuration */ 
	NULL, 								/* create server configuration */ 
	NULL, 								/* merge server configuration */ 
	NULL, 								/* create location configuration */ 
	NULL 								/* merge location configuration */ 
}; 


ngx_module_t ngx_http_oauth2_module = { 
	NGX_MODULE_V1, 
	&ngx_http_oauth2_module_ctx, 		/* module context */ 
	ngx_http_oauth2_commands, 			/* module directives */ 
	NGX_HTTP_MODULE, 					/* module type */ 
	NULL, 								/* init master */ 
	NULL, 								/* init module */ 
	NULL, 								/* init process */ 
	NULL, 								/* init thread */ 
	NULL, 								/* exit thread */ 
	NULL, 								/* exit process */ 
	NULL,   							/* exit master */ 
	NGX_MODULE_V1_PADDING 
};

