#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

ngx_module_t ngx_http_oauth2_module;

/*
	ngx_http_impression_handler_handler is the function that runs when the request is processed. 
	It is the function responsible for coordinating all of the actions in this module. 
	The function accepts the parsed request and operates on it.
*/
static ngx_int_t ngx_http_oauth2_handler(ngx_http_request_t *r) { 
	// if this func has already been invoked...
	if (r->main->internal) {
		// ...go to the next phase of processing
		return NGX_DECLINED; 
	} 
	r->main->internal = 1;
	return NGX_DECLINED; 
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

static ngx_http_module_t ngx_http_oauth2_module_ctx = { 
	NULL, 											/* preconfiguration */ 
	ngx_http_oauth2_init, 				/* postconfiguration */ 
	NULL, 								/* create main configuration */ 
	NULL, 											/* init main configuration */ 
	NULL, 											/* create server configuration */ 
	NULL, 											/* merge server configuration */ 
	NULL, 											/* create location configuration */ 
	NULL 											/* merge location configuration */ 
}; 


ngx_module_t ngx_http_oauth2_module = { 
	NGX_MODULE_V1, 
	&ngx_http_oauth2_module_ctx, 	/* module context */ 
	NULL, 		/* module directives */ 
	NGX_HTTP_MODULE, 							/* module type */ 
	NULL, 										/* init master */ 
	NULL, 	/* init module */ 
	NULL, 										/* init process */ 
	NULL, 										/* init thread */ 
	NULL, 										/* exit thread */ 
	NULL, 										/* exit process */ 
	NULL,   /* exit master */ 
	NGX_MODULE_V1_PADDING 
};
