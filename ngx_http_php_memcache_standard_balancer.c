

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct
{
    struct sockaddr                              *sockaddr;
    socklen_t                                     socklen;
    ngx_str_t                                     name;
} ngx_http_memcache_node;

typedef struct
{
    ngx_http_memcache_node                       *buckets;
    ngx_int_t                                     num_buckets;
    ngx_array_t                                  *key_vars_lengths;
    ngx_array_t                                  *key_vars_values;
} ngx_http_memcache_node_hash_upstream_context;

typedef struct {
    ngx_http_memcache_node_hash_upstream_context          *upstream_context;

    u_char                                        tries;
    ngx_uint_t                                    point;

    ngx_event_get_peer_pt                         get_rr_peer;
} ngx_http_php_memcache_standard_balancer_peer_data_t;

static char * ngx_http_php_memcache_standard_balancer_hash_key(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
ngx_int_t ngx_http_php_memcache_standard_balancer_init(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_php_memcache_standard_balancer_init_peer(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_php_memcache_standard_balancer_get_peer(ngx_peer_connection_t *pc, void *data);
void ngx_http_php_memcache_standard_balancer_free_peer(ngx_peer_connection_t *pc, void *data, ngx_uint_t state);

static ngx_array_t * ngx_http_php_memcache_hash_key_vars_lengths;
static ngx_array_t * ngx_http_php_memcache_hash_key_vars_values;

static ngx_command_t  ngx_http_php_memcache_standard_balancer_commands[] = { 

    { ngx_string("hash_key"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
      ngx_http_php_memcache_standard_balancer_hash_key,
      0,
      0,
      NULL },

      ngx_null_command
};

static ngx_http_module_t  ngx_http_php_memcache_standard_balancer_module_ctx = { 
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};

ngx_module_t  ngx_http_php_memcache_standard_balancer_module = {
    NGX_MODULE_V1,
    &ngx_http_php_memcache_standard_balancer_module_ctx, /* module context */
    ngx_http_php_memcache_standard_balancer_commands,    /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static char *
ngx_http_php_memcache_standard_balancer_hash_key(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_upstream_srv_conf_t *uscf;
    ngx_http_script_compile_t sc;
    ngx_str_t *value;
    ngx_http_memcache_node_hash_upstream_context     *upstream_context;
    
    value = cf->args->elts;
    
    ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));
    
    upstream_context = ngx_pcalloc(cf->pool, sizeof(ngx_http_memcache_node_hash_upstream_context));
    upstream_context->key_vars_lengths = NULL;
    upstream_context->key_vars_values = NULL;
    
    sc.cf = cf;
    sc.source = &value[1];
    sc.lengths = &upstream_context->key_vars_lengths;
    sc.values = &upstream_context->key_vars_values;
    sc.complete_lengths = 1;
    sc.complete_values = 1;
    
    if (ngx_http_script_compile(&sc) != NGX_OK) {
        return NGX_CONF_ERROR;
    }
    
    uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);
    
    uscf->peer.init_upstream = ngx_http_php_memcache_standard_balancer_init;
    uscf->peer.data = upstream_context;
    
    uscf->flags = NGX_HTTP_UPSTREAM_CREATE | NGX_HTTP_UPSTREAM_WEIGHT;
    
    return NGX_CONF_OK;
}

ngx_int_t
ngx_http_php_memcache_standard_balancer_init(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *us)
{
    ngx_http_memcache_node_hash_upstream_context     *upstream_context;
    ngx_http_upstream_server_t              *server;
    ngx_uint_t                               i, j;
    
    server = us->servers->elts;
    
    for (j = 0, i = 0; i < us->servers->nelts; i++) {
        j += server[i].weight;
    }
    
    upstream_context = us->peer.data;

    upstream_context->buckets = ngx_pcalloc(cf->pool, sizeof(ngx_http_memcache_node) * j);
    
    upstream_context->num_buckets = 0;
    
    for (i = 0; i < us->servers->nelts; i++) {
        for (j = 0; j < server[i].weight; j++) {
            upstream_context->buckets[i].sockaddr = server[i].addrs[0].sockaddr;
            upstream_context->buckets[i].socklen = server[i].addrs[0].socklen;
            upstream_context->buckets[i].name.data = ngx_pcalloc(cf->pool, sizeof(u_char) * server[i].addrs[0].name.len + 1);
            ngx_cpystrn(upstream_context->buckets[i].name.data, server[i].addrs[0].name.data, server[i].addrs[0].name.len + 1);
            upstream_context->buckets[i].name.len = server[i].addrs[0].name.len;
            upstream_context->num_buckets++;
        }
    }
    
    us->peer.init = ngx_http_php_memcache_standard_balancer_init_peer;
    
    return NGX_OK;
}

static ngx_int_t
ngx_http_php_memcache_standard_balancer_init_peer(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *us)
{
    ngx_str_t evaluated_key_to_hash;
    ngx_http_php_memcache_standard_balancer_peer_data_t *pmsbd;
    
    pmsbd = ngx_pcalloc(r->pool, sizeof(ngx_http_php_memcache_standard_balancer_peer_data_t));
    if (pmsbd == NULL) {
        return NGX_ERROR;
    }
    pmsbd->upstream_context = us->peer.data;
    r->upstream->peer.data = us->peer.data;
    
    if (ngx_http_script_run(r, &evaluated_key_to_hash, pmsbd->upstream_context->key_vars_lengths->elts, 0, pmsbd->upstream_context->key_vars_values->elts) == NULL) {
        return NGX_ERROR;
    }
    pmsbd->point = (ngx_crc32_long(evaluated_key_to_hash.data, evaluated_key_to_hash.len) >> 16) & 0x7fff;
    
    printf("the key is %s and it got %u points\n", evaluated_key_to_hash.data, (unsigned int)pmsbd->point);
    r->upstream->peer.free = ngx_http_php_memcache_standard_balancer_free_peer;
    r->upstream->peer.get = ngx_http_php_memcache_standard_balancer_get_peer;
    r->upstream->peer.data = pmsbd;
    
    return NGX_OK;
}

static ngx_int_t
ngx_http_php_memcache_standard_balancer_get_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_php_memcache_standard_balancer_peer_data_t *pmsbd = data;
    
    pc->sockaddr = pmsbd->upstream_context->buckets[pmsbd->point % pmsbd->upstream_context->num_buckets].sockaddr;
    pc->socklen = pmsbd->upstream_context->buckets[pmsbd->point % pmsbd->upstream_context->num_buckets].socklen;
    pc->name = &pmsbd->upstream_context->buckets[pmsbd->point % pmsbd->upstream_context->num_buckets].name;
    
    printf("the winner is bucket number %u with the name %s\n", (unsigned int)(pmsbd->point % pmsbd->upstream_context->num_buckets), pc->name->data);
    return NGX_OK;
}

void ngx_http_php_memcache_standard_balancer_free_peer(ngx_peer_connection_t *pc, void *data, ngx_uint_t state) 
{
    pc->tries = 0;
}
