#include "token_bucket.h"

#include <stdlib.h>

#ifndef MIN
#define MIN(a, b) (((a) > (b)) ? (b) : (a))
#endif

#define DEFALUT_REFILL_INTERVAL_MS 10

struct token_bucket {
    long long CBS;              //
    long long tokens;                // available tokens
    long long CIR;  // fill tokens per time interval
    long long last_refill_timestamp_ms;      //
};

struct token_bucket *token_bucket_new(long long now_ms, long long CBS, long long CIR) 
{
    struct token_bucket *tb = (struct token_bucket *)calloc(sizeof(struct token_bucket),1);
    tb->CBS = CBS;
    tb->tokens = CBS;  // initially full
    tb->CIR = CIR;
    tb->last_refill_timestamp_ms = now_ms;
    return tb;
}

void token_bucket_free(struct token_bucket *t)
{
    if(t)free(t);
}

int token_bucket_consume(struct token_bucket *t, long long tokens, long long now_ms) 
{
    if (t == NULL || tokens <= 0 || now_ms <= 0)return 0;
	if (tokens > t->CBS)return 0;
	if (now_ms < t->last_refill_timestamp_ms) return 0;

	//refill
	long long delta_ms = now_ms - t->last_refill_timestamp_ms;
    long long refill = (delta_ms * t->CIR)/1000;
	if(delta_ms > DEFALUT_REFILL_INTERVAL_MS && refill > 0)
	{
		
		t->tokens += MIN(refill, t->CBS);
		t->last_refill_timestamp_ms = now_ms;
	}

	//consume
    if (t->tokens >= tokens) 
	{
        t->tokens -= tokens;
        return 1;  // success
    }
    return 0;  // failure
}