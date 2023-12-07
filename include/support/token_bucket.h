#pragma once

struct token_bucket;
struct token_bucket *token_bucket_new(long long now_ms, long long CBS, long long CIR);
void token_bucket_free(struct token_bucket *t);
int token_bucket_consume(struct token_bucket *t, long long tokens, long long now_ms);