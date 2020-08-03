
struct breakpad_instance;

void breakpad_segv_generate();

struct breakpad_instance *breakpad_init(const char *profile, const char *module, void *logger);
