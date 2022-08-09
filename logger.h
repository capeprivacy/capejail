#ifndef LOGGER_H
#define LOGGER_H

void cape_print_usage(void);

void cape_log_error(const char *fmt, ...);

/* returns 0 on success, and non-zero on failure */
int cape_logger_init(const char *program_name);

void cape_logger_shutdown(void);

#endif /* LOGGER_H */
