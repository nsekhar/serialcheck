#include <argp.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <termios.h>
#include <stdarg.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdint.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <linux/serial.h>

struct g_opt {
	char *uart_name;
	unsigned int interval;
	bool once;
};

/* name, key, arg, flags, doc, group */
static struct argp_option options[] = {
	{"interval",	'i', "NUM",  0, "interval in seconds", 0},
	{"device",	'd', "FILE", 0, "serial node device", 0},
	{"once",	'o', 0, 0, "print stats once and exit", 0},
	{NULL, 0, NULL, 0, NULL, 0}
};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct g_opt *go = state->input;
	unsigned long long num;
	char *p;
	error_t ret = 0;

	switch (key) {
	case ARGP_KEY_INIT:
		memset(go, 0, sizeof(*go));
		go->interval = 10;
		go->once = false;
		break;
	case ARGP_KEY_ARG:
		ret =  ARGP_ERR_UNKNOWN;
		break;
	case 'i':
		num = strtoul(arg, &p, 0);
		if (!num || num > UINT_MAX || *p != '\0') {
			printf("Unsupported interval: %s\n", arg);
			ret =  ARGP_ERR_UNKNOWN;
		} else
			go->interval = num;
		break;
	case 'd':
		free(go->uart_name);
		go->uart_name = strdup(arg);
		break;
	case 'o':
		go->once = true;
		break;
	default:
		ret = ARGP_ERR_UNKNOWN;
	}
	return ret;
}

static struct argp argp = {
	.options = options,
	.parser = parse_opt,
	.doc = "uart stats tool",
};

static void dieh(const char *s)
{
	printf("Error: %s. Use --help\n", s);
	exit(1);
}

static void die(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	exit(1);
}

int main(int argc, char *argv[])
{
	struct g_opt opts;
	struct serial_icounter_struct old_counters;
	struct serial_icounter_struct new_counters;
	int fd;
	int ret;

	argp_parse(&argp, argc, argv, 0, NULL, &opts);
	if (!opts.uart_name)
		dieh("Missing uart node");
	if (!opts.interval) {
		printf("Missing interval, assuming 10 seconds");
		opts.interval = 10;
	}

	fd = open(opts.uart_name, O_RDONLY | O_NONBLOCK);
	if (fd < 0)
		die("Failed to open %s: %m\n", opts.uart_name);

	ret = ioctl(fd, TIOCGICOUNT, &old_counters);
	if (ret)
		die("Failed to get counters for %s\n", opts.uart_name);

#define STAT(x) (old_counters.x)
	if (opts.once) {
		printf("cts: %d dsr: %d rng: %d dcd: %d rx: %d tx: %d "
		"frame error %d overuns %d parity: %d break: %d buffer overrun: %d\n",
		STAT(cts), STAT(dsr), STAT(rng), STAT(dcd), STAT(rx),
		STAT(tx), STAT(frame), STAT(overrun), STAT(parity),
		STAT(brk), STAT(buf_overrun));
		goto out;
	}

	while (1) {
		sleep(opts.interval);
		ret = ioctl(fd, TIOCGICOUNT, &new_counters);
		if (!ret) {
#define CNT(x) (new_counters.x - old_counters.x)
			printf("cts: %d dsr: %d rng: %d dcd: %d rx: %d tx: %d "
			"frame error %d overuns %d parity: %d break: %d buffer overrun: %d\n",
			CNT(cts), CNT(dsr), CNT(rng), CNT(dcd), CNT(rx),
			CNT(tx), CNT(frame), CNT(overrun), CNT(parity),
			CNT(brk), CNT(buf_overrun));
#undef CNT
		}
	}

out:
	close(fd);
	return 0;
}
