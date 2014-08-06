#include <argp.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <termios.h>
#include <stdarg.h>
#include <unistd.h>

#define __same_type(a, b)	__builtin_types_compatible_p(typeof(a), typeof(b))
#define BUILD_BUG_ON_ZERO(e)	(sizeof(struct { int:-!!(e); }))
#define __must_be_array(a)	BUILD_BUG_ON_ZERO(__same_type((a), &(a)[0]))
#define ARRAY_SIZE(arr)	(sizeof(arr) / sizeof((arr)[0]) + __must_be_array(arr))

struct g_opt {
	char *uart_name;
	char *file_trans;
	unsigned int baudrate;
};

/* name, key, arg, flags, doc, group */
static struct argp_option options[] = {
	{"baud",	'b', "NUM",  0, "baudrate", 0},
	{"device",	'd', "FILE", 0, "serial node device", 0},
	{"file",	'f', "FILE", 0, "binary file for transfers", 0},
	{"mode",	'm', "NUM",  0, "transfer mode (0 = duplex, 1 = receive, 2 = send)", 0},
	{NULL, 0, NULL, 0, NULL, 0}
};

static error_t parse_baudrate(const char *arg, struct g_opt *go)
{
	unsigned long num;
	char *p;

	num = strtoul(arg, &p, 0);
	if (*p != '\0')
		goto err;

	/* 4M is a sane limit but… */
	if (!num || num > UINT_MAX) {
err:
		printf("Unsupported baudrate: %s\n", arg);
		return ARGP_ERR_UNKNOWN;
	}
	go->baudrate = num;
	return 0;
}

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct g_opt *go = state->input;
	error_t ret = 0;

	switch (key)
	{
	case ARGP_KEY_INIT:
		memset(go, 0, sizeof(*go));
		go->baudrate = 115200;
		break;
	case ARGP_KEY_ARG:
		printf("WTF\n");
		break;
	case 'b':
		ret = parse_baudrate(arg, go);
		break;
	case 'd':
		free(go->uart_name);
		go->uart_name = strdup(arg);
		break;
	case 'f':
		free(go->file_trans);
		go->file_trans = strdup(arg);
		break;
	default:
		ret = ARGP_ERR_UNKNOWN;
	}
	return ret;
}

static struct argp argp = {
	.options = options,
	.parser = parse_opt,
//	.args_doc = "[cfg_file]",
	.doc = "user stress testing tool",
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
}

static char *test_string = "qaywsxedcrfvtgbzhnujmikolp";

int main(int argc, char *argv[])
{
	struct g_opt opts;
	int uart_fd;
	struct termios old_term, new_term;
	int ret;
	ssize_t size;

	argp_parse(&argp, argc, argv, 0, NULL, &opts);
	if (!opts.file_trans)
		dieh("Missing file for transfers");
	if (!opts.uart_name)
		dieh("Missing uart node");

	uart_fd = open(opts.uart_name, O_RDWR);
	if (uart_fd < 0)
		die("Failed to open %s: %m\n", opts.uart_name);
	ret = tcgetattr(uart_fd, &old_term);
	if (ret < 0)
		die("tcgetattr() failed: %m\n");
	memset(&new_term, 0, sizeof(new_term));

	ret = cfsetspeed(&new_term, opts.baudrate);
	if (ret < 0)
		die("cfsetspeed(, %u) failed %m\n", opts.baudrate);

	/* or c_cflag |= BOTHER and c_ospeed for any speed */
	new_term.c_cflag |= CRTSCTS | CS8 | CLOCAL | CREAD;
	new_term.c_iflag = IGNPAR | IGNCR;
	new_term.c_oflag = 0;
	new_term.c_lflag = ICANON;
	ret = tcflush(uart_fd, TCIFLUSH);
	if (ret < 0)
		die("tcflush failed: %m\n");
	ret = tcsetattr(uart_fd, TCSANOW, &new_term);
	if (ret < 0)
		die("tcsetattr failed: %m\n");

	size = write(uart_fd, test_string, sizeof(test_string));
	if (size != sizeof(test_string))
		printf("Wronte only %zd instead %zd\n", size, sizeof(test_string));

	sleep(1);
	ret = tcsetattr(uart_fd, TCSANOW, &old_term);
	if (ret)
		printf("tcsetattr() of old ones failed: %m\n");

	close(uart_fd);
	return 0;
}
