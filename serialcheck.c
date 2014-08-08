#include <argp.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <termios.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdint.h>
#include <poll.h>

#define __same_type(a, b)	__builtin_types_compatible_p(typeof(a), typeof(b))
#define BUILD_BUG_ON_ZERO(e)	(sizeof(struct { int:-!!(e); }))
#define __must_be_array(a)	BUILD_BUG_ON_ZERO(__same_type((a), &(a)[0]))
#define ARRAY_SIZE(arr)	(sizeof(arr) / sizeof((arr)[0]) + __must_be_array(arr))


#define min(x, y) ({			\
		typeof(x) _min1 = (x);	\
		typeof(y) _min2 = (y);	\
		(void) (&_min1 == &_min2);	\
		_min1 < _min2 ? _min1 : _min2;	})

static const char hex_asc[] = "0123456789abcdef";
#define hex_asc_lo(x)	hex_asc[((x) & 0x0f)]
#define hex_asc_hi(x)	hex_asc[((x) & 0xf0) >> 4]

struct g_opt {
	char *uart_name;
	char *file_trans;
	unsigned int baudrate;
#define MODE_DUPLEX	(MODE_TX_ONLY | MODE_RX_ONLY)
#define MODE_TX_ONLY	(1 << 0)
#define MODE_RX_ONLY	(1 << 1)
	unsigned int mode;
	unsigned int loops;
	unsigned char do_termios;
	unsigned char *cmp_buff;
};

/* name, key, arg, flags, doc, group */
static struct argp_option options[] = {
	{"baud",	'b', "NUM",  0, "baudrate", 0},
	{"device",	'd', "FILE", 0, "serial node device", 0},
	{"file",	'f', "FILE", 0, "binary file for transfers", 0},
	{"mode",	'm', "M",    0, "transfer mode (d = duplex, t = send r = receive)", 0},
	{"loops",	'l', "NUM",  0, "loops to perform (0 => wait fot CTRL-C", 0},
	{"no-termios",	'n', NULL,   0, "No termios change (baud rate etc. remains unchanged)", 0},
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
		go->baudrate = 115200;
		go->loops = UINT_MAX;
		go->do_termios = 1;
		break;
	case ARGP_KEY_ARG:
		ret =  ARGP_ERR_UNKNOWN;
		break;
	case 'b':
		num = strtoul(arg, &p, 0);
		if (!num || num > UINT_MAX || *p != '\0') {
			printf("Unsupported baudrate: %s\n", arg);
			ret =  ARGP_ERR_UNKNOWN;
		} else
			go->baudrate = num;
		break;
	case 'd':
		free(go->uart_name);
		go->uart_name = strdup(arg);
		break;
	case 'f':
		free(go->file_trans);
		go->file_trans = strdup(arg);
		break;
	case 'm':
		if (arg[0] == 'r')
			go->mode = MODE_RX_ONLY;
		else if (arg[0] == 't')
			go->mode = MODE_TX_ONLY;
		else if (arg[0] == 'd')
			go->mode = MODE_DUPLEX;
		else {
			printf("Unsuported mode: %s\n", arg);
			ret = ARGP_ERR_UNKNOWN;
		}
		break;
	case 'n':
		go->do_termios = 0;
		break;
	case 'l':
		num = strtoull(arg, &p, 0);
		if (num >= UINT_MAX || *p != '\0') {
			printf("Unsuported loop count: %s\n", arg);
			ret = ARGP_ERR_UNKNOWN;
		} else
			go->loops = num;
		break;
	default:
		ret = ARGP_ERR_UNKNOWN;
	}
	return ret;
}

static struct argp argp = {
	.options = options,
	.parser = parse_opt,
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
	exit(1);
}

static int vscnprintf(char *buf, size_t size, const char *fmt, va_list args)
{
	int i;

	i = vsnprintf(buf, size, fmt, args);

	if (i < size)
		return i;
	if (size != 0)
		return size - 1;
	return 0;
}

static int scnprintf(char *buf, size_t size, const char *fmt, ...)
{
	va_list args;
	int i;

	va_start(args, fmt);
	i = vscnprintf(buf, size, fmt, args);
	va_end(args);

	return i;
}


static void hex_dump_to_buffer(const void *buf, size_t len, int rowsize,
		int groupsize, char *linebuf, size_t linebuflen,
		int ascii)
{
	const uint8_t *ptr = buf;
	uint8_t ch;
	int j, lx = 0;
	int ascii_column;

	if (rowsize != 16 && rowsize != 32)
		rowsize = 16;

	if (!len)
		goto nil;
	if (len > rowsize)              /* limit to one line at a time */
		len = rowsize;
	if ((len % groupsize) != 0)     /* no mixed size output */
		groupsize = 1;

	switch (groupsize) {
	case 8: {
		const uint64_t *ptr8 = buf;
		int ngroups = len / groupsize;

		for (j = 0; j < ngroups; j++)
			lx += scnprintf(linebuf + lx, linebuflen - lx,
					"%s%16.16llx", j ? " " : "",
					(unsigned long long)*(ptr8 + j));
		ascii_column = 17 * ngroups + 2;
		break;
		}

	case 4: {
		const uint32_t *ptr4 = buf;
		int ngroups = len / groupsize;

		for (j = 0; j < ngroups; j++)
			lx += scnprintf(linebuf + lx, linebuflen - lx,
					"%s%8.8x", j ? " " : "", *(ptr4 + j));
		ascii_column = 9 * ngroups + 2;
		break;
		}

	case 2: {
		const uint16_t *ptr2 = buf;
		int ngroups = len / groupsize;

		for (j = 0; j < ngroups; j++)
			lx += scnprintf(linebuf + lx, linebuflen - lx,
					"%s%4.4x", j ? " " : "", *(ptr2 + j));
		ascii_column = 5 * ngroups + 2;
		break;
		}

	default:
		for (j = 0; (j < len) && (lx + 3) <= linebuflen; j++) {
			ch = ptr[j];
			linebuf[lx++] = hex_asc_hi(ch);
			linebuf[lx++] = hex_asc_lo(ch);
			linebuf[lx++] = ' ';
			if (j == 7)
				linebuf[lx++] = ' ';
		}
		if (j)
			lx--;

		ascii_column = 3 * rowsize + 2 + 2;
		break;
	}
	if (!ascii)
		goto nil;

	while (lx < (linebuflen - 1) && lx < (ascii_column - 1))
		linebuf[lx++] = ' ';
	for (j = 0; (j < len) && (lx + 2) < linebuflen; j++) {
		ch = ptr[j];
		linebuf[lx++] = (isascii(ch) && isprint(ch)) ? ch : '.';
	}
nil:
	linebuf[lx++] = '\0';
}

static void print_hex_dump(const void *buf, size_t len, int offset)
{
	const uint8_t *ptr = buf;
	int i, linelen, remaining = len;
	unsigned char linebuf[32 * 3 + 2 + 32 + 2 + 1];
	int rowsize = 16;
	int groupsize = 1;

	if (rowsize != 16 && rowsize != 32)
		rowsize = 16;

	for (i = 0; i < len; i += rowsize) {
		linelen = min(remaining, rowsize);
		remaining -= rowsize;

		hex_dump_to_buffer(ptr + i, linelen, rowsize, groupsize,
				linebuf, sizeof(linebuf), 1);

		printf("%.8x: %s\n", i + offset, linebuf);
	}
}

static void stress_test_uart_once(struct g_opt *opts, int fd, unsigned char *data,
		off_t data_len)
{
	unsigned char *cmp_data = opts->cmp_buff;
	ssize_t size;
	int wait_rx;
	int wait_tx;
	ssize_t progress_rx = 0;
	ssize_t progress_tx = 0;
	unsigned int reads = 0;
	unsigned int writes = 0;

	do {
		struct pollfd pfd = {
			.fd = fd,
		};
		int ret;

		if (opts->mode & MODE_RX_ONLY && progress_rx < data_len) {
			pfd.events |= POLLIN;
			wait_rx = 1;
		} else {
			wait_rx = 0;
		}

		if (opts->mode & MODE_TX_ONLY && progress_tx < data_len) {
			pfd.events |= POLLOUT;
			wait_tx = 1;
		} else {
			wait_tx = 0;
		}

		ret = poll(&pfd, 1, 10 * 1000);
		if (ret == 0) {
			printf("timeout, RX/TX: %zd/%zd\n", progress_rx, progress_tx);
			break;
		}
		if (ret < 0)
			die("poll() failed: %m\n");

		if (pfd.revents & POLLIN) {

			size = read(fd, cmp_data + progress_rx, data_len - progress_rx);
			if (size < 0)
				die("Read failed: %m\n");
			reads++;
			progress_rx += size;
			if (progress_rx >= data_len)
				wait_rx = 0;
		}

		if (pfd.revents & POLLOUT) {

			size = write(fd, data + progress_tx, data_len - progress_tx);
			if (size < 0)
				die("write failed\n");
			writes++;
			progress_tx += size;
			if (progress_tx >= data_len)
				wait_tx = 0;
		}
	} while (wait_rx || wait_tx);

	printf("Needed %u reads %u writes ", reads, writes);
	if (opts->mode & MODE_RX_ONLY && memcmp(data, cmp_data, data_len)) {
		unsigned int i;
		int found = 0;
		unsigned int min_pos;
		unsigned int max_pos;

		for (i = 0; i < data_len && !found; i++) {
			if (data[i] != cmp_data[i]) {
				found = 1;
				break;
			}
		}

		if (!found)
			die("memcmp() didn't match but manual cmp did\n");

		max_pos = (i & ~0xfULL) + 16 * 3;
		if (max_pos > data_len)
			max_pos = data_len;

		min_pos = i & ~0xfULL;
		if (min_pos > 16 * 3)
			min_pos -= 16 * 3;
		else
			min_pos = 0;

		printf("Oh oh, inconsistency at pos %d (0x%x).\n", i, i);

		printf("\nOriginal sample:\n");
		print_hex_dump(data + min_pos, max_pos - min_pos, min_pos);

		printf("\nReceived sample:\n");
		print_hex_dump(cmp_data + min_pos, max_pos - min_pos, min_pos);
		exit(2);
	}
}

static void stress_test_uart(struct g_opt *opts, int fd, unsigned char *data,
		off_t data_len)
{
	unsigned int loops = 0;

	opts->cmp_buff = malloc(data_len);
	if (!opts->cmp_buff)
		die("Failed to malloc(%d): %m\n", data_len);
	memset(opts->cmp_buff, 0, data_len);

	do {
		stress_test_uart_once(opts, fd, data, data_len);
		memset(opts->cmp_buff, 0, data_len);
		printf("loops %u / %u\n", loops + 1, opts->loops);
	} while (++loops < opts->loops);
	free(opts->cmp_buff);
}

struct term_params {
	struct termios *term;
	int fd;
};

static void set_old_term(int status, void *arg)
{
	struct term_params *tparams = arg;
	int ret;

	if (!status)
		return;
	ret = fcntl(tparams->fd, F_SETFL, O_NONBLOCK);
	if (ret)
		return;
	tcsetattr(tparams->fd, TCSAFLUSH, tparams->term);
}

int main(int argc, char *argv[])
{
	struct g_opt opts;
	struct termios old_term, new_term;
	struct term_params term_params = {
		.term = &old_term,
	};
	struct stat data_stat;
	int fd;
	int ret;
	unsigned char *data;
	off_t data_len;

	argp_parse(&argp, argc, argv, 0, NULL, &opts);
	if (!opts.file_trans)
		dieh("Missing file for transfers");
	if (!opts.uart_name)
		dieh("Missing uart node");
	if (!opts.mode)
		dieh("Missing mode");

	fd = open(opts.file_trans, O_RDONLY);
	if (fd < 0)
		die("Failed to open %s: %m\n", opts.file_trans);

	ret = fstat(fd, &data_stat);
	if (ret < 0)
		die("stat on %s failed: %m\n", opts.file_trans);

	data_len = data_stat.st_size;

	data = mmap(NULL, data_len, PROT_READ, MAP_SHARED | MAP_LOCKED |
			MAP_POPULATE, fd, 0);
	if (data == MAP_FAILED)
		die("mmap() of %s size %d failed: %m\n", opts.file_trans,
				data_len);
	close(fd);

	fd = open(opts.uart_name, O_RDWR | O_NONBLOCK);
	if (fd < 0)
		die("Failed to open %s: %m\n", opts.uart_name);
	term_params.fd = fd;

	ret = tcgetattr(fd, &old_term);
	if (ret < 0)
		die("tcgetattr() failed: %m\n");

	new_term = old_term;

	/* or c_cflag |= BOTHER and c_ospeed for any speed */
	ret = cfsetspeed(&new_term, opts.baudrate);
	if (ret < 0)
		die("cfsetspeed(, %u) failed %m\n", opts.baudrate);
	cfmakeraw(&new_term);
	new_term.c_cflag |= CREAD;
	new_term.c_iflag |= CRTSCTS;
	new_term.c_cc[VMIN] = 64;
	new_term.c_cc[VTIME] = 8;

	on_exit(set_old_term, &term_params);

	ret = tcsetattr(fd, TCSANOW, &new_term);
	if (ret < 0)
		die("tcsetattr failed: %m\n");

	if (opts.do_termios) {
		ret = tcflush(fd, TCIFLUSH);
		if (ret < 0)
			die("tcflush failed: %m\n");
	}

	ret = fcntl(fd, F_SETFL, 0);
	if (ret)
		printf("Failed to remove nonblock mode\n");

	stress_test_uart(&opts, fd, data, data_len);

	ret = tcsetattr(fd, TCSAFLUSH, &old_term);
	if (ret)
		printf("tcsetattr() of old ones failed: %m\n");

	close(fd);
	return 0;
}
