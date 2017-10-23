#include "GDBDebugClient.h"
#include <ida.hpp>
#include <dbg.hpp>

const char* register_classes[] =
{
	"General registers",
	"Floating point registers",
	/*"Velocity Engine/VMX/AltiVec", // 128-bit Vector Registers*/
	NULL
};

static const char *const CReg[] =
{
	"cr7",
	"cr7",
	"cr7",
	"cr7",
	"cr6",
	"cr6",
	"cr6",
	"cr6",
	"cr5",
	"cr5",
	"cr5",
	"cr5",
	"cr4",
	"cr4",
	"cr4",
	"cr4",
	"cr3",
	"cr3",
	"cr3",
	"cr3",
	"cr2",
	"cr2",
	"cr2",
	"cr2",
	"cr1",
	"cr1",
	"cr1",
	"cr1",
	"cr0",
	"cr0",
	"cr0",
	"cr0",
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
};

static const char *const vmx_format[] =
{
	"VMX 128 bit",
};

//--------------------------------------------------------------------------
register_info_t registers[] =
{
	{ "r0",     REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
	{ "r1",     REGISTER_ADDRESS | REGISTER_SP, RC_GENERAL,  dt_qword,  NULL,   0 },
	{ "r2",     REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
	{ "r3",     REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
	{ "r4",     REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
	{ "r5",     REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
	{ "r6",     REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
	{ "r7",     REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
	{ "r8",     REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
	{ "r9",     REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
	{ "r10",    REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
	{ "r11",    REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
	{ "r12",    REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
	{ "r13",    REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
	{ "r14",    REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
	{ "r15",    REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
	{ "r16",    REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
	{ "r17",    REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
	{ "r18",    REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
	{ "r19",    REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
	{ "r20",    REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
	{ "r21",    REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
	{ "r22",    REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
	{ "r23",    REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
	{ "r24",    REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
	{ "r25",    REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
	{ "r26",    REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
	{ "r27",    REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
	{ "r28",    REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
	{ "r29",    REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
	{ "r30",    REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
	{ "r31",    REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },

	{ "PC",     REGISTER_ADDRESS | REGISTER_IP,  RC_GENERAL,  dt_qword,  NULL,   0 },
	{ "MSR",    NULL,                            RC_GENERAL,  dt_qword,  NULL,   0 },
	{ "CR",     NULL,							 RC_GENERAL,  dt_dword,  CReg,   0xFFFFFFFF },
	{ "LR",     REGISTER_ADDRESS,                RC_GENERAL,  dt_qword,  NULL,   0 },
	{ "CTR",    REGISTER_ADDRESS,                RC_GENERAL,  dt_qword,  NULL,   0 },
	{ "XER",    NULL,                            RC_GENERAL,  dt_dword,  NULL,   0 },

	{ "f0",     NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
	{ "f1",     NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
	{ "f2",     NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
	{ "f3",     NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
	{ "f4",     NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
	{ "f5",     NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
	{ "f6",     NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
	{ "f7",     NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
	{ "f8",     NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
	{ "f9",     NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
	{ "f10",    NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
	{ "f11",    NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
	{ "f12",    NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
	{ "f13",    NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
	{ "f14",    NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
	{ "f15",    NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
	{ "f16",    NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
	{ "f17",    NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
	{ "f18",    NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
	{ "f19",    NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
	{ "f20",    NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
	{ "f21",    NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
	{ "f22",    NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
	{ "f23",    NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
	{ "f24",    NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
	{ "f25",    NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
	{ "f26",    NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
	{ "f27",    NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
	{ "f28",    NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
	{ "f29",    NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
	{ "f30",    NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
	{ "f31",    NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },

	{ "FPSCR",  NULL,                            RC_FLOAT,    dt_dword,  NULL,   0 },

	/*{ "v0",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
	{ "v1",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
	{ "v2",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
	{ "v3",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
	{ "v4",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
	{ "v5",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
	{ "v6",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
	{ "v7",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
	{ "v8",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
	{ "v9",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
	{ "v10",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
	{ "v11",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
	{ "v12",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
	{ "v13",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
	{ "v14",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
	{ "v15",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
	{ "v16",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
	{ "v17",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
	{ "v18",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
	{ "v19",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
	{ "v20",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
	{ "v21",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
	{ "v22",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
	{ "v23",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
	{ "v24",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
	{ "v25",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
	{ "v26",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
	{ "v27",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
	{ "v28",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
	{ "v29",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
	{ "v30",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
	{ "v31",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 }*/
};

size_t registers_count = qnumber(registers);

int sock_init(void)
{
#ifdef _WIN32
	WSADATA wsa_data;
	return WSAStartup(MAKEWORD(1, 1), &wsa_data);
#else
	return 0;
#endif
}

int sock_quit(void)
{
#ifdef _WIN32
	return WSACleanup();
#else
	return 0;
#endif
}

#ifndef _WIN32
int closesocket(socket_t s) {
	return close(s);
}
const int SOCKET_ERROR = -1;
const socket_t INVALID_SOCKET = -1;
#define sscanf_s sscanf
#define HEX_U32 "x"
#define HEX_U64 "lx"
#else
#define HEX_U32 "lx"
#define HEX_U64 "llx"
#endif

bool check_errno_again() {
#ifdef _WIN32
	int err = GetLastError();
	return (err == WSAEWOULDBLOCK);
#else
	int err = errno;
	return (err == EAGAIN) || (err == EWOULDBLOCK);
#endif
}

std::string u32_to_hex(u32 i) {
	char buf[9];
	qsnprintf(buf, 9, "%" HEX_U32, i);
	return buf;
}

std::string u64_to_padded_hex(u64 value) {
	char buf[17];
	qsnprintf(buf, 17, "%.16" HEX_U64, value);
	return buf;
}

std::string u32_to_padded_hex(u32 value) {
	char buf[9];
	qsnprintf(buf, 9, "%.8" HEX_U32, value);
	return buf;
}

u8 hexdigit(char hex)
{
	return (hex <= '9') ? hex - '0' :
		toupper(hex) - 'A' + 10;
}

u8 hexbyte(const char* hex)
{
	return (hexdigit(*hex) << 4) | hexdigit(*(hex + 1));
}

u8 hex_to_u8(std::string val) {
	return hexbyte(val.c_str());
}

u32 hex_to_u32(std::string val) {
	u32 result;
	sscanf_s(val.c_str(), "%" HEX_U32, &result);
	return result;
}

u64 hex_to_u64(std::string val) {
	u64 result;
	sscanf_s(val.c_str(), "%" HEX_U64, &result);
	return result;
}

u32 idaregid_to_gdb(u32 r) {
	if (r < 32) {
		return r;
	}
	if (r < 38) {
		return r + 32;
	}
	if (r < 38 + 32) {
		return r - 6;
	}
	return r;
}

u32 gdbregid_to_ida(u32 r) {
	if (r < 32) {
		return r;
	}
	if (r < 64) {
		return r + 6;
	}
	if (r < 64 + 6) {
		return r - 32;
	}
	return r;
}

bool GDBDebugClient::connect(const char * hostname, int port)
{
	sock_init();
	int err;

	addrinfo* addr;

	struct addrinfo hints;
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;

	char sport[15];
	qsnprintf(sport, 15, "%d", port);

	err = getaddrinfo(hostname, sport, &hints, &addr);
	if (err == SOCKET_ERROR) {
		dbg_error("Error resolving hostname %s", hostname);
		return false;
	}

	client_socket = socket(AF_INET, SOCK_STREAM, 0);

	if (client_socket == INVALID_SOCKET) {
		dbg_error("Error creating socket");
		freeaddrinfo(addr);
		return false;
	}

#ifdef WIN32
	{
		int mode = 1;
		ioctlsocket(client_socket, FIONBIO, (u_long FAR *)&mode);
	}
#else
	fcntl(server_socket, F_SETFL, fcntl(client_socket, F_GETFL) | O_NONBLOCK);
#endif

	err = ::connect(client_socket, addr->ai_addr, addr->ai_addrlen);
	if (check_errno_again()) {
		FD_SET writableSet;
		FD_ZERO(&writableSet);
		FD_SET(client_socket, &writableSet);
		err = ::select(0, nullptr, &writableSet, nullptr, nullptr);
	}
	if (err == SOCKET_ERROR) {
		dbg_error("Error connecting to %s:%d", hostname, port);
		close(client_socket);
		client_socket = INVALID_SOCKET;
		freeaddrinfo(addr);
		return false;
	}
	attaching = true;

	dbg_success("Connected to %s:%d", hostname, port);
	freeaddrinfo(addr);
	return true;
}

int GDBDebugClient::read(void * buf, int cnt)
{
	int result = recv(client_socket, reinterpret_cast<char*>(buf), cnt, 0);
	if (result == SOCKET_ERROR) {
		if (check_errno_again()) {
			// not the best for perfromance, but easy control-flow
			throw would_block_exception();
		}
		dbg_error("Error during socket read");
		throw std::exception("Error during socket read");
	}
	return result;
}

char GDBDebugClient::read_char()
{
	char result;
	while (true) {
		try {
			read(&result, 1);
		}
		catch (would_block_exception) {
			continue;
		}
		break;
	}
	return result;
}

char GDBDebugClient::read_char_async()
{
	char result;
	read(&result, 1);
	return result;
}

u8 GDBDebugClient::read_hexbyte()
{
	std::string s = "";
	s += read_char();
	s += read_char();
	return hex_to_u8(s);
}

bool GDBDebugClient::try_read_packet(gdb_packet& out_cmd)
{
	char c;
	try {
		c = read_char_async();
	} catch (would_block_exception e) {
		return false;
	}
	//interrupt
	if (c == 0x03) {
		out_cmd.data = '\x03';
		out_cmd.checksum = 0;
		return true;
	}
	if (c != '$') {
		//gdb starts conversation with + for some reason
		if (c == '+') {
			c = read_char();
		}
		if (c != '$') {
			dbg_error("Expected start of packet character '$', got '%c' instead", c);
			throw std::exception("Expected start of packet character '$', got '%c' instead", c);
		}
	}
	//clear packet data
	out_cmd.data = "";
	out_cmd.checksum = 0;
	u8 checksum = 0;
	while (true) {
		c = read_char();
		if (c == '#') {
			break;
		}
		checksum = (checksum + reinterpret_cast<u8&>(c)) % 256;
		//escaped char
		if (c == '}') {
			c = read_char() ^ 0x20;
			checksum = (checksum + reinterpret_cast<u8&>(c)) % 256;
		}
		out_cmd.data += c;
	}
	out_cmd.checksum = read_hexbyte();
	if (out_cmd.checksum != checksum) {
		throw wrong_checksum_exception("Wrong checksum for packet");
	}
	return true;
}

bool GDBDebugClient::read_packet(gdb_packet& out_cmd)
{
	while (true) {
		try {
			if (!try_read_packet(out_cmd)) {
				continue;
			}
			ack(true);
			return true;
		}
		catch (wrong_checksum_exception) {
			ack(false);
		}
		catch (std::runtime_error e) {
			dbg_error(e.what());
			return false;
		}
	}
}

bool GDBDebugClient::read_packet_async(gdb_packet& out_cmd)
{
	while (true) {
		try {
			// try_read_packet returning false means there was no data available
			if (!try_read_packet(out_cmd)) {
				return false;
			}
			ack(true);
			return true;
		}
		catch (wrong_checksum_exception) {
			ack(false);
		}
		catch (std::runtime_error e) {
			dbg_error(e.what());
			return false;
		}
	}
}

void GDBDebugClient::send(const char * buf, int cnt)
{
	//dbg_trace_msg("Sending %s (%d bytes)", buf, cnt);
	while (true) {
		int res = ::send(client_socket, buf, cnt, 0);
		if (res == SOCKET_ERROR) {
			if (check_errno_again()) {
				Sleep(50);
				continue;
			}
			dbg_error("Failed sending %d bytes", cnt);
			return;
		}
		return;
	}
}

void GDBDebugClient::send_char(char c)
{
	send(&c, 1);
}

void GDBDebugClient::ack(bool accepted)
{
	send_char(accepted ? '+' : '-');
}

void GDBDebugClient::send_cmd(const std::string & cmd)
{
	u8 checksum = 0;
	std::string buf;
	buf.reserve(cmd.length() + 4);
	buf += "$";
	for (size_t i = 0; i < cmd.length(); ++i) {
		checksum = (checksum + append_encoded_char(cmd[i], buf)) % 256;
	}
	buf += "#";
	buf += to_hexbyte(checksum);
	send(buf.c_str(), static_cast<int>(buf.length()));
}

bool GDBDebugClient::send_cmd_ack(const std::string & cmd)
{
	while (true) {
		send_cmd(cmd);
		char c = read_char();
		if (c == '+') {
			return true;
		}
		if (c != '-') {
			dbg_warning("Wrong acknowledge character received %c", c);
			return false;
		}
		dbg_warning("Client rejected our cmd");
	}
}

u8 GDBDebugClient::append_encoded_char(char c, std::string & str)
{
	u8 checksum = 0;
	if ((c == '#') || (c == '$') || (c == '}')) {
		str += '}';
		c ^= 0x20;
		checksum = '}';
	}
	checksum = (checksum + reinterpret_cast<u8&>(c)) % 256;
	str += c;
	return checksum;
}

std::string GDBDebugClient::to_hexbyte(u8 i)
{
	std::string result = "00";
	u8 i1 = i & 0xF;
	u8 i2 = i >> 4;
	result[0] = i2 > 9 ? 'a' + i2 - 10 : '0' + i2;
	result[1] = i1 > 9 ? 'a' + i1 - 10 : '0' + i1;
	return result;
}

int GDBDebugClient::process_get_info(int n, process_info_t * info)
{
	//todo: can we do that properly?
	if (n > 0) {
		return IDA_FAIL;
	}
	info->pid = n + 1;
	qstrncpy(info->name, "Unknown", sizeof(info->name));
	return IDA_OK;
}

error_t GDBDebugClient::set_threadlist()
{
	return IDA_OK;
}

void GDBDebugClient::get_threads_info()
{
	if (!attaching) {
		return;
	}
	debug_event_t ev;
	if (send_cmd_ack("qfThreadInfo")) {
		gdb_packet p;
		if (read_packet(p)) {
			if (p.data[0] != 'm') {
				return;
			}
			int ptr = 1;
			std::string id = "";
			while (ptr < p.data.length()) {
				char c = p.data[ptr++];
				if (c == ',' || c == 'l') {
					try {
						ev.eid = THREAD_START;
						ev.pid = pid;
						ev.tid = static_cast<u32>(hex_to_u64(id));
						ev.ea = read_pc(ev.tid);
						ev.handled = true;

						events.enqueue(ev, IN_BACK);
					} catch (std::exception e) {
						dbg_warning(e.what());
					}
					id = "";
				}
				else {
					id += c;
				}
			}
		}
	}
	return;
}

int GDBDebugClient::start_process(const char * path, const char * args, const char * startdir, int dbg_proc_flags, const char * input_path, uint32 input_file_crc32)
{
	return 0;
}

int GDBDebugClient::attach_to_process(pid_t pid, int event_id)
{
	this->pid = pid;

	debug_event_t ev;
	ev.eid = PROCESS_START;
	ev.pid = pid;
	ev.tid = NO_THREAD;
	ev.ea = BADADDR;
	ev.handled = true;

	qstrncpy(ev.modinfo.name, "Unknown", sizeof(ev.modinfo.name));
	ev.modinfo.base = 0x10200;
	ev.modinfo.size = 0;
	ev.modinfo.rebase_to = BADADDR;

	events.enqueue(ev, IN_BACK);

	get_threads_info();
	//get_modules_info();
	//clear_all_bp(-1);

	ev.eid = PROCESS_ATTACH;
	ev.pid = pid;
	ev.tid = NO_THREAD; get_current_thread();
	ev.ea = BADADDR; get_current_pc();
	ev.handled = true;

	qstrncpy(ev.modinfo.name, "Unknown", sizeof(ev.modinfo.name));
	ev.modinfo.base = 0x10200;
	ev.modinfo.size = 0;
	ev.modinfo.rebase_to = BADADDR;

	events.enqueue(ev, IN_BACK);

	//process_names.clear();

	status = normal;

	return IDA_OK;
}

int GDBDebugClient::detach()
{
	bool ok = send_cmd_ack("D");
	if (ok) {
		gdb_packet p;
		if (read_packet(p)) {
			ok = p.data == "OK";
			if (!ok) {
				dbg_error("Got error from remote %s", p.data.c_str());
			}
		} else {
			ok = false;
		}
	}
	return ok ? IDA_OK : IDA_FAIL;
}

void GDBDebugClient::rebase_if_required_to(ea_t new_base)
{
	//todo: ???
}

int GDBDebugClient::prepare_to_pause()
{	
	// Ctrl+C "hack" in protocol
	send_char(0x03);
	waiting_for_status = true;
	status = pausing;
	return IDA_OK;
}

int GDBDebugClient::exit_process()
{
	send_cmd("k");
	return IDA_OK;
}

event_id_t status_to_event_type(status s) {
	switch (s) {
	case starting:
		return PROCESS_START;
	case attaching:
		return PROCESS_ATTACH;
	case normal:
		return BREAKPOINT;
	case pausing:
		return PROCESS_SUSPEND;
	}
}

bool GDBDebugClient::parse_stop_packet_to_event(std::string data, debug_event_t* event) {
	switch (data[0]) {
	case 'S':
	case 'T':
	{
		u8 signal = hex_to_u8(data.substr(1));
		//todo: others?
		if (signal != 5) {
			return false;
		}
		event->eid = status_to_event_type(status);
		if (status == starting || status == attaching) {
			//todo: retrieve from backend
			event->modinfo.base = 0x10200;// BADADDR;
			qstrncpy(event->modinfo.name, "Unknown", qnumber(event->modinfo.name));
			event->modinfo.rebase_to = BADADDR;
			event->modinfo.size = 0;
		} else {
			event->bpt.hea = BADADDR;
			event->bpt.kea = BADADDR;
		}		
		return true;
	}
	case 'W':
	case 'X':
		event->eid = PROCESS_EXIT;
		event->exit_code = static_cast<int>(hex_to_u8(data.substr(1)));
		return true;
	default:
		return false;
	}
}

int GDBDebugClient::get_current_thread()
{
	if (!send_cmd_ack("qC")) {
		throw std::exception("Failed sending qC command");
	}
	gdb_packet p;
	if (!read_packet(p)) {
		throw std::exception("Failed reading qC command response");
	}
	if ((p.data.length() >= 2) && (p.data[0] == 'Q') && (p.data[1] == 'C')) {
		last_thread_id = hex_to_u32(p.data.substr(2).c_str());
	}
	return last_thread_id;
}

std::string GDBDebugClient::get_register(int regid)
{
	gdb_packet p;
	regid = idaregid_to_gdb(regid);
	if (!send_cmd_ack("p" + u32_to_hex(regid))) {
		throw std::exception("Failed sending p command");
	}
	if (!read_packet(p)) {
		throw std::exception("Failed reading p command response");
	}
	if (!p.data.length()) {
		throw std::exception("Remote doesn't know how to read registers");
	}
	//this is quite strange gdb choice, what if registry value starts from 'E' ? do they just hope that no remote will have 24-bit registers?
	if ((p.data.length() == 3) && (p.data[0] == 'E')) {
		dbg_warning("Remote returned error while trying to read register %d: %s", regid, p.data.substr(1).c_str());
		return "x";
	}
	return p.data;
}

u32 GDBDebugClient::get_u32_register(int regid)
{
	std::string value = get_register(regid);
	if (value[0] == 'x') {
		throw std::exception("Remote doesn't have value for register %d", regid);
	}
	return hex_to_u32(value);
}

u64 GDBDebugClient::get_u64_register(int regid)
{
	std::string value = get_register(regid);
	if (value[0] == 'x') {
		throw std::exception("Remote doesn't have value for register %d", regid);
	}
	return hex_to_u64(value);
}

f64 GDBDebugClient::get_fpr(int fpr_id)
{
	std::string value = get_register(FPR_BASE + fpr_id);
	if (value[0] == 'x') {
		throw std::exception("Remote doesn't have value for fpr register %d", fpr_id);
	}
	u64 val = hex_to_u64(value);
	return reinterpret_cast<f64&>(val);
}

u64 GDBDebugClient::get_current_pc()
{
	return get_u64_register(PC_REGISTER_ID);
}

bool GDBDebugClient::set_current_thread(bool step_and_continue, thid_t id)
{
	if (!send_cmd_ack((step_and_continue ? "Hc" : "Hg") + u32_to_hex(id))) {
		return false;
	}
	gdb_packet p;
	if (!read_packet(p) || (p.data != "OK")) {
		return false;
	}
	return true;
}

gdecode_t GDBDebugClient::get_debug_event(debug_event_t * event, int ida_is_idle)
{
	if (event == NULL) {
		return GDE_NO_EVENT;
	}

	while (true) {
		if (events.retrieve(event)) {
			if (event->eid == PROCESS_ATTACH) {
				attaching = false;
			}
			return GDE_ONE_EVENT;
		}
		if (events.empty()) {
			break;
		}
	}

	bool ok;
	if (waiting_for_status) {
		ok = true;
		waiting_for_status = false;
	} else {
		return GDE_NO_EVENT;
		ok = send_cmd_ack("?");
	}
	if (ok) {
		gdb_packet p, p2;
		if (!read_packet_async(p)) {
			waiting_for_status = true;
			return GDE_NO_EVENT;
		}
		if (parse_stop_packet_to_event(p.data, event)) {
			event->pid = pid;
			event->tid = get_current_thread();
			event->ea = get_current_pc();
			//we have only one process...
			event->pid = pid;
			event->handled = true;

			if (step_map.find(event->tid) != step_map.end()) {
				event->eid = STEP;
				step_map.erase(event->tid);
			}
			return GDE_ONE_EVENT;
		}
		dbg_warning("Unparsable stop packet received: %s", p.data.c_str());
		return GDE_NO_EVENT;
	}
	return GDE_NO_EVENT;
}

int GDBDebugClient::continue_after_event(const debug_event_t * event)
{
	if (event == NULL) {
		return IDA_FAIL;
	}
	// allow PROCESS_ATTACH, since there will be only one, compared to THREAD_START
	if (event->eid == THREAD_START || event->eid == PROCESS_START) {
		return IDA_OK;
	}
	/*if (ignore_next_continue) {
		ignore_next_continue = false;
		return IDA_OK;
	}*/
	/*if (event->eid == PROCESS_START || event->eid == PROCESS_ATTACH || event->eid == THREAD_START || waiting_for_status) {
		return IDA_OK;
	}*/
	u64 thread_id;
	if (step_map.size()) {
		thread_id = step_map.begin()->first;
	}
	else {
		thread_id = event->tid;
	}
	if (!set_current_thread(true, thread_id)) {
		return IDA_FAIL;
	}
	std::string cmd = "vCont;";
	if (step_map.size()) {
		cmd += "s";
	//} else if (step_map.find(event->tid) != step_map.end()) {
	//	cmd += "s";
	} else {
		cmd += "c";
	}
	bool ok = send_cmd_ack(cmd);
	if (ok) {
		waiting_for_status = true;
	}

	return ok ? IDA_OK : IDA_FAIL;
}

void GDBDebugClient::stopped_at_debug_event(bool dlls_added)
{
}

int GDBDebugClient::thread_suspend(thid_t tid)
{
	return IDA_OK;
}

int GDBDebugClient::thread_continue(thid_t tid)
{	
	if (!set_current_thread(true, tid)) {
		return IDA_FAIL;
	}
	if (!send_cmd_ack("vCont;c")) {
		return IDA_FAIL;
	}
	waiting_for_status = true;
	return IDA_OK;
}

int GDBDebugClient::thread_step(thid_t tid)
{
	step_map[tid] = true;
	return IDA_OK;
	/*
	if (!set_current_thread(true, tid)) {
		return IDA_FAIL;
	}
	if (!send_cmd_ack("vCont;s")) {
		return IDA_FAIL;
	}
	status = step;

	debug_event_t event;
	gdb_packet p;
	read_packet(p);
	if (parse_stop_packet_to_event(p.data, &event)) {
		event.pid = pid;
		event.tid = get_current_thread();
		event.ea = get_current_pc();
		//we have only one process...
		event.pid = pid;
		event.handled = true;
		events.enqueue(event, IN_BACK);
		ignore_next_continue = true;

		status = normal;
	} else {
		status = normal;
		return IDA_FAIL;
	}
	return IDA_OK;
	*/
}

u64 GDBDebugClient::read_pc(thid_t tid) {

	if (!set_current_thread(false, tid)) {
		return IDA_FAIL;
	}
	return get_current_pc();
}

int GDBDebugClient::read_registers(thid_t tid, int clsmask, regval_t * values)
{
	if (!set_current_thread(false, tid)) {
		return IDA_FAIL;
	}
	if (!send_cmd_ack("g")) {
		return IDA_FAIL;
	}
	gdb_packet p;
	if (!read_packet(p)) {
		return IDA_FAIL;
	}
	if ((p.data.length() == 3) && (p.data[0] == 'E')) {
		return IDA_FAIL;
	}
	int n = sizeof(registers)/sizeof(register_info_t);
	int val_id = 0;
	int str_ptr = 0;
	for (int i = 0; i < n; ++i) {
		int idaid = gdbregid_to_ida(i);
		if (clsmask & registers[idaid].register_class) {
			if (p.data[str_ptr] != 'x') {
				if (registers[idaid].dtyp == dt_qword) {
					u64 val = hex_to_u64(p.data.substr(str_ptr, 16));
					values[val_id].ival = val;
				}
				else {
					u32 val = hex_to_u32(p.data.substr(str_ptr, 8));
					values[val_id].ival = val;
				}
			} else {
				values[val_id].ival = 0xDEADBEEF;
			}
			++val_id;
		}
		if (registers[idaid].dtyp == dt_qword) {
			str_ptr += 16;
		} else {
			str_ptr += 8;
		}
	}
	return IDA_OK;
}

int GDBDebugClient::write_register(thid_t tid, int reg_idx, const regval_t * value)
{
	if (!set_current_thread(false, tid)) {
		return IDA_FAIL;
	}
	int gdb_id = idaregid_to_gdb(reg_idx);
	std::string cmd = "P" + u32_to_hex(gdb_id) + "=";
	if (registers[reg_idx].dtyp == dt_qword) {
		cmd += u64_to_padded_hex(value->ival);
	} else {
		cmd += u32_to_padded_hex(static_cast<u32>(value->ival));
	}
	if (!send_cmd_ack(cmd)) {
		return IDA_FAIL;
	}
	gdb_packet p;
	if (read_packet(p) && (p.data == "OK")) {
		return IDA_OK;
	}
	return IDA_FAIL;
}

int GDBDebugClient::get_memory_info(meminfo_vec_t & areas)
{
	memory_info_t info;

	info.startEA = 0;
	info.endEA = 0xFFFF0000;
	info.name = NULL;
	info.sclass = NULL;
	info.sbase = 0;
	info.bitness = 1;
	info.perm = 0; // SEGPERM_EXEC / SEGPERM_WRITE / SEGPERM_READ

	areas.push_back(info);

	return 1;
}

ssize_t GDBDebugClient::read_memory(ea_t ea, void * buffer, size_t size)
{
	if (!send_cmd_ack("m" + u32_to_padded_hex(ea) + "," + u32_to_padded_hex(size))) {
		return IDA_FAIL;
	}
	gdb_packet p;
	if (!read_packet(p)) {
		return IDA_FAIL;
	}
	if ((p.data.length() == 3) && (p.data[0] == 'E')) {
		return IDA_FAIL;
	}
	size_t sz = min(p.data.length() / 2, size);
	u8* buf = reinterpret_cast<u8*>(buffer);
	for (size_t i = 0; i < sz; ++i) {
		buf[i] = hex_to_u8(p.data.substr(i * 2, 2).c_str());
	}
	return sz;
}

ssize_t GDBDebugClient::write_memory(ea_t ea, const void * buffer, size_t size)
{
	std::string cmd = "M" + u32_to_padded_hex(ea) + "," + u32_to_padded_hex(size) + ":";
	const u8* buf = reinterpret_cast<const u8*>(buffer);
	for (size_t i = 0; i < size; ++i) {
		cmd += to_hexbyte(buf[i]);
	}
	if (!send_cmd_ack(cmd)) {
		return -1;
	}
	gdb_packet p;
	if (!read_packet(p) || (p.data != "OK")) {
		return -1;
	}
	return size;
}

int GDBDebugClient::is_ok_bpt(bpttype_t type, ea_t ea, int len)
{
	if (type == BPT_SOFT) {
		return BPT_OK;
	}
	return BPT_BAD_TYPE;
}

int GDBDebugClient::update_bpts(update_bpt_info_t * bpts, int nadd, int ndel)
{
	int ok = 0;
	for(int i = 0; i < nadd; ++i) {
		if (bpts[i].code == BPT_SKIP) {
			++ok;
			continue;
		}
		if (bpts[i].type != BPT_SOFT) {
			bpts[i].code = BPT_BAD_TYPE;
			continue;
		}
		// can't send anything, while waiting for status
		if (waiting_for_status) {
			bpts[i].code = BPT_WRITE_ERROR;
			continue;
		}

		u32 orig;
		if (!read_memory(bpts[0].ea, &orig, 4)) {
			bpts[i].code = BPT_READ_ERROR;
			continue;
		}

		if (!send_cmd_ack("Z0," + u32_to_padded_hex(bpts[i].ea) + ",4")) {
			bpts[i].code = BPT_WRITE_ERROR;
			continue;
		}
		gdb_packet p;
		if (!read_packet(p) || (p.data != "OK")) {
			bpts[i].code = BPT_WRITE_ERROR;
			continue;
		}
		bpts[i].orgbytes.push_back(orig);
		bpts[i].code = BPT_OK;
		++ok;
	}
	for (int i = nadd; i < nadd + ndel; ++i) {
		if (bpts[i].code == BPT_SKIP) {
			++ok;
			continue;
		}
		if (bpts[i].type != BPT_SOFT) {
			bpts[i].code = BPT_BAD_TYPE;
			continue;
		}
		if (!send_cmd_ack("z0," + u32_to_padded_hex(bpts[i].ea) + ",4")) {
			bpts[i].code = BPT_WRITE_ERROR;
			continue;
		}
		gdb_packet p;
		if (!read_packet(p) || (p.data != "OK")) {
			bpts[i].code = BPT_WRITE_ERROR;
			continue;
		}
		bpts[i].code = BPT_OK;
		++ok;
	}
	return ok;
}

ea_t GDBDebugClient::map_address(ea_t off, const regval_t * regs, int regnum)
{
	if (regnum == 0)
	{
	}

	if (regs == NULL) // jump prediction
	{
		return BADADDR;
	}

	if (regs[regnum].ival < 0x100000000 && regs[regnum].ival > 0x10200)
	{
		return static_cast<u32>(regs[regnum].ival);
	}

	return BADADDR;
}

int GDBDebugClient::send_ioctl(int fn, const void * buf, size_t size, void ** poutbuf, ssize_t * poutsize)
{
	return 0;
}

bool GDBDebugClient::read_u64_from_mem(ea_t ea, u64& out) {
	u64 res;
	int result = read_memory(ea, &res, 8);
	if (result == IDA_FAIL) {
		return false;
	}
	out = _byteswap_uint64(res);
	return true;
}

bool idaapi GDBDebugClient::update_call_stack(thid_t tid, call_stack_t *trace) {
	set_current_thread(false, tid);
	u32 stack_ptr = static_cast<u32>(get_u64_register(SP_REGISTER_ID));

	u32 stack_min = stack_ptr & ~0xfff;
	u32 stack_max = stack_min + 4096;

	char buf;

	while (stack_min && (read_memory(stack_min - 1, &buf, 1) != IDA_FAIL))
	{
		stack_min -= 4096;
	}

	while (stack_max + 4096 && (read_memory(stack_max, &buf, 1) != IDA_FAIL))
	{
		stack_max += 4096;
	}

	call_stack_info_t entry;
	entry.callea = get_current_pc();
	entry.fp = stack_ptr;
	trace->push_back(entry);

	u64 sp;
	if (!read_u64_from_mem(stack_ptr, sp)) {
		dbg_error("Can't read from stack addr %llx", stack_ptr);
		return false;
	}
	for (; sp >= stack_min && sp + 0x200 < stack_max;)
	{
		u64 from;
		if (!read_u64_from_mem(static_cast<u32>(sp + 16), from)) {
			dbg_error("Can't read from stack addr %llx", sp + 16);
			return false;
		}
		entry.fp = sp;
		entry.callea = from;
		trace->push_back(entry);

		if (!read_u64_from_mem(static_cast<u32>(sp), sp)) {
			dbg_error("Can't read from stack addr %llx", sp);
			return false;
		}
	}
	return true;
}