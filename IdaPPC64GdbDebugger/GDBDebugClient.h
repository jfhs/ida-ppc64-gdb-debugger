#pragma once

#include <ida.hpp>
#include <dbg.hpp>
#include <string>
#include <deque>

#ifdef _WIN32
#include <winsock2.h>
#include <WS2tcpip.h>
#else
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

#ifdef _WIN32
typedef SOCKET socket_t;
#else
typedef int socket_t;
#endif

const int IDA_OK = 1;
const int IDA_FAIL = 0;
const int IDA_NETWORK_ERR = -1;

typedef unsigned char u8;
typedef unsigned int u16;
typedef unsigned long u32;
typedef unsigned long long u64;

typedef signed char s8;
typedef signed int s16;
typedef signed long s32;
typedef signed long long s64;

typedef float f32;
typedef double f64;

const int FPR_BASE = 32;
const int PC_REGISTER_ID = 32;
const int SP_REGISTER_ID = 1;
const int REGISTER_GPR_MASK = 1;
const int REGISTER_FPR_MASK = 2;

#define dbg_error warning
#define dbg_warning msg
#define dbg_success msg
#define dbg_trace_msg msg

#define RC_GENERAL 1
#define RC_FLOAT   2
//#define RC_VECTOR  3

extern const char* register_classes[];

extern const char *const CReg[];

extern const char *const vmx_format[];

//--------------------------------------------------------------------------
extern register_info_t registers[];
extern size_t registers_count;

class wrong_checksum_exception : public std::runtime_error {
public:
	wrong_checksum_exception(char const* const message) : runtime_error(message) {}
};

class would_block_exception : public std::runtime_error {
public:
	would_block_exception() : runtime_error("would block") {}
};

typedef struct gdb_packet {
	std::string data;
	u8 checksum;
} gdb_cmd;

enum status {
	starting,
	attaching,
	normal,
	pausing
};

// Very simple class to store pending events
enum queue_pos_t
{
	IN_FRONT,
	IN_BACK
};

struct eventlist_t : public std::deque<debug_event_t>
{
private:
	bool synced;
public:
	// save a pending event
	void enqueue(const debug_event_t &ev, queue_pos_t pos)
	{
		if (pos != IN_BACK)
			push_front(ev);
		else
			push_back(ev);
	}

	// retrieve a pending event
	bool retrieve(debug_event_t *event)
	{
		if (empty())
			return false;
		// get the first event and return it
		*event = front();
		pop_front();
		return true;
	}
};

class GDBDebugClient {
private:
	socket_t client_socket;
	status status;
	int last_thread_id;
	bool waiting_for_status;
	bool attaching;
	pid_t pid;
	eventlist_t events;
	bool ignore_next_continue;
	std::map<u32, bool> step_map;

	bool parse_stop_packet_to_event(std::string data, debug_event_t* event);
	int get_current_thread();
	std::string get_register(int regid);
	u32 get_u32_register(int regid);
	u64 get_u64_register(int regid);
	f64 get_fpr(int fpr_id);
	u64 get_current_pc();	
	bool set_current_thread(bool step_and_continue, thid_t tid);
	void get_threads_info();
	u64 read_pc(thid_t tid);

public:
	GDBDebugClient() : waiting_for_status(false), attaching(false), last_thread_id(NO_THREAD), ignore_next_continue(false) {
	}

	//stop reading/writing sockets
	bool stop;

	//initialize client socket and connect to host
	bool connect(const char* hostname, int port);
	//read at most cnt bytes to buf, returns nubmer of bytes actually read
	int read(void* buf, int cnt);
	//reads one character
	char read_char();
	char read_char_async();
	//reads pairs of hex characters and returns their integer value
	u8 read_hexbyte();
	//tries to read command, throws exceptions if anything goes wrong
	bool try_read_packet(gdb_packet& out_cmd);
	//reads commands until receiveing one with valid checksum
	//in case of other exception (i.e. wrong first char of command)
	//it will log exception text and return false 
	//in that case best for caller would be to stop reading, because 
	//chance of getting correct command is low
	bool read_packet(gdb_packet& out_cmd);

	bool read_packet_async(gdb_packet& out_cmd);
	//send cnt bytes from buf to client
	void send(const char* buf, int cnt);
	//send character to client
	void send_char(char c);
	//acknowledge packet, either as accepted or declined
	void ack(bool accepted);
	//sends command body cmd to client
	void send_cmd(const std::string & cmd);
	//sends command to client until receives positive acknowledgement
	//returns false in case some error happened, and command wasn't sent
	bool send_cmd_ack(const std::string & cmd);
	//appends encoded char c to string str, and returns checksum. encoded byte can occupy 2 bytes
	static u8 append_encoded_char(char c, std::string& str);
	//convert u8 to 2 byte hexademical representation
	static std::string to_hexbyte(u8 i);

	bool read_u64_from_mem(ea_t ea, u64& out);

	int process_get_info(int n, process_info_t *info);
	error_t set_threadlist();
	int start_process(const char *path, const char *args, const char *startdir, int dbg_proc_flags, const char *input_path, uint32 input_file_crc32);
	int attach_to_process(pid_t pid, int event_id);
	int detach();
	void rebase_if_required_to(ea_t new_base);
	int prepare_to_pause();
	int exit_process();
	gdecode_t get_debug_event(debug_event_t *event, int ida_is_idle);
	int continue_after_event(const debug_event_t *event);
	void stopped_at_debug_event(bool dlls_added);
	int thread_suspend(thid_t tid);
	int thread_continue(thid_t tid);
	int thread_step(thid_t tid);
	int read_registers(thid_t tid, int clsmask, regval_t *values);
	int write_register(thid_t tid, int reg_idx, const regval_t *value);
	int get_memory_info(meminfo_vec_t &areas);
	ssize_t read_memory(ea_t ea, void *buffer, size_t size);
	ssize_t write_memory(ea_t ea, const void *buffer, size_t size);
	int is_ok_bpt(bpttype_t type, ea_t ea, int len);
	int update_bpts(update_bpt_info_t *bpts, int nadd, int ndel);
	ea_t map_address(ea_t off, const regval_t *regs, int regnum);
	int send_ioctl(int fn, const void *buf, size_t size, void **poutbuf, ssize_t *poutsize);
	bool idaapi update_call_stack(thid_t tid, call_stack_t *trace);
};