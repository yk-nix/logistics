/*
 * main.cpp
 *
 *  Created on: 2023年3月23日
 *      Author: yui
 */
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <libconfig.h>
#include <mqueue.h>
#define MQ_CONFIG_FILE "/etc/mq/mq.conf"


#include <iostream>
#include <thread>

using namespace std;

struct MQ {
	char *name;
	int priority;
	int size;
	void (*action) (const char *msg, int len);
};

struct MQs {
	MQ *peccancy;
	MQ *log;
	MQ *alert;
	MQ *plate;
	MQ *oplog;
};

static MQs logtistics_mqs = { 0 };

static MQ *mq_create(const char *name, int size,  int priority, void (*action)(const char*, int)) {
	MQ *mq = new MQ;
	mq->name = strdup(name);
	mq->priority = priority;
	mq->size = size;
	mq->action = action;
	return mq;
}
static void mq_free(MQ **mq) {
	if (*mq) {
		if ((*mq)->name)
			free((*mq)->name);
		delete *mq;
		*mq = NULL;
	}
}

static void log_routine(const char *msg, int len) {
	cout << msg << endl;
}
static void oplog_routine(const char *msg, int len) {
	cout << msg << endl;
}
static void peccancy_routine(const char *msg, int len) {
	cout << msg << endl;
}
static void plate_routine(const char *msg, int len) {
	cout << msg << endl;
}
static void alert_routine(const char *msg, int len) {
	cout << msg << endl;
}

static void load_mq_config_file(const char *config_file) {
	if (access(config_file, R_OK))
		return;
	config_t config = { 0 };
	config_init(&config);
	if (config_read_file(&config, config_file) != CONFIG_TRUE)
		return;
	config_setting_t *mqs = config_lookup(&config,"mqs");
	if (mqs == NULL)
		return;
	int idx = 0;
	config_setting_t *elem = NULL;
	while ((elem = config_setting_get_elem(mqs, idx++))) {
		const char *name = NULL;
		int size = 0, priority = 0;
		if (config_setting_lookup_string(elem, "name", &name) != CONFIG_TRUE)
			continue;
		if (config_setting_lookup_int(elem, "size", &size) != CONFIG_TRUE)
			continue;
		config_setting_lookup_int(elem, "priority", &priority);
		if (size <= 0)
			continue;
		if (strcmp(name, "/peccancy") == 0)
			logtistics_mqs.peccancy = mq_create(name, size, priority, peccancy_routine);
		else if (strcmp(name, "/alert") == 0)
			logtistics_mqs.alert = mq_create(name, size, priority, alert_routine);
		else if (strcmp(name, "/plate") == 0)
			logtistics_mqs.plate = mq_create(name, size, priority, plate_routine);
		else if (strcmp(name, "/log") == 0)
			logtistics_mqs.log = mq_create(name, size, priority, log_routine);
		else if (strcmp(name, "/oplog") == 0)
			logtistics_mqs.oplog = mq_create(name, size, priority, oplog_routine);
	}
	config_destroy(&config);
}

static void routine(MQ *ctx) {
	int buf_size = ctx->size + 1, bytes = 0;
	char *buf = (char *)malloc(buf_size);
	if (buf == NULL)
		return;
	mqd_t mq = mq_open(ctx->name, O_RDONLY, 0, NULL);
	if (mq == -1) {
		cout << "failed to open mq (" << ctx->name << ")" << endl;
		goto err1;
	}
	while (true) {
		memset(buf, 0, sizeof(buf));
		if ((bytes = mq_receive(mq, buf, buf_size, NULL)) < 0) {
			cout << "mq (" << ctx->name << ") fatal error: " << strerror(errno) << endl;
			break;
		}
		if (ctx->action)
			ctx->action(buf, bytes);
	}
	mq_close(mq);
err1:
	free(buf);
}

int main(int argc, char *argv[]) {
	load_mq_config_file(MQ_CONFIG_FILE);
	thread pecc(routine, logtistics_mqs.peccancy);
	thread alert(routine, logtistics_mqs.alert);
	thread log(routine, logtistics_mqs.log);
	thread oplog(routine, logtistics_mqs.oplog);
	thread plate(routine, logtistics_mqs.plate);
	pecc.join();
	alert.join();
	log.join();
	oplog.join();
	plate.join();
	cout << "logistics out" << endl;
}

