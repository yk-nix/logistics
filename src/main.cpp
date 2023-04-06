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

#include <activemq/library/ActiveMQCPP.h>
#include <decaf/lang/Thread.h>
#include <decaf/lang/Runnable.h>
#include <decaf/util/concurrent/CountDownLatch.h>
#include <decaf/lang/Integer.h>
#include <decaf/lang/Long.h>
#include <decaf/lang/System.h>
#include <activemq/core/ActiveMQConnectionFactory.h>
#include <activemq/util/Config.h>
#include <cms/Connection.h>
#include <cms/Session.h>
#include <cms/TextMessage.h>
#include <cms/BytesMessage.h>
#include <cms/MapMessage.h>
#include <cms/ExceptionListener.h>
#include <cms/MessageListener.h>

#define CONFIG_FILE "/etc/logistics/logistics.conf"

#include <iostream>
#include <thread>

using namespace std;
using namespace cms;

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

enum ActiveMQType {
	TOPIC,
	QUEUE,
};

struct ActiveMQ {
	char *name;
	char *active_name;
	int type;
	char *uri;
	Connection* connection;
	Session* session;
	Destination* destination;
	MessageProducer* producer;
};

struct ActiveMQs {
	ActiveMQ *peccancy;
	ActiveMQ *log;
	ActiveMQ *alert;
	ActiveMQ *plate;
	ActiveMQ *oplog;
};

static ActiveMQs active_mqs = { 0 };

static int create_connection(ActiveMQ *mq) {
	try {
cout << "create connection-factory(" << mq->uri << ") ...";
		//auto_ptr<ConnectionFactory> connectionFactory(ConnectionFactory::createCMSConnectionFactory(mq->uri));
		ConnectionFactory *connectionFactory = ConnectionFactory::createCMSConnectionFactory(mq->uri);
		if (connectionFactory == NULL)
			throw CMSException("invalid uri." );
		mq->connection = connectionFactory->createConnection();
		mq->connection->start();
cout << "OK" << endl;
		return 0;
	}
	catch (CMSException &e) {
		return 1;
	}
}

static int create_session(ActiveMQ *mq) {
	try {
		if (mq->connection == NULL)
			create_connection(mq);
cout << "create session...";
		mq->session = mq->connection->createSession(Session::SESSION_TRANSACTED);
cout << "OK" << endl;
		return 0;
	}
	catch (CMSException &e) {
		return 1;
	}
}

static int create_destination(ActiveMQ *mq) {
	try {
		if (mq->session == NULL)
			create_session(mq);
cout << "create destination...";
		mq->destination = mq->session->createTopic(mq->active_name);
cout << "OK" << endl;
		return 0;
	}
	catch (CMSException &e) {
		return 1;
	}
}

static int create_producer(ActiveMQ *mq) {
	try {
		if (mq->destination == NULL)
			create_destination(mq);
cout << "create producer...";
		mq->producer = mq->session->createProducer(mq->destination);
		mq->producer->setDeliveryMode(DeliveryMode::NON_PERSISTENT);
cout << "OK" << endl;
		return 0;
	}
	catch (CMSException &e) {
		return 1;
	}
}

static int send_message(ActiveMQ *mq, const char *msg) {
	try {
		if (mq == NULL)
			return 0;
		if (mq->producer == NULL) {
			create_producer(mq);
		}
cout << "send message to activemq(" << mq->name << ")...";
		std::auto_ptr<TextMessage> message(mq->session->createTextMessage(msg));
		mq->producer->send(message.get());
cout << "OK" << endl;
		return 0;
	}
	catch (CMSException &e) {
		return -1;
	}
}

static void active_mq_cleanup(ActiveMQ *mq) {
	if (mq->connection != NULL) {
		try {
cout << "close connection...";
			mq->connection->close();
cout << "OK" << endl;
		}
		catch (CMSException &ex) {
			ex.printStackTrace();
		}
	}
	try {
cout << "release activemq resources...";
		delete mq->destination;
		mq->destination = NULL;
		delete mq->producer;
		mq->producer = NULL;
		delete mq->session;
		mq->session = NULL;
		delete mq->connection;
		mq->connection = NULL;
cout << "OK" << endl;
	} catch (CMSException& e) {
		e.printStackTrace();
	}
}

static ActiveMQ *active_mq_create(const char *uri, const char *name, const char *type, const char *active_name) {
cout << "create active mq: " << endl;
cout << "  uri: " << uri << endl;
cout << "  acitve_name: " << active_name << endl;
	ActiveMQ *mq = new ActiveMQ;
	mq->name = strdup(name);
	mq->active_name = strdup(active_name);
	mq->uri = strdup(uri);
	if (type) {
		mq->type = strcmp(type, "queue") ? TOPIC : QUEUE;
	}
	else {
		mq->type = TOPIC;
	}
	mq->connection = NULL;
	mq->session = NULL;
	mq->producer = NULL;
	mq->destination = NULL;
	return mq;
}

static void active_mq_free(ActiveMQ **mq) {
	if (*mq) {
		if ((*mq)->name)
			free((*mq)->name);
		if ((*mq)->active_name)
			free((*mq)->active_name);
		active_mq_cleanup(*mq);
		delete *mq;
		*mq = NULL;
	}
}

static void log_routine(const char *msg, int len) {
	cout << "log: " << msg << endl;
	if (send_message(active_mqs.log, msg) < 0)
		active_mq_cleanup(active_mqs.log);
}
static void oplog_routine(const char *msg, int len) {
	cout << "oplog: " <<  msg << endl;
	if (send_message(active_mqs.oplog, msg) < 0)
		active_mq_cleanup(active_mqs.oplog);
}
static void peccancy_routine(const char *msg, int len) {
	cout << "peccancy: " << msg << endl;
	if (send_message(active_mqs.peccancy, msg) < 0)
		active_mq_cleanup(active_mqs.peccancy);
}
static void plate_routine(const char *msg, int len) {
	cout << "plate: " << msg << endl;
	if (send_message(active_mqs.plate, msg) < 0)
		active_mq_cleanup(active_mqs.plate);
}
static void alert_routine(const char *msg, int len) {
	cout << "alert: " << msg << endl;
	if (send_message(active_mqs.alert, msg) < 0)
		active_mq_cleanup(active_mqs.alert);
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

static void load_config_file(const char *config_file) {
	int idx = 0;
	config_setting_t *elem = NULL;
	const char *uri = NULL;
	config_setting_t *mqs = NULL;
	if (access(config_file, R_OK))
		return;
	config_t config = { 0 };
	config_init(&config);
	if (config_read_file(&config, config_file) != CONFIG_TRUE)
		goto err0;
	mqs = config_lookup(&config, "active_mqs");
	if (mqs == NULL)
		goto err0;
	if (config_lookup_string(&config, "active_mq_uri", &uri) != CONFIG_TRUE)
		goto err0;
	while ((elem = config_setting_get_elem(mqs, idx++))) {
		const char *name = NULL, *type=NULL, *active_name=NULL;
		if (config_setting_lookup_string(elem, "name", &name) != CONFIG_TRUE)
			continue;
		if (config_setting_lookup_string(elem, "active_name", &active_name) != CONFIG_TRUE)
			continue;
		config_setting_lookup_string(elem, "type", &type);
		if (strcmp(name, "peccancy") == 0)
			active_mqs.peccancy = active_mq_create(uri, name, type, active_name);
		else if (strcmp(name, "alert") == 0)
			active_mqs.alert = active_mq_create(uri, name, type, active_name);
		else if (strcmp(name, "plate") == 0)
			active_mqs.plate = active_mq_create(uri, name, type, active_name);
		else if (strcmp(name, "log") == 0)
			active_mqs.log = active_mq_create(uri, name, type, active_name);
		else if (strcmp(name, "oplog") == 0)
			active_mqs.oplog = active_mq_create(uri, name, type, active_name);
	}
err0:
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
	activemq::library::ActiveMQCPP::initializeLibrary();
	const char *config = CONFIG_FILE;
	if (argc >= 2)
		config = argv[1];
	load_config_file(config);
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
	activemq::library::ActiveMQCPP::shutdownLibrary();
}

