#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <netinet/tcp.h>
#include <sys/select.h>
#include <arpa/inet.h>

#include "config.h"
#include "log.h"
#include "tunnel.h"
#include "http.h" // for url_encode

static void print_url(const struct vpn_config *cfg) {
	char *encoded_realm = NULL;
	char realm[] = "&realm=";
	char *empty_string = "\0";

	// Desired string is https://company.com:port/remote/saml/start?redirect=1(&realm=<str>)
	// with the realm being optional
	static const char *uri_pattern = "https://%s:%d/remote/saml/start?redirect=1%s%s";

	if (cfg->realm[0] != '\0') {
		encoded_realm = alloca(strlen(cfg->realm) * 3 + 1); // url_encode required three times the size
		url_encode(encoded_realm, cfg->realm);
	} else {
		encoded_realm = empty_string;
		realm[0] = 0; // Make realm appear empty when printing as string
	}

	int required_size = 1 + snprintf(NULL, 0, uri_pattern, cfg->gateway_host, cfg->gateway_port, realm, encoded_realm);
	char *url = alloca(required_size);
	snprintf(url, required_size, uri_pattern, cfg->gateway_host, cfg->gateway_port, realm, encoded_realm);

	log_info("Authenticate at '%s'\n", url);
}

// Convenience function to send a response with a user readable status message and the
// request URL shown for debug purposes.
// The response is shown in the user's browser after being redirected from the Fortinet Server.
static void send_status_response(int socket, const char *userMessage) {
	static const char *replyHeader = "HTTP/1.1 200 OK\r\n"
			"Content-Type: text/html\r\n"
			"Content-Length: %lu\r\n"
			"Connection: close\r\n"
			"\r\n";

	static const char *replyBody = "<!DOCTYPE html>\r\n"
			"<html><body>\r\n"
			"%s" // User readable message
			"</body></html>\r\n";

	int replyBodySize = snprintf(NULL, 0, replyBody, userMessage) + 1;
	char *replyBodyBuffer = alloca(replyBodySize);
	snprintf(replyBodyBuffer, replyBodySize, replyBody, userMessage);

	int replyHeaderSize = snprintf(NULL, 0, replyHeader, replyBodySize) + 1;
	char *replyHeaderBuffer = alloca(replyHeaderSize);
	snprintf(replyHeaderBuffer, replyHeaderSize, replyHeader, strlen(replyBodyBuffer));

	// Using two separate writes here to make the code not more complicated assembling
	// the buffers.
	ssize_t write_result = write(socket, replyHeaderBuffer, strlen(replyHeaderBuffer));
	write_result = write(socket, replyBodyBuffer, strlen(replyBodyBuffer));
	(void)write_result;
}

static int process_request(int new_socket, char *id) {
	log_info("Processing HTTP SAML request\n");

	int flag = 1;
	setsockopt(new_socket, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(int));

	// Read the request
	char request[1024];
	ssize_t read_result = read(new_socket, request, sizeof(request) - 1 /*  Save one place for termination
										in case the request is about to
										fill the entire buffer. */
				);

	// Check for '=id' in the response
	// If the recevied request from the server is larger than the buffer, the result will not be null-terminated.
	// Causing strlen to behave wrong.
	if (read_result < 0) {
		log_error("Bad request\n");
		send_status_response(new_socket, "Invalid redirect response from Fortinet server. VPN could not be established.");
		return -1;
	}

	// Safety Null-terminate
	request[sizeof(request) - 1] = 0;
	request[read_result] = 0;

	static const char *request_head = "GET /?id=";

	if (strncmp(request, request_head, strlen(request_head)) != 0) {
		log_error("Bad request\n");
		send_status_response(new_socket, "Invalid redirect response from Fortinet server. VPN could not be established.");
		return -1;
	}

	// Extract the id
	static const char *token_delimiter = " &\r\n";
	char *next_token = request + strlen(request_head); // strsep does modify the input argument and we don't want to loose our request pointer.
	char *id_start = strsep(&next_token, token_delimiter);

	if (next_token == NULL) {
		// In case not found, next_token was set to NULL
		// This should be invalid because we expect \r\n at the end of the GET request line
		log_error("Bad request format\n");
		send_status_response(new_socket, "Invalid formatting of Fortinet server redirect response. VPN could not be established.");
		return -1;
	}

	// strsep inserted a NULL at the location of the delimiter.
	int id_length = strlen(id_start);

	if(id_length == 0 || id_length >= MAX_SAML_SESSION_ID_LENGTH) {
		log_error("Bad request id\n");
		send_status_response(new_socket, "Invalid SAML session id received from Fortinet server. VPN could not be established.");
		return -1;
	}

	// It was checked above, that the length is smaller than MAX_SAML_SESSION_ID_LENGTH
	strcpy(id, id_start);

	for (int i = 0; i < id_length; i++) {
		if (isalnum(id[i]) || id[i] == '-') continue;
		log_error("Invalid id format\n");
		send_status_response(new_socket, "Invalid SAML session id received from Fortinet server. VPN could not be established.");
		return -1;
	}

	send_status_response(new_socket,
			"SAML session id received from Fortinet server. VPN will be established...<br>"
			"You may close this browser tab now.<br>"
			"<script>"
			"window.setTimeout(() => { window.close(); }, 5000);\r\n"
			"document.write(\"<br>This window will close automatically in 5 seconds.\");\r\n"
			"</script>\r\n");
	return 0;
}

/**
 * Run a http server to listen for SAML login requests
 *
 * @return 0 in case of success
 *         < 0 in case of error
*/
int wait_for_http_request(struct vpn_config *config) {
	int server_fd, new_socket;
	struct sockaddr_in address;
	int opt = 1;
	int addrlen = sizeof(address);
	long saml_port = config->saml_port;
	char addrstring[INET_ADDRSTRLEN];

	address.sin_family = AF_INET;
	if (config->saml_hostaddr == NULL) {
		// If hostaddr is not set, default to the loopback interface to avoid the port being
		// publicly accessible to other machines on the network.
		address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	} else {
		if (inet_pton(AF_INET, config->saml_hostaddr, &address.sin_addr.s_addr) != 1) {
			log_error("SAML host address '%s' is invalid.\n", config->saml_hostaddr);
			return -1;
		}
	}
	address.sin_port = htons(saml_port);

	// Creating socket file descriptor
	if ((server_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0)) == 0) {
		log_error("Failed to create socket\n");
		return -1;
	}

	// Forcefully attaching socket to the port
	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
		close(server_fd);
		log_error("Failed to set socket options\n");
		return -1;
	}

	inet_ntop(AF_INET, &address.sin_addr.s_addr, addrstring, sizeof(addrstring)); // Ignore error

	// Forcefully attaching socket to the port
	if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
		close(server_fd);
		log_error("Failed to bind socket to %s:%d\n", addrstring, saml_port);
		return -1;
	}

	if (listen(server_fd, 3) < 0) {
		close(server_fd);
		log_error("Failed to listen on socket\n");
		return -1;
	}

	int max_tries = 5;
	fd_set readfds;
	struct timeval tv;

	log_info("Listening for SAML login on %s:%d\n", addrstring, saml_port);
	print_url(config);

	while(max_tries > 0) {
		--max_tries;
		FD_ZERO(&readfds);
		FD_SET(server_fd, &readfds);
		// Wait up to ten seconds
		tv.tv_sec = 10;
		tv.tv_usec = 0;

		int retval = select(server_fd + 1, &readfds, NULL, NULL, &tv);

		if (retval == -1) {
			log_error("Failed to wait for connection: %s\n", strerror(errno));
			break;
		} else if (retval > 0) {
			log_debug("Incoming HTTP connection\n");
			if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
				log_error("Failed to accept connection\n");
				continue;
			}
		} else {
			log_debug("Timeout listening for incoming HTTP connection reached\n");
			continue;
		}

		int result = process_request(new_socket, config->saml_session_id);
		close(new_socket);
		if(result == 0)
			break;

		log_warn("Failed to process request\n");
	}

	close(server_fd);

	if (max_tries == 0 && strlen(config->saml_session_id) == 0) {
		log_error("Finally failed to retrieve SAML authentication token\n");
		return -1;
	}

	return 0;
}

