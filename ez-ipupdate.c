/* ============================================================================
 * Copyright (C) 1999 Angus Mackay. All rights reserved; 
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 * ============================================================================
 */

/*
 * ez-ipupdate
 *
 * a very simple dynDNS client for the ez-ip dynamic dns service 
 * (http://www.ez-ip.net).
 *
 * why this program when something like:
 *   curl -u user:pass http://www.ez-ip.net/members/update/?key=val&...
 * would do the trick? because there are nicer clients for other OSes and
 * I don't like to see UNIX get the short end of the stick.
 *
 * tested under Linux and Solaris.
 * 
 */

#define DEFAULT_SERVER "www.EZ-IP.Net"
#define DEFAULT_PORT "80"
#define REQUEST "/members/update/"
#define DEFAULT_TIMEOUT 120
#define DEFAULT_UPDATE_PERIOD 1800
#if __linux__
#  define DEFAULT_IF "eth0"
#elif __OpenBSD__
#  define DEFAULT_IF "ne0"
#else
#  define DEFAULT_IF "eth0"
#endif

#define BUFFER_SIZE 2048

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#if HAVE_FCNTL_H
#  include <fcntl.h>
#endif
#include <netinet/in.h>
#if HAVE_ARPA_INET_H
#  include <arpa/inet.h>
#endif
#include <netdb.h>
#include <sys/socket.h>
#if HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#if HAVE_SIGNAL_H
#  include <signal.h>
#endif
#if HAVE_SYS_TIME_H
#  include <sys/time.h>
#endif
#if HAVE_SYSLOG_H
#  include <syslog.h>
#endif
#if HAVE_STRERROR
extern int errno;
#  define error_string strerror(errno)
#elif HAVE_SYS_ERRLIST
extern const char *const sys_errlist[];
extern int errno;
#  define error_string (sys_errlist[errno])
#else
#  define error_string "error message not found"
#endif
#if HAVE_PWD_H && HAVE_GRP_H
#  include <pwd.h>
#  include <grp.h>
#endif



#if __linux__
#  define IF_LOOKUP 1
#  include <sys/ioctl.h>
#  include <net/if.h>
#elif __OpenBSD__
#  define IF_LOOKUP 1
#  include <sys/ioctl.h>
#  include <net/if.h>
#endif

#include <conf_file.h>

#if !defined(__GNUC__) && !defined(HAVE_SNPRINTF)
#error "get gcc, fix this code, or find yourself a snprintf!"
#else
#  if HAVE_SNPRINTF
#    define  snprint(x, y, z...) snprintf(x, y, ## z)
#  else
#    define  snprint(x, y, z...) sprintf(x, ## z)
#  endif
#endif

#ifndef HAVE_HERROR
#  define herror(x) fprintf(stderr, "%s: error\n", x)
#endif

#ifdef DEBUG
#define dprintf(x) if( options & OPT_DEBUG ) \
{ \
  fprintf(stderr, "%s,%d: ", __FILE__, __LINE__); \
    fprintf x; \
}
#else
#  define dprintf(x)
#endif

#ifndef OS
#  define OS "unknown"
#endif

/**************************************************/

static char *program_name = NULL;
static char *config_file = NULL;
static char *server = NULL;
static char *port = NULL;
static char user[256];
static char auth[512];
static char *address = NULL;
static char *request = NULL;
static char *wildcard = NULL;
static char *mx = NULL;
static char *url = NULL;
static char *host = NULL;
static char *interface = NULL;
static int ntrys = 1;
static int update_period = DEFAULT_UPDATE_PERIOD;
static struct timeval timeout;

static volatile int client_sockfd;
static volatile int last_sig = 0;

int options;

#define OPT_DEBUG       0x0001
#define OPT_DAEMON      0x0004
#define OPT_QUIET       0x0008
#define OPT_FOREGROUND  0x0010

enum { 
  CMD__start = 1,
  CMD_server,
  CMD_user,
  CMD_address,
  CMD_wildcard,
  CMD_mx,
  CMD_url,
  CMD_host,
  CMD_interface,
  CMD_retrys,
  CMD_period,
  CMD_daemon,
  CMD_debug,
  CMD_foreground,
  CMD_quiet,
  CMD_timeout,
  CMD_run_as_user,
  CMD__end
};

int conf_handler(struct conf_cmd *cmd, char *arg);
static struct conf_cmd conf_commands[] = {
  { CMD_address,       "address",       CONF_NEED_ARG, 1, conf_handler, "%s=<ip address>" },
  { CMD_daemon,        "daemon",        CONF_NO_ARG,   1, conf_handler, "%s" },
  { CMD_debug,         "debug",         CONF_NO_ARG,   1, conf_handler, "%s" },
  { CMD_foreground,    "foreground",    CONF_NO_ARG,   1, conf_handler, "%s" },
  { CMD_host,          "host",          CONF_NEED_ARG, 1, conf_handler, "%s=<host>" },
  { CMD_interface,     "interface",     CONF_NEED_ARG, 1, conf_handler, "%s=<interface>" },
  { CMD_mx,            "mx",            CONF_NEED_ARG, 1, conf_handler, "%s=<mail exchanger>" },
  { CMD_retrys,        "retrys",        CONF_NEED_ARG, 1, conf_handler, "%s=<number of trys>" },
  { CMD_server,        "server",        CONF_NEED_ARG, 1, conf_handler, "%s=<server name>" },
  { CMD_timeout,       "timeout",       CONF_NEED_ARG, 1, conf_handler, "%s=<sec.millisec>" },
  { CMD_period,        "period",        CONF_NEED_ARG, 1, conf_handler, "%s=<time between update attempts>" },
  { CMD_url,           "url",           CONF_NEED_ARG, 1, conf_handler, "%s=<url>" },
  { CMD_user,          "user",          CONF_NEED_ARG, 1, conf_handler, "%s=<user name>[:password]" },
  { CMD_run_as_user,   "run-as-user",   CONF_NEED_ARG, 1, conf_handler, "%s=<user>" },
  { CMD_wildcard,      "wildcard",      CONF_NO_ARG,   1, conf_handler, "%s" },
  { CMD_quiet,         "quiet",         CONF_NO_ARG,   1, conf_handler, "%s" },
  { 0, 0, 0, 0, 0 }
};

/**************************************************/

void print_useage( void );
void print_version( void );
void parse_args( int argc, char **argv );
int do_connect(int *sock, char *host, char *port);
void base64Encode(char *intext, char *output);
int main( int argc, char **argv );

/**************************************************/

void print_useage( void )
{
  fprintf(stdout, "useage: ");
  fprintf(stdout, "%s [options] \n\n", program_name);
  fprintf(stdout, " Options are:\n");
  fprintf(stdout, "  -a, --address <ip address>\tstring to send as your ip address\n");
  fprintf(stdout, "  -c, --config_file <file>\tconfiguration file, almost all arguments can be\n");
  fprintf(stdout, "\t\t\t\tgiven with: <name>[=<value>]\n\t\t\t\tto see a list of possible config commands\n");
  fprintf(stdout, "\t\t\t\ttry \"echo help | %s -c -\"\n", program_name);
  fprintf(stdout, "  -d, --daemon\t\t\trun as a daemon periodicly updating if necessary\n");
#ifdef DEBUG
  fprintf(stdout, "  -D, --debug\t\t\tturn on debuggin\n");
#endif
  fprintf(stdout, "  -f, --foreground\t\twhen running as a daemon run in the foreground\n");
  fprintf(stdout, "  -h, --host <host>\t\tstring to send as host parameter\n");
  fprintf(stdout, "  -i, --interface <iface>\twhich interface to use, the default is %s\n\t\t\t\tbut a common one to use would be ppp0\n", DEFAULT_IF);
  fprintf(stdout, "  -m, --mx <mail exchange>\tstring to send as your mail exchange\n");
  fprintf(stdout, "  -P, --period <# of sec>\tperiod to check IP in daemon \n\t\t\t\tmode (default: 1800 seconds)\n");
  fprintf(stdout, "  -r, --retrys <num>\t\tnumber of trys (default: 1)\n");
  fprintf(stdout, "  -R, --run-as-user <user>\tchange to <user> for running, be ware\n\t\t\t\tthat this can cause problems with handeling\n\t\t\t\tSIGHUP properly if that user can't read the\n\t\t\t\tconfig file\n");
  fprintf(stdout, "  -s, --server <server[:port]>\tthe server to connect to\n");
  fprintf(stdout, "  -t, --timeout <sec.millisec>\tthe amount of time to wait on I/O\n");
  fprintf(stdout, "  -U, --url <url>\t\tstring to send as the url parameter\n");
  fprintf(stdout, "  -u, --user <user[:passwd]>\tuser ID and password, if either is left blank \n\t\t\t\tthey will be prompted for\n");
  fprintf(stdout, "  -w, --wildcard\t\tset your domain to have a wildcard alias\n");
  fprintf(stdout, "      --help\t\t\tdisplay this help and exit\n");
  fprintf(stdout, "      --version\t\t\toutput version information and exit\n");
  fprintf(stdout, "      --credits\t\t\tprint the credits and exit\n");
  fprintf(stdout, "\n");
}

void print_version( void )
{
  fprintf(stdout, "%s: - %s - $Id: ez-ipupdate.c,v 1.4 1999/04/21 03:12:26 amackay Exp $\n", program_name, VERSION);
}

void print_credits( void )
{
  fprintf( stdout, "AUTHORS / CONTRIBUTORS\n"
      "  Angus Mackay <amackay@gus.ml.org>\n"
      "\n" );
}

#if HAVE_SIGNAL_H
RETSIGTYPE sigint_handler(int sig)
{
  char message[] = "interupted.\n";
  close(client_sockfd);
  write(2, message, sizeof(message)-1);
  exit(0);
}
RETSIGTYPE generic_sig_handler(int sig)
{
  last_sig = sig;
}
#endif

int option_handler(int id, char *optarg)
{
#if HAVE_PWD_H && HAVE_GRP_H
  struct passwd *pw;
#endif
  char *tmp;
  int i;

  switch(id)
  {
    case CMD_address:
      if(address) { free(address); }
      address = strdup(optarg);
      dprintf((stderr, "address: %s\n", address));
      break;

    case CMD_daemon:
      options |= OPT_DAEMON;
      dprintf((stderr, "daemon mode\n"));
      break;

    case CMD_debug:
#ifdef DEBUG
      options |= OPT_DEBUG;
      dprintf((stderr, "debugging on\n"));
#else
      fprintf(stderr, "debugging was not enabled at compile time\n");
#endif
      break;

    case CMD_foreground:
      options |= OPT_FOREGROUND;
      dprintf((stderr, "fork()ing off\n"));
      break;

    case CMD_host:
      if(host) { free(host); }
      host = strdup(optarg);
      dprintf((stderr, "host: %s\n", host));
      break;

    case CMD_interface:
      if(interface) { free(interface); }
      interface = strdup(optarg);
      dprintf((stderr, "interface: %s\n", interface));
      break;

    case CMD_mx:
      if(mx) { free(mx); }
      mx = strdup(optarg);
      dprintf((stderr, "mx: %s\n", mx));
      break;

    case CMD_period:
      update_period = atoi(optarg);
      dprintf((stderr, "update_period: %d\n", update_period));
      break;

    case CMD_quiet:
      options |= OPT_QUIET;
      dprintf((stderr, "quiet mode\n"));
      break;

    case CMD_retrys:
      ntrys = atoi(optarg);
      dprintf((stderr, "ntrys: %d\n", ntrys));
      break;

    case CMD_server:
      if(server) { free(server); }
      server = strdup(optarg);
      tmp = strchr(server, ':');
      if(tmp)
      {
        *tmp++ = '\0';
        if(port) { free(port); }
        port = strdup(tmp);
      }
      dprintf((stderr, "server: %s\n", server));
      dprintf((stderr, "port: %s\n", port));
      break;

    case CMD_user:
      strncpy(user, optarg, sizeof(user));
      user[sizeof(user)-1] = '\0';
      dprintf((stderr, "user: %s\n", user));
      tmp = strchr(optarg, ':');
      if(tmp)
      {
        tmp++;
        while(*tmp) { *tmp++ = '*'; }
      }
      break;

    case CMD_run_as_user:
#if HAVE_PWD_H && HAVE_GRP_H
      if((pw=getpwnam(optarg)) == NULL)
      {
        i = atoi(optarg);
      }
      else
      {
        if(setgid(pw->pw_gid) != 0)
        {
          fprintf(stderr, "error changing group id\n");
        }
        dprintf((stderr, "GID now %d\n", pw->pw_gid));
        i = pw->pw_uid;
      }
      if(setuid(i) != 0)
      {
        fprintf(stderr, "error changing user id\n");
      }
      dprintf((stderr, "UID now %d\n", i));
#else
      fprintf(stderr, "option \"daemon-user\" not supported on this system\n");
#endif
      break;

    case CMD_url:
      if(url) { free(url); }
      url = strdup(optarg);
      dprintf((stderr, "url: %s\n", url));
      break;

    case CMD_wildcard:
      if(wildcard) { free(wildcard); }
      wildcard = strdup("yes");
      dprintf((stderr, "wildcard: %s\n", wildcard));
      break;

    case CMD_timeout:
      timeout.tv_sec = atoi(optarg);
      timeout.tv_usec = (atof(optarg) - timeout.tv_sec) * 1000000L;
      dprintf((stderr, "timeout: %ld.%06ld\n", timeout.tv_sec, timeout.tv_usec));
      break;

    default:
      dprintf((stderr, "case not handled: %d\n", id));
      break;
  }

  return 0;
}

int conf_handler(struct conf_cmd *cmd, char *arg)
{
  return(option_handler(cmd->id, arg));
}


#ifdef HAVE_GETOPT_LONG
#  define xgetopt( x1, x2, x3, x4, x5 ) getopt_long( x1, x2, x3, x4, x5 )
#else
#  define xgetopt( x1, x2, x3, x4, x5 ) getopt( x1, x2, x3 )
#endif

void parse_args( int argc, char **argv )
{
#ifdef HAVE_GETOPT_LONG
  struct option long_options[] = {
      {"address",       required_argument,      0, 'a'},
      {"config_file",   required_argument,      0, 'c'},
      {"daemon",        no_argument,            0, 'd'},
      {"debug",         no_argument,            0, 'D'},
      {"foreground",    no_argument,            0, 'f'},
      {"host",          required_argument,      0, 'h'},
      {"interface",     required_argument,      0, 'i'},
      {"mx",            required_argument,      0, 'm'},
      {"period",        required_argument,      0, 'P'},
      {"quiet",         no_argument,            0, 'q'},
      {"retrys",        required_argument,      0, 'r'},
      {"run-as-user",   required_argument,      0, 'R'},
      {"server",        required_argument,      0, 's'},
      {"timeout",       required_argument,      0, 't'},
      {"url",           required_argument,      0, 'U'},
      {"user",          required_argument,      0, 'u'},
      {"wildcard",      no_argument,            0, 'w'},
      {"help",          no_argument,            0, 'H'},
      {"version",       no_argument,            0, 'V'},
      {"credits",       no_argument,            0, 'C'},
      {0,0,0,0}
  };
#else
#  define long_options NULL
#endif
  int opt;

  while((opt=xgetopt(argc, argv, "a:c:dDfh:i:m:P:qr:R:s:t:U:u:wHVC", 
          long_options, NULL)) != -1)
  {
    switch (opt)
    {
      case 'a':
        option_handler(CMD_address, optarg);
        break;

      case 'c':
        if(config_file) { free(config_file); }
        config_file = strdup(optarg);
        dprintf((stderr, "config_file: %s\n", config_file));
        if(config_file)
        {
          if(parse_conf_file(config_file, conf_commands) != 0)
          {
            fprintf(stderr, "error parsing config file \"%s\"\n", config_file);
            exit(1);
          }
        }
        break;

      case 'd':
        option_handler(CMD_daemon, optarg);
        break;

      case 'D':
        option_handler(CMD_debug, optarg);
        break;

      case 'f':
        option_handler(CMD_foreground, optarg);
        break;

      case 'h':
        option_handler(CMD_host, optarg);
        break;

      case 'i':
        option_handler(CMD_interface, optarg);
        break;

      case 'm':
        option_handler(CMD_mx, optarg);
        break;

      case 'P':
        option_handler(CMD_period, optarg);
        break;

      case 'q':
        option_handler(CMD_quiet, optarg);
        break;

      case 'r':
        option_handler(CMD_retrys, optarg);
        break;

      case 'R':
        option_handler(CMD_run_as_user, optarg);
        break;

      case 's':
        option_handler(CMD_server, optarg);
        break;

      case 't':
        option_handler(CMD_timeout, optarg);
        break;

      case 'u':
        option_handler(CMD_user, optarg);
        break;

      case 'U':
        option_handler(CMD_url, optarg);
        break;

      case 'w':
        option_handler(CMD_wildcard, optarg);
        break;

      case 'H':
        print_useage();
        exit(0);
        break;

      case 'V':
        print_version();
        exit(0);
        break;

      case 'C':
        print_credits();
        exit(0);
        break;

      default:
#ifdef HAVE_GETOPT_LONG
        fprintf(stderr, "Try `%s --help' for more information\n", argv[0]);
#else
        fprintf(stderr, "Try `%s -H' for more information\n", argv[0]);
        fprintf(stderr, "warning: this program was compilied without getopt_long\n");
        fprintf(stderr, "         as such all long options will not work!\n");
#endif
        exit(1);
        break;
    }
  }
}

/*
 * do_connect
 *
 * connect a socket and return the file descriptor
 *
 */
int do_connect(int *sock, char *host, char *port)
{
  struct sockaddr_in address;
  int len;
  int result;
  struct hostent *hostinfo;
  struct servent *servinfo;

  // set up the socket
  *sock = socket(AF_INET, SOCK_STREAM, 0);
  address.sin_family = AF_INET;

  // get the host address
  hostinfo = gethostbyname(host);
  if(!hostinfo)
  {
    if(!(options & OPT_QUIET))
    {
      herror("gethostbyname");
    }
    return(-1);
  }
  address.sin_addr = *(struct in_addr *)*hostinfo -> h_addr_list;

  // get the host port
  servinfo = getservbyname(port, "tcp");
  if(servinfo)
  {
    address.sin_port = servinfo -> s_port;
  }
  else
  {
    address.sin_port = htons(atoi(port));
  }


  // connect the socket
  len = sizeof(address);
  result = connect(*sock, (struct sockaddr *)&address, len);

  if(result == -1) {
    if(!(options & OPT_QUIET))
    {
      perror("connect");
    }
    return(-1);
  }

  // print out some info
  if(!(options & OPT_QUIET))
  {
    fprintf(stderr,
        "connected to %s (%s) on port %d.\n",
        host,
        inet_ntoa(address.sin_addr),
        ntohs(address.sin_port));
  }

  return 0;
}

static char table64[]=
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
void base64Encode(char *intext, char *output)
{
  unsigned char ibuf[3];
  unsigned char obuf[4];
  int i;
  int inputparts;

  while(*intext) {
    for (i = inputparts = 0; i < 3; i++) { 
      if(*intext) {
        inputparts++;
        ibuf[i] = *intext;
        intext++;
      }
      else
        ibuf[i] = 0;
    }

    obuf [0] = (ibuf [0] & 0xFC) >> 2;
    obuf [1] = ((ibuf [0] & 0x03) << 4) | ((ibuf [1] & 0xF0) >> 4);
    obuf [2] = ((ibuf [1] & 0x0F) << 2) | ((ibuf [2] & 0xC0) >> 6);
    obuf [3] = ibuf [2] & 0x3F;

    switch(inputparts) {
      case 1: /* only one byte read */
        sprintf(output, "%c%c==", 
            table64[obuf[0]],
            table64[obuf[1]]);
        break;
      case 2: /* two bytes read */
        sprintf(output, "%c%c%c=", 
            table64[obuf[0]],
            table64[obuf[1]],
            table64[obuf[2]]);
        break;
      default:
        sprintf(output, "%c%c%c%c", 
            table64[obuf[0]],
            table64[obuf[1]],
            table64[obuf[2]],
            table64[obuf[3]] );
        break;
    }
    output += 4;
  }
  *output=0;
}

void output(void *buf)
{
  fd_set writefds;
  int max_fd;
  struct timeval tv;
  int ret;

  // set up our fdset and timeout
  FD_ZERO(&writefds);
  FD_SET(client_sockfd, &writefds);
  max_fd = client_sockfd;
  memcpy(&tv, &timeout, sizeof(struct timeval));

  ret = select(max_fd + 1, NULL, &writefds, NULL, &tv);
  dprintf((stderr, "ret: %d\n", ret));

  if(ret == -1)
  {
    dprintf((stderr, "select: %s\n", error_string));
  }
  else if(ret == 0)
  {
    fprintf(stderr, "timeout\n");
  }
  else
  {
    /* if we woke up on client_sockfd do the data passing */
    if(FD_ISSET(client_sockfd, &writefds))
    {
      if(send(client_sockfd, buf, strlen(buf), 0) == -1)
      {
        fprintf(stderr, "error send()ing request\n");
      }
    }
    else
    {
      dprintf((stderr, "error: case not handled."));
    }
  }
}

int read_input(void *buf, int len)
{
  fd_set readfds;
  int max_fd;
  struct timeval tv;
  int ret;
  int bread;

  // set up our fdset and timeout
  FD_ZERO(&readfds);
  FD_SET(client_sockfd, &readfds);
  max_fd = client_sockfd;
  memcpy(&tv, &timeout, sizeof(struct timeval));

  ret = select(max_fd + 1, &readfds, NULL, NULL, &tv);
  dprintf((stderr, "ret: %d\n", ret));

  if(ret == -1)
  {
    dprintf((stderr, "select: %s\n", error_string));
  }
  else if(ret == 0)
  {
    fprintf(stderr, "timeout\n");
  }
  else
  {
    /* if we woke up on client_sockfd do the data passing */
    if(FD_ISSET(client_sockfd, &readfds))
    {
      if((bread=recv(client_sockfd, buf, len, 0)) == -1)
      {
        fprintf(stderr, "error send()ing request\n");
      }
    }
    else
    {
      dprintf((stderr, "error: case not handled."));
    }
  }

  return(bread);
}

#ifdef IF_LOOKUP
int get_if_addr(int sock, char *name, struct sockaddr_in *sin)
{
  struct ifreq ifr;

  memset(&ifr, 0, sizeof(ifr));
  strcpy(ifr.ifr_name, name);
  /* why does this need to be done twice? */
  if(ioctl(sock, SIOCGIFADDR, &ifr) < 0) 
  { 
    perror("ioctl(SIOCGIFADDR)"); 
    memset(sin, 0, sizeof(struct sockaddr_in));
    dprintf((stderr, "%s: %s\n", name, "unknown interface"));
    return -1;
  }
  if(ioctl(sock, SIOCGIFADDR, &ifr) < 0)
  { 
    perror("ioctl(SIOCGIFADDR)"); 
    memset(sin, 0, sizeof(struct sockaddr_in));
    dprintf((stderr, "%s: %s\n", name, "unknown interface"));
    return -1;
  }

  if(ifr.ifr_addr.sa_family == AF_INET)
  {
    memcpy(sin, &(ifr.ifr_addr), sizeof(struct sockaddr_in));
    dprintf((stderr, "%s: %s\n", name, inet_ntoa(sin->sin_addr)));
    return 0;
  }
  else
  {
    memset(sin, 0, sizeof(struct sockaddr_in));
    dprintf((stderr, "%s: %s\n", name, "could not resolve"));
    return -1;
  }
  return -1;
}
#endif

int update_entry(void)
{
  char buf[BUFFER_SIZE];
  char *bp = buf;
  int bytes;
  int btot;
  int ret;

  if(do_connect((int*)&client_sockfd, server, port) != 0)
  {
    if(!(options & OPT_QUIET))
    {
      fprintf(stderr, "error connecting to %s:%s\n", server, port);
    }
    close(client_sockfd);
    return(-1);
  }

  snprint(buf, BUFFER_SIZE, "GET %s?mode=update&", request);
  output(buf);
  snprint(buf, BUFFER_SIZE, "%s=%s&", "ipaddress", address);
  output(buf);
  snprint(buf, BUFFER_SIZE, "%s=%s&", "wildcard", wildcard);
  output(buf);
  snprint(buf, BUFFER_SIZE, "%s=%s&", "mx", mx);
  output(buf);
  snprint(buf, BUFFER_SIZE, "%s=%s&", "url", url);
  output(buf);
  snprint(buf, BUFFER_SIZE, "%s=%s&", "host", host);
  output(buf);
  snprint(buf, BUFFER_SIZE, " HTTP/1.0\015\012");
  output(buf);
  snprint(buf, BUFFER_SIZE, "Authorization: Basic %s\015\012", auth);
  output(buf);
  snprint(buf, BUFFER_SIZE, "User-Agent: %s-%s %s (%s)\015\012", 
      "ez-update", VERSION, OS, "by Angus Mackay");
  output(buf);
  snprint(buf, BUFFER_SIZE, "Host: %s\015\012", server);
  output(buf);
  snprint(buf, BUFFER_SIZE, "\015\012");
  output(buf);

  bp = buf;
  bytes = 0;
  btot = 0;
  while((bytes=read_input(bp, BUFFER_SIZE-btot)) > 0)
  {
    bp += bytes;
    btot += bytes;
    dprintf((stderr, "btot: %d\n", btot));
  }
  close(client_sockfd);
  buf[btot] = '\0';

  dprintf((stderr, "server output: %s\n", buf));

  if(sscanf(buf, " HTTP/1.%*c %3d", &ret) != 1)
  {
    ret = -1;
  }

  switch(ret)
  {
    case -1:
      if(!(options & OPT_QUIET))
      {
        fprintf(stderr, "strange server response, are you connecting to the right server?\n");
      }
      return(-1);
      break;

    case 200:
      if(!(options & OPT_QUIET))
      {
        printf("request successful\n");
      }
      break;

    case 401:
      if(!(options & OPT_QUIET))
      {
        fprintf(stderr, "authentication failure\n");
      }
      return(-1);
      break;

    default:
      if(!(options & OPT_QUIET))
      {
        // reuse the auth buffer
        *auth = '\0';
        sscanf(buf, " HTTP/1.%*c %*3d %255[^\r\n]", auth);
        fprintf(stderr, "unknown return code: %d\n", ret);
        fprintf(stderr, "server response: %s\n", auth);
      }
      return(-1);
      break;
  }

  return 0;
}

void handle_sig(int sig)
{
  switch(sig)
  {
    case SIGHUP:
      if(config_file)
      {
#if HAVE_SYSLOG_H
        syslog(LOG_NOTICE, "SIGHUP recieved, re-reading config file\n");
#else
        fprintf(stderr, "SIGHUP recieved, re-reading config file\n");
#endif
        if(parse_conf_file(config_file, conf_commands) != 0)
        {
#if HAVE_SYSLOG_H
          syslog(LOG_NOTICE, "error parsing config file \"%s\"\n", config_file);
#else
          fprintf(stderr, "error parsing config file \"%s\"\n", config_file);
#endif
        }
      }
      break;
    case SIGTERM:
      /* 
       * this is used to wake up the client so that it will perform an update 
       */
      break;
    case SIGQUIT:
#if HAVE_SYSLOG_H
      syslog(LOG_NOTICE, "received SIGQUIT, shutting down\n");
      closelog();
      exit(0);
#else
      fprintf(stderr, "received SIGQUIT, shutting down\n");
      exit(0);
#endif
    default:
      dprintf((stderr, "case not handled: %d\n", sig));
      break;
  }
}

int main( int argc, char **argv )
{
  char user_name[128];
  char password[128];
  int ifresolve_warned = 0;
  int i;
#ifdef IF_LOOKUP
  int sock = -1;
  struct sockaddr_in sin;
  struct sockaddr_in sin2;
#endif

  dprintf((stderr, "staring...\n"));

  program_name = argv[0];
  options = 0;
  *user = '\0';
  timeout.tv_sec = DEFAULT_TIMEOUT;
  timeout.tv_usec = 0;

#if HAVE_SIGNAL_H
  // catch user interupts
  signal(SIGINT,  sigint_handler);
  signal(SIGHUP,  generic_sig_handler);
  signal(SIGTERM, generic_sig_handler);
  signal(SIGQUIT, generic_sig_handler);
#endif

  parse_args(argc, argv);

  if(!(options & OPT_QUIET) && !(options & OPT_DAEMON))
  {
    fprintf(stderr, "ez-ipupdate Version %s\nCopyright (C) 1999 Angus Mackay.\n", VERSION);
  }

  dprintf((stderr, "options: 0x%04X\n", options));
  dprintf((stderr, "interface: %s\n", interface));
  dprintf((stderr, "ntrys: %d\n", ntrys));
  dprintf((stderr, "server: %s:%s\n", server, port));

  dprintf((stderr, "address: %s\n", address));
  dprintf((stderr, "wildcard: %s\n", wildcard));
  dprintf((stderr, "mx: %s\n", mx));
  dprintf((stderr, "auth: %s\n", auth));

#ifdef IF_LOOKUP
  if(options & OPT_DAEMON)
  {
    sock = socket(AF_INET, SOCK_STREAM, 0);
  }
#endif

  if(server == NULL)
  {
    server = strdup(DEFAULT_SERVER);
  }
  if(port == NULL)
  {
    port = strdup(DEFAULT_PORT);
  }

  *user_name = '\0';
  *password = '\0';
  if(*user != '\0')
  {
    sscanf(user, "%127[^:]:%127[^\n]", user_name, password);
    dprintf((stderr, "user_name: %s\n", user_name));
    dprintf((stderr, "password: %s\n", password));
  }
  if(*user_name == '\0')
  {
    printf("user name: ");
    fgets(user_name, 127, stdin);
    user_name[strlen(user_name)-1] = '\0';
  }
  if(*password == '\0')
  {
    strncpy(password, getpass("password: "), sizeof(password));
  }
  sprintf(user, "%s:%s", user_name, password);

  base64Encode(user, auth);

  request = strdup(REQUEST);

  if(interface == NULL) { interface = strdup(DEFAULT_IF); }

  if(address == NULL) { address = strdup(""); }
  if(wildcard == NULL) { wildcard = strdup("no"); }
  if(mx == NULL) { mx = strdup(""); }
  if(url == NULL) { url = strdup(""); }
  if(host == NULL) { host = strdup(""); }

  if(options & OPT_DAEMON)
  {
#if IF_LOOKUP
    /* background our selves */
    if(!(options & OPT_FOREGROUND))
    {
#  if HAVE_SYSLOG_H
      close(0);
      close(1);
      close(2);
#  endif
      if(fork() > 0) { exit(0); } /* parent */
    }

#  if HAVE_SYSLOG_H
    openlog(program_name, LOG_PID, LOG_USER );
    syslog(LOG_NOTICE, "ez-ipupdate Version %s, Copyright (C) 1999 Angus Mackay.\n", 
        VERSION);
    syslog(LOG_NOTICE, "%s started for interface %s using server %s\n",
        program_name, interface, server);
    options |= OPT_QUIET;
#  endif
    memset(&sin, 0, sizeof(sin));

    for(;;)
    {
#if HAVE_SIGNAL_H
      /* check for signals */
      if(last_sig != 0)
      {
        handle_sig(last_sig);
        last_sig = 0;
      }
#endif
      if(get_if_addr(sock, interface, &sin2) == 0)
      {
        ifresolve_warned = 0;
        if(memcmp(&sin, &sin2, sizeof(sin)) != 0)
        {
          memcpy(&sin, &sin2, sizeof(sin));

          if(update_entry() == 0)
          {
#  if HAVE_SYSLOG_H
            syslog(LOG_NOTICE, "successful update for %s->%s\n",
                interface, inet_ntoa(sin.sin_addr));
#  else
            fprintf(stderr, "successful update for %s->%s\n",
                interface, inet_ntoa(sin.sin_addr));
#  endif
          }
          else
          {
#  if HAVE_SYSLOG_H
            syslog(LOG_NOTICE, "failure to update %s->%s\n",
                interface, inet_ntoa(sin.sin_addr));
#  else
            fprintf(stderr, "failure to update %s->%s\n",
                interface, inet_ntoa(sin.sin_addr));
#  endif
            memset(&sin, 0, sizeof(sin));
          }
        }
      }
      else
      {
        if(!ifresolve_warned)
        {
          ifresolve_warned = 1;
#  if HAVE_SYSLOG_H
          syslog(LOG_NOTICE, "unable to resolve interface %s\n",
              interface);
#  else
          fprintf(stderr, "unable to resolve interface %s\n",
              interface);
#  endif
        }
      }
      sleep(update_period);
    }
#else
    fprintf(stderr, "sorry, this mode is only available on platforms that the ");
    fprintf(stderr, "IP address \ncan be determined. feel free to hack the code");
    fprintf(stderr, " though.\n");
    exit(1);
#endif
  }
  else
  {
    for(i=0; i<ntrys; i++)
    {
      if(update_entry() == 0)
      {
        break;
      }
      if(i+1 != ntrys) { sleep(1); }
    }
    return 1;
  }

  if(address) { free(address); }
  if(config_file) { free(config_file); }
  if(host) { free(host); }
  if(interface) { free(interface); }
  if(mx) { free(mx); }
  if(port) { free(port); }
  if(request) { free(request); }
  if(server) { free(server); }
  if(url) { free(url); }
  if(wildcard) { free(wildcard); }

  dprintf((stderr, "done\n"));
  return 0;
}

