/* ============================================================================
 * Copyright (C) 1998 Angus Mackay. All rights reserved; 
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
#define PERFERRED_REQUEST "/members/preferred/update/"
#define REQUEST "/members/update/"

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

#if __linux__
#  define IF_LOOKUP 1
#  include <sys/ioctl.h>
#  include <net/if.h>
#endif

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
static int update_peroid = 600;

static volatile int client_sockfd;

static int options;

#define OPT_DEBUG       0x0001
#define OPT_PERFERRED   0x0002
#define OPT_DAEMON      0x0004
#define OPT_QUIET       0x0008
#define OPT_FOREGROUND  0x0010

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
  fprintf(stdout, "  -d, --daemon\t\t\trun as a daemon periodicly updating if necessary\n");
#ifdef DEBUG
  fprintf(stdout, "  -D, --debug\t\t\tturn on debuggin\n");
#endif
  fprintf(stdout, "  -f, --foreground\t\twhen running as a daemon run in the foreground\n");
  fprintf(stdout, "  -h, --host <host>\t\tstring to send as host parameter\n");
  fprintf(stdout, "  -i, --interface <iface>\twhich interface to use, the default is eth0\n\t\t\t\tbut a common one to use would be ppp0\n");
  fprintf(stdout, "  -m, --mx <mail exchange>\tstring to send as your mail exchange\n");
  fprintf(stdout, "  -p, --perferred\t\tconnect to the perferred members server\n");
  fprintf(stdout, "  -P, --period <# of sec>\tperiod to check IP in daemon \n\t\t\t\tmode (default: 600s)\n");
  fprintf(stdout, "  -r, --retrys <num>\t\tnumber of trys (default: 1)\n");
  fprintf(stdout, "  -s, --server <server[:port]>\tthe server to connect to\n");
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
  fprintf(stdout, "%s: - %s - $Id$\n", program_name, VERSION);
}

void print_credits( void )
{
  fprintf( stdout, "AUTHORS / CONTRIBUTORS\n"
      "  Angus Mackay <amackay@gus.ml.org>\n"
      "\n" );
}

#if HAVE_SIGNAL_H
RETSIGTYPE sig_handler(int sig)
{
  char message[] = "interupted.\n";
  close(client_sockfd);
  write(2, message, sizeof(message)-1);
  exit(0);
}
#endif

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
      {"daemon",        no_argument,            0, 'd'},
      {"debug",         no_argument,            0, 'D'},
      {"foreground",    no_argument,            0, 'f'},
      {"host",          required_argument,      0, 'h'},
      {"interface",     required_argument,      0, 'i'},
      {"mx",            required_argument,      0, 'm'},
      {"perferred",     no_argument,            0, 'p'},
      {"period",        required_argument,      0, 'P'},
      {"quiet",         no_argument,            0, 'q'},
      {"retrys",        required_argument,      0, 'r'},
      {"server",        required_argument,      0, 's'},
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
  char *tmp;

  while((opt = xgetopt(argc, argv, "a:dDfh:i:m:pP:qr:s:U:u:wHVC", long_options, NULL)) != -1)
  {
    switch (opt)
    {
      case 'a':
        if(address) { free(address); }
        address = strdup(optarg);
        dprintf((stderr, "address: %s\n", address));
        break;

      case 'd':
        options |= OPT_DAEMON;
        dprintf((stderr, "daemon mode\n"));
        break;

      case 'D':
#ifdef DEBUG
        options |= OPT_DEBUG;
        dprintf((stderr, "debugging on\n"));
#else
        fprintf(stderr, "debugging was not enabled at compile time\n");
#endif
        break;

      case 'f':
        options |= OPT_FOREGROUND;
        dprintf((stderr, "fork()ing off\n"));
        break;

      case 'h':
        if(host) { free(host); }
        host = strdup(optarg);
        dprintf((stderr, "host: %s\n", host));
        break;

      case 'i':
        if(interface) { free(interface); }
        interface = strdup(optarg);
        dprintf((stderr, "interface: %s\n", interface));
        break;

      case 'm':
        if(mx) { free(mx); }
        mx = strdup(optarg);
        dprintf((stderr, "mx: %s\n", mx));
        break;

      case 'P':
        update_peroid = atoi(optarg);
        dprintf((stderr, "update_peroid: %d\n", update_peroid));
        break;

      case 'p':
        options |= OPT_PERFERRED;
        dprintf((stderr, "perferred member\n"));
        break;

      case 'q':
        options |= OPT_QUIET;
        dprintf((stderr, "quiet mode\n"));
        break;

      case 'r':
        ntrys = atoi(optarg);
        dprintf((stderr, "ntrys: %d\n", ntrys));
        break;

      case 's':
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

      case 'u':
        strncpy(user, optarg, sizeof(user));
        user[sizeof(user)-1] = '\0';
        dprintf((stderr, "user: %s\n", user));
        tmp = strchr(optarg, ':');
        if(tmp)
        {
          *tmp++;
          while(*tmp) { *tmp++ = '*'; }
        }
        break;

      case 'U':
        if(url) { free(url); }
        url = strdup(optarg);
        dprintf((stderr, "url: %s\n", url));
        break;

      case 'w':
        if(wildcard) { free(wildcard); }
        wildcard = strdup("yes");
        dprintf((stderr, "wildcard: %s\n", wildcard));
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
  if(send(client_sockfd, buf, strlen(buf), 0) == -1)
  {
    fprintf(stderr, "error send()ing request\n");
  }
}

#ifdef IF_LOOKUP
int get_if_addr(int sock, char *name, struct sockaddr_in *sin)
{
  struct ifreq ifr;
  int i;

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
  while((bytes=recv(client_sockfd, bp, BUFFER_SIZE-btot, 0)) > 0)
  {
    bp += bytes;
    btot += bytes;
    dprintf((stderr, "btot: %d\n", btot));
  }
  close(client_sockfd);

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

int main( int argc, char **argv )
{
  char user_name[128];
  char password[128];
  int ifresolve_warned = 0;
  int i;
#ifdef IF_LOOKUP
  int sock;
  struct sockaddr_in sin;
  struct sockaddr_in sin2;
#endif

  dprintf((stderr, "staring...\n"));

  program_name = argv[0];
  options = 0;
  *user = '\0';

#if HAVE_SIGNAL_H
  // catch user interupts
  signal(SIGINT, sig_handler);
#endif

  parse_args(argc, argv);

  dprintf((stderr, "options: 0x%04X\n", options));
  dprintf((stderr, "interface: %s\n", interface));
  dprintf((stderr, "ntrys: %d\n", ntrys));

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
    sscanf(user, "%127[^:]:%127s", user_name, password);
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

  if(options & OPT_PERFERRED)
  {
    request = strdup(PERFERRED_REQUEST);
  }
  else
  {
    request = strdup(REQUEST);
  }

  if(interface == NULL) { interface = strdup("eth0"); }

  if(address == NULL) { address = strdup(""); }
  if(wildcard == NULL) { wildcard = strdup("no"); }
  if(mx == NULL) { mx = strdup(""); }
  if(url == NULL) { url = strdup(""); }
  if(host == NULL) { host = strdup(""); }

  if(options & OPT_DAEMON)
  {
    pid_t pid;

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
    syslog(LOG_NOTICE, "%s started for interface %s using server %s\n",
        program_name, interface, server);
    options |= OPT_QUIET;
#  endif
    memset(&sin, 0, sizeof(sin));

    for(;;)
    {
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
#  endif
          }
          else
          {
#  if HAVE_SYSLOG_H
            syslog(LOG_NOTICE, "failure to update %s->%s\n",
                interface, inet_ntoa(sin.sin_addr));
#  endif
            memset(&sin, 0, sizeof(sin));
          }
        }
      }
      else
      {
#  if HAVE_SYSLOG_H
        if(!ifresolve_warned)
        {
          ifresolve_warned = 1;
          syslog(LOG_NOTICE, "unable to resolve interface %s\n",
              interface);
        }
#  endif
      }
      sleep(update_peroid);
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

  dprintf((stderr, "done\n"));
  return 0;
}

