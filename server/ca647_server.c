/* The vulnerable server */
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <netdb.h>
#include <time.h>

#define	PORTNUM	8001
#define	BLENGTH	256
#define	ALENGTH	128

static int
read_command(int s, char *buffer, char *response)
{
  char *p = "Please select an option:\n1. Time\n2. Date\n";
  char *e = ", is not a valid option.\n";
  char *c;
  int x;

  /* Construct prompt */
  snprintf(buffer, BLENGTH, p); /* XXX : format string misuse (potentially unsecure) */

  /* Prompt until valid response */
  for (;;) {

    /* Send prompt */
    send(s, (void *)buffer, BLENGTH, 0);

    /* Receive response */
    recv(s, (void *)response, BLENGTH, 0);

    /* Remove trailing '\n' */
    c = response + strlen(response) - 1;
    *c = '\0';

    /* Extract integer */
    x = strtol(response, NULL, 10);

    /* Done if valid */
    if (x == 1 || x == 2) {
      return (x);
    }

    /* Otherwise construct new prompt */
    snprintf(buffer, BLENGTH, response); /* XXX : format string vulnerability */
    strncat(buffer, e, BLENGTH);
    strncat(buffer, p, BLENGTH);
  }
}

static void
execute_command(int s, unsigned int x, char *buffer, char *answer)
{
  time_t curtime;
  struct tm *loctime;

  /* Get the time/date */
  curtime = time(NULL);
  loctime = localtime(&curtime);

  /* Put time/date in buffer */
  if (x == 1) {
    strftime(buffer, BLENGTH, "The time is %I:%M %p\n", loctime);
  } else {
    strftime(buffer, BLENGTH, "Today is %A, %B %d\n", loctime);
  }

  /* Append question */
  strncat(buffer, "Do you wish to continue? (Y/N)\n", BLENGTH);

  /* Send to client */
  send(s, (void *)buffer, BLENGTH, 0);

  /* Receive reply */
  recv(s, (void *)buffer, BLENGTH, 0);

  /* Make copy */
  strcpy(answer, buffer); /* XXX : stack based buffer overflow vulnerability */
}

static void
handle_it(int s)
{
  char answer[ALENGTH];
  char response[BLENGTH]; /* XXX : uninitialized data */
  char buffer[BLENGTH];
  unsigned int x;

  for (;;) {

    /* Read command code from client */
    x = read_command(s, buffer, response); /* XXX : implicit conversion from int to unsigned int */

    /* Execute the command */
    execute_command(s, x, buffer, answer);

    /* Break if done */
    if (strcmp(answer, "Y\n")) {
      break;
    }
  }
}

void *
handler(void *n)
{
  int s;

  /* Detach */
  pthread_detach(pthread_self());

  /* Cast */
  s = *((int *)n);

  /* Handle and then clean up */
  handle_it(s);
  close(s);
  free(n);

  return ((void *)NULL);
}

int
main(void)
{
  struct sockaddr_in socketname, client;
  struct hostent *host;
  socklen_t clientlen = sizeof (client);
  pthread_t tid;
  int s, n, *c, optval = 1;

  /* Retrieve localhost interface information */
  if ((host = gethostbyname("localhost")) == NULL) {
    perror("gethostbyname()");
    exit(EXIT_FAILURE);
  }

  /* Fill in socket address */
  memset((char *)&socketname, '\0', sizeof (socketname));
  socketname.sin_family = AF_INET;
  socketname.sin_port = htons(PORTNUM);
  memcpy((char *)&socketname.sin_addr, host->h_addr_list[0], host->h_length);

  /* Create an Internet family, stream socket */
  s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0) {
    perror("socket()");
    exit(EXIT_FAILURE);
  }

  /* Allow address reuse if waiting on kernel to clean up */
  if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof (optval)) < 0) {
    perror("setsockopt()");
    exit(EXIT_FAILURE);
  }

  /* Bind address to socket */
  if (bind(s, (struct sockaddr *)&socketname, sizeof (socketname)) < 0) {
    perror("bind()");
    exit(EXIT_FAILURE);
  }

  /* Activate socket */
  if (listen(s, 5)) {
    perror("listen()");
    exit(EXIT_FAILURE);
  }

  /* Loop forever */
  for (;;) {

    /* Accept connection */
    n = accept(s, (struct sockaddr *)&client, &clientlen);
    if (n < 0) {
      perror("accept()");
      exit(EXIT_FAILURE);
    }

    /* Allocate memory for client socket */
    c = malloc(sizeof (*c));
    if (!c) {
      perror("malloc()");
      exit(EXIT_FAILURE);
    }
    *c = n;

    /* Create thread for this client */
    pthread_create(&tid, NULL, handler, (void *)c);		
  }

  /* Close socket */
  close(s); /* XXX : unreachable code */

  return (0);
}
