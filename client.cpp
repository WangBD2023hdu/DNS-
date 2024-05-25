#include <stdio.h>
#include <stdlib.h>

#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <unistd.h>

#include <string.h>

#include <sys/socket.h>
#include <time.h>

#include <arpa/inet.h>
#include "dns_protocol.h"
int dns_server_port = 53;

void init_header(struct DNS_HEADER *header) {
  bzero(header, sizeof(struct DNS_HEADER));
  srandom(time(NULL));
  header->id = random();
  header->rd = 0;  // TODO
  header->q_count = htons(1);
}

int send_query(int sockfd, const char *domain, sockaddr_in *servaddr) {
  char buf[65535];
  bzero(buf, 65535);
  struct DNS_HEADER header;
  init_header(&header);
  mempcpy(buf, &header, sizeof(header));

  struct QUESTION question;
  question.qtype = htons(1);
  question.qclass = htons(1);

  char netdomian[256];
  bzero(netdomian, 256);
  int offset = 0;
  char *hostname_dup = strdup(domain);      // strdup --> malloc
  char *token = strtok(hostname_dup, ".");  // www.0voice.com ,token的结果是www
  while (token != NULL) {
    size_t len = strlen(token);
    *(netdomian + offset) = len;
    offset++;
    strncpy(netdomian + offset, token,
            len + 1);  // len+1是由于qname的最后必须以0结尾
    offset += len;
    // strtok不是线程安全的，要由前面的截取后再次截取
    token = strtok(NULL, ".");  // 0voice.com ,  com
  }
  free(hostname_dup);
  printf("len %lu\n", strlen(netdomian));
  QUERY query;
  bzero(&query, sizeof(query));
  query.name = (unsigned char *)netdomian;
  query.ques = &question;
  memcpy(buf + sizeof(header), netdomian, strlen(netdomian));
  memcpy(buf + sizeof(header) + strlen(netdomian) + 1, &question,
         sizeof(question));
  size_t buflen = sizeof(header) + strlen(netdomian) + 1 + sizeof(question);
  if (sendto(sockfd, buf,
             sizeof(header) + strlen(netdomian) + 1 + sizeof(question), 0,
             (sockaddr *)servaddr, sizeof(sockaddr_in)) < 0) {
    perror("send failure!");
    return -1;
  }

  return buflen;
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    printf("please input domain!\n");
    return -1;
  }
  (void)argc;
  (void)argv;
  char domain[256];
  bzero(domain, 256);
  struct hostent *server = NULL;
  if (argc >= 2) {
    strcpy(domain, argv[1]);
  }
  if (argc >= 3) {
    server = gethostbyname(argv[2]);  // TODO
  } else {
    server = gethostbyname("localhost");
  }
  if (argc == 4) {
    dns_server_port = atoi(argv[3]);
  }

  int sockfd = socket(AF_INET, SOCK_DGRAM, 0);  // UDP
  if (sockfd < 0) {
    return -1;
  }
  struct sockaddr_in servaddr;
  bzero(&servaddr, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_port = htons(dns_server_port);
  bcopy(server->h_addr, (char *)&servaddr.sin_addr.s_addr,
        (size_t)server->h_length);
  printf("%s\n", server->h_addr);
  int sendlen;
  if ((sendlen = send_query(sockfd, domain, &servaddr)) == -1) {
    exit(1);
  }
  printf("send success!\n");

  char revbuf[65535];
  bzero(revbuf, 65535);
  socklen_t len = sizeof(servaddr);
  int relen = recvfrom(sockfd, (char *)revbuf, 65535, 0,
                       (struct sockaddr *)&servaddr, (socklen_t *)&len);
  if (relen < 0) {
    perror("erroe");
    exit(1);
  }
  printf("recv response!\n");
  struct DNS_HEADER *respondheader;
  respondheader = (struct DNS_HEADER *)revbuf;
  printf("id %u qu count %d ans cout %u\n:", ntohs(respondheader->id),
         ntohs(respondheader->q_count), ntohs(respondheader->ans_count));
  char *readbuf = revbuf + sendlen;

  struct RES_RECORD answer[30];
  answer[0].resource = (struct R_DATA *)(readbuf + 2);
  answer[0].rdata =
      (unsigned char *)malloc(ntohs(answer[0].resource->data_len) + 1);

  struct sockaddr_in addres;
  if (ntohs(answer[0].resource->type) == T_A) {
    printf("ttl:%d\n", ntohs(answer[0].resource->ttl));
    memcpy(answer[0].rdata, (revbuf + sendlen + 2 + sizeof(struct R_DATA)),
           ntohs(answer[0].resource->data_len));
    answer[0].rdata[ntohs(answer[0].resource->data_len)] = '\0';
    char ip[20];
    inet_ntop(AF_INET, answer[0].rdata, ip, sizeof(struct sockaddr));
    addres.sin_addr.s_addr = (long)answer[0].rdata;
    printf("%d", ntohs(answer[0].resource->data_len));
    printf("send %u ip:%s\n", ntohs(answer[0].resource->data_len), ip);
  }

  return 0;
}
