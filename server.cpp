#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "dns_protocol.h"

int dns_port = 53;

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;
  if (argc == 2) {
    dns_port = atoi(argv[1]);
  }

  int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (sockfd < 0) {
    perror("socket");
    exit(EXIT_FAILURE);
  }

  // 绑定UDP套接字
  struct sockaddr_in server_addr;
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(dns_port);
  server_addr.sin_addr.s_addr = INADDR_ANY;

  if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
    perror("bind failure");
    exit(EXIT_FAILURE);
  }

  while (1) {
    struct sockaddr_in clientaddr;
    bzero(&clientaddr, sizeof(clientaddr));
    socklen_t addrLen = sizeof(clientaddr);
    char recvbuf[65536];
    bzero(recvbuf, 65536);
    int nrec = recvfrom(sockfd, recvbuf, 65536, 0,
                        (struct sockaddr *)&clientaddr, &addrLen);
    if (nrec < 0) {
      perror("recvfrom failure, continue ....");
      continue;
    }
    printf("recv query succes\n");

    struct DNS_HEADER *clientHeader = (struct DNS_HEADER *)recvbuf;
    int domainLen = 0;
    while (*(recvbuf + sizeof(struct DNS_HEADER) + domainLen) != '\0') {
      domainLen++;
    }
    printf("doamin :%s\n", recvbuf + sizeof(struct DNS_HEADER));
    int offset = 0;
    if (domainLen == 0) {
      domainLen = 1;
      offset -= 1;
    }
    clientHeader->aa = 1;
    clientHeader->qr = 1;
    clientHeader->ra = 1;
    clientHeader->ans_count = htons(1);
    clientHeader->add_count = htons(0);
    offset +=
        sizeof(struct DNS_HEADER) + domainLen + 1 + sizeof(struct QUESTION);
    uint16_t domain_offset = htons(0xc00c);
    memcpy(recvbuf + offset, &domain_offset, 2);
    offset += 2;
    printf("len %d \n", domainLen);
    struct R_DATA returnData;
    returnData.type = htons(T_A);
    returnData._class = htons(1);
    returnData.ttl = htons(600);
    returnData.data_len = htons(4);
    memcpy(recvbuf + offset, &returnData, sizeof(returnData));
    offset += sizeof(returnData);

    char resdata[4];
    bzero(resdata, 4);
    if (domainLen == 20) {
      domainLen = 5;
    }
    char dat = domainLen;
    memcpy(resdata + 3, &dat, 1);
    memcpy(recvbuf + offset, resdata, 4);
    offset += 4;

    // 发送DNS响应报文
    int nsent = sendto(sockfd, recvbuf, offset, 0,
                       (struct sockaddr *)&clientaddr, addrLen);
    if (nsent < 0) {
      perror("sendto");
      continue;
    }
  }

  close(sockfd);

  return 0;
}
