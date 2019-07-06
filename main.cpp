#include "stdio.h"
#include "stdlib.h"
#include <pcap.h>
#include <netinet/in.h>
#include <time.h>
#include "string.h"
#include <string>



#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_IPV6 0x86DD
#define ETHERTYPE_PPPOE1 0x8864
#define ETHERTYPE_PPPOE2 0x8863
#define ETHERTYPE_PPP 0x880B
#define PCAP_DATABUF_MAX 65535

using namespace std;

typedef unsigned  char u_int8; //8 bit
typedef unsigned short u_int16; // 16 bit
typedef unsigned  int u_int32;  // 32 bit
typedef unsigned long u_int64;  // 64 bit

//MAC 总长度14字节
typedef struct eth_hdr{
    u_int8 dst_mac[6];
    u_int8 src_mac[6];
    u_int16 eth_type;
} eth_hdr;

//IP 头
typedef struct ip_hdr{
    u_int8 ver_hl;    //版本和头长
    u_int8 serv_type; //服务类型
    u_int16 pkt_len;  //包总长
    u_int16 re_mark;  //重组标志
    u_int16 flag_seg; //标志位和段偏移量
    u_int8 surv_tm;    //生存时间
    u_int8 protocol;  //协议码（判断传输层是哪一个协议）
    u_int16 h_check;  //头检验和
    u_int32 src_ip;   //源ip
    u_int32 dst_ip;   //目的ip
    u_int32 option;   //可选选项
}ip_hdr;

/*UDP头，总长度8个字节*/
typedef struct Udp_hdr{
    u_int16 sport;     //源端口
    u_int16 dport;     //目的端口
    u_int16 pktlen;    //UDP头和数据的总长度
    u_int16 check_sum; //校验和
}Udp_hdr;

/*TCP头,总长度20字节，不包括可选选项*/
typedef struct  Tcp_hdr{
    u_int16 sport;     //源端口
    u_int16 dport;     //目的端口
    u_int32 seq;       //序列号
    u_int32 ack;       //确认序号
    u_int8  head_len;  //头长度
    u_int8  flags;     //保留和标记位
    u_int16 wind_size; //窗口大小
    u_int16 check_sum; //校验和
    u_int16 urgent_p;  //紧急指针
}Tcp_hdr;

typedef struct PPP_hdr{
    u_int8 protocol;

}PPP_hdr;

typedef struct PPPOE_hdr{
    u_int8 version;
    u_int8 VER_CODE;
    u_int16 SESSION_ID;
    u_int16 LENGTH;
    PPP_hdr ppp;
}PPPOE_hdr;

typedef struct RDP_hdr{
    u_int8 flag;
    u_int8 Payload_type;
    u_int16 sequence_number;
    u_int32 Timestamp;
    u_int32 identifier;
}RDP_hdr;


ip_hdr *ip;
Udp_hdr *udp;
Tcp_hdr *tcp;
eth_hdr *ethernet;
PPPOE_hdr *pppoeHdr;
RDP_hdr *rdpHdr;

//解析RDP包头
void parseRDP(const unsigned char *p_packet_content, u_int32 lenth, u_int32 len){
    printf("It's Rdp\n");
    rdpHdr= static_cast<RDP_hdr *>(malloc(sizeof(RDP_hdr)));
    rdpHdr->flag=p_packet_content[lenth++];
    rdpHdr->Payload_type=p_packet_content[lenth++];
    rdpHdr->sequence_number=(p_packet_content[lenth++]<<8)+p_packet_content[lenth++];
    rdpHdr->Timestamp = (p_packet_content[lenth++]<<24)+(p_packet_content[lenth++]<<16)+(p_packet_content[lenth++]<<8)+p_packet_content[lenth++];
    rdpHdr->identifier=(p_packet_content[lenth++]<<24)+(p_packet_content[lenth++]<<16)+(p_packet_content[lenth++]<<8)+p_packet_content[lenth++];
    printf("flag: %d\n",rdpHdr->flag);
    printf("Playload_type: %d\n",rdpHdr->Payload_type);
    printf("sequence-number: %d\n",rdpHdr->sequence_number);
    printf("identifier: %d\n",rdpHdr->identifier);
    FILE *file=fopen("/home/oida/ouput1","ab+");
    if (!file){
        printf("file open fail");
    }
    p_packet_content=p_packet_content+lenth;
    int length=len-lenth;
    char out[length];
    for (int i = 0; i < length; ++i) {
        out[i]=p_packet_content[i];
    }

    fwrite(out, sizeof(char), sizeof(out),file);
    fclose(file);
}

//解析UDP包头
void parseUdpAndIp(const unsigned char *p_packet_content, u_int32 lenth, u_int32 len){

    u_int32 udp_len = sizeof(struct Udp_hdr);// udp头的长度

    udp->sport=(p_packet_content[lenth++]<<8)+p_packet_content[lenth++];
    udp->dport=(p_packet_content[lenth++]<<8)+p_packet_content[lenth++];
    udp->pktlen=(p_packet_content[lenth++]<<8)+p_packet_content[lenth++];
    udp->check_sum=(p_packet_content[lenth++]<<8)+p_packet_content[lenth++];
    printf("udp_sport = %u\n",udp->sport);
    printf("udp_dport = %u\n",udp->dport);
    printf("Pktlen : %u\n",udp->pktlen);
    printf("check_sum : %u\n",udp->check_sum);
    parseRDP(p_packet_content,lenth,len);

}


//ip整型转换点分十进制
char *InttoIpv4str(u_int32 num){
    char *ipstr= (char*)calloc(128, sizeof(char*));

    if (ipstr){
        sprintf(ipstr,"%d.%d.%d.%d", num>> 24 & 255, num >> 16 & 255,num >> 8&255, num & 255);
    } else{
        printf("failed to Allocate memory....");
    }
    return ipstr;
}

void PrintIP(){
    u_int32 saddr = (u_int32) ntohl(ip->src_ip);//网络字节序转换成主机字节序
    u_int32 daddr = (u_int32) ntohl(ip->dst_ip);
    printf("src_ip:%s\n",InttoIpv4str(saddr)); //源IP地址
    printf("dst_ip:%s\n",InttoIpv4str(daddr)); //目的IP地址
    printf("ip->proto: %u\n",ip->protocol); //传输层用的哪一个协议
    printf("ip remark:%u\n",ip->re_mark);
    printf("ip pktlen:%u\n", ip->pkt_len);
    printf("ip servtype:%u\n",ip->serv_type);
    printf("ip ver_hl:%u\n",ip->ver_hl);
    printf("ip flagseg:%u\n",ip->flag_seg);
    printf("ip h_check: %u\n",ip->h_check);
    printf("ip option:%u\n",ip->option);
    printf("ip surv_tm:%u\n",ip->surv_tm);
}


//解析IP包头
void parseIp(const unsigned char *p_packet_content, u_int32 eth_len, u_int32 len){

    printf("It is IPv4\n");
    u_int32 ip_len;//ip头的长度
    u_int32 tcp_len = sizeof(struct Tcp_hdr);// tcp头的长度

    ip=(struct ip_hdr*) (p_packet_content+eth_len);
    ip_len = (ip->ver_hl & 0x0f)*4; //ip头的长度


    printf("eth_len:%u ip_len:%u tcp_len:%u udp_len:%u\n",eth_len,ip_len,tcp_len);

    PrintIP();

    /*解析传输层  TCP、UDP、ICMP*/
    if (ip->protocol == 6){ //TCP
        printf("It's TCP\n");
        int lenth=eth_len+ip_len;
        tcp=(struct Tcp_hdr*)(p_packet_content + eth_len + ip_len);
        printf("tcp_sport = %u\n",tcp->sport);
        printf("tcp_dport = %u\n",tcp->dport);
        char * s= (char *) (p_packet_content + eth_len + ip_len + tcp_len);
    } else if(ip->protocol == 17){ // UDP
        printf("It's UDP\n");
        int lenth=eth_len+ip_len;
        udp= static_cast<Udp_hdr *>(malloc(sizeof(Udp_hdr)));
        parseUdpAndIp(p_packet_content, lenth,len);

    } else if(ip->protocol == 1){ // ICMP
        printf("It's ICMP\n");
    }
}

//解析PPPOE包头
void parsePPPOE(const unsigned char *p_packet_content, u_int32 eth_len){
    pppoeHdr= static_cast<PPPOE_hdr *>(malloc(sizeof(PPPOE_hdr)));
    pppoeHdr->version=p_packet_content[eth_len];
    int length=eth_len+1;
    pppoeHdr->VER_CODE=p_packet_content[length++];
    pppoeHdr->SESSION_ID=(p_packet_content[length++]<<8)+p_packet_content[length++];
    pppoeHdr->LENGTH=(p_packet_content[length++]<<8)+p_packet_content[length++];
    pppoeHdr->ppp.protocol=(p_packet_content[length++]<<8)+p_packet_content[length++];
}

//分离数据链路层
void divide_ethernet(const unsigned  char *p_packet_content){
    ethernet = (struct eth_hdr*)p_packet_content;

    /*解析数据链路层 以太网头*/
    printf("src_mac:");
    for (int i = 0; i < 6; ++i) {
        printf("%02x ",ethernet->src_mac[i]);
    }
    printf("\ndst_mac:");
    for (int i = 0; i < 6; ++i) {
        printf("%02x ",ethernet->dst_mac[i]);
    }

    printf("\neth_type:%4x\n",ntohs(ethernet->eth_type));
}

//解析回调函数
void pcap_callback(const unsigned  char *p_packet_content,struct  pcap_pkthdr protocol_header){

    printf("Capture Time is : %s \n",ctime((const time_t *)&protocol_header.ts.tv_sec));//time
    printf("Packet Length is: %d \n",protocol_header.len);
    printf("Number of bytes: %d \n",protocol_header.caplen);

    divide_ethernet(p_packet_content);

    u_int32 eth_len = sizeof(struct eth_hdr);//以太网头的长度
    u_int32 ip_len;//ip头的长度
    u_int32 tcp_len = sizeof(struct Tcp_hdr);// tcp头的长度
    u_int32 udp_len = sizeof(struct Udp_hdr);// udp头的长度

    if (ntohs(ethernet->eth_type) == ETHERTYPE_IPV4){
        parseIp(p_packet_content,eth_len,protocol_header.len);

    }else if (ntohs(ethernet->eth_type)== ETHERTYPE_IPV6) // IPV6
    {
        printf("It's IPv6 !\n");
    }else if (ntohs(ethernet->eth_type)== ETHERTYPE_PPPOE1 || (ntohs(ethernet->eth_type)==ETHERTYPE_PPPOE2))//PPPOE
    {
        printf("It's PPPOE! \n");
        parsePPPOE(p_packet_content, eth_len);
        printf("PPPOE length: %hu\n",pppoeHdr->LENGTH);
        printf("PPPOE session ID: %4x\n",pppoeHdr->SESSION_ID);
        printf("PPP protocol:%4x\n",pppoeHdr->ppp.protocol);
        eth_len=eth_len+ sizeof(struct PPPOE_hdr);
        parseIp(p_packet_content,eth_len,protocol_header.len);
    }else if (ntohs(ethernet->eth_type)== ETHERTYPE_PPP){ //纯ppp
        printf("It's PPP");
    }

}

void getPcap(const unsigned  char *p_packet_content,struct  pcap_pkthdr protocol_header,pcap_t *pcap_handler,int flag){
    int count=0;
    while (p_packet_content || flag ==1){

        if (flag ==1){
            flag = 0;
        }
        p_packet_content = pcap_next(pcap_handler,&protocol_header);

        if (!p_packet_content){
            printf("Sorry 黄逸东\n");
            break;
        }
        printf("Hello 黄逸东\n");
        for (int i = 0; i < protocol_header.len; ++i) {
            printf("%02x ",p_packet_content[i]);
            if (i%32 ==0 && i!= 0){
                printf("\n");
            }
        }
        printf("\n");
        pcap_callback(p_packet_content,protocol_header);
        count++;

    }
    pcap_close(pcap_handler);
    printf("\n%d",count);
}

void readConfig(char *path){
    FILE *fp;
    fp=fopen(path,"r");
    if (fp == NULL){
        printf("%s Couldn't open file",path);
    }
    while (feof(fp)== 0){

    }
}


int main(int argc,char *argv[],char *envp[]){
    pcap_t *pcap_handler = NULL;
    const unsigned  char *p_packet_content = NULL;//
    char *dev,errbuf[PCAP_ERRBUF_SIZE];
//    char *pcap_file = "one.pcap";
    struct  pcap_pkthdr protocol_header;
    //获得设备名
    dev=pcap_lookupdev(errbuf);
    if (dev == NULL){
        printf("fail");
        return 1;
    }
    printf("Device: %s\n",dev);
    printf("argv :%s",argv[0]);
    //live
    //获得第一个命令行参数
    char * live=argv[1];
    string li;
    if (live == NULL){
        li="1";
    } else{
        li = live;
    }

    if (li == "1"){
        pcap_handler=pcap_open_live(dev,65535,1,0,errbuf);
    } else {
        char const *pcap_file="/home/oida/CLionProjects/untitled/one.pcapng";
        pcap_handler=pcap_open_offline(pcap_file,errbuf);
    }

    if (pcap_handler){
        printf("open is ok\n");
        printf("Hello 黄逸东\n");

    }else{
        printf("%s\n",errbuf);
        printf("Sorry 黄逸东\n");
        exit(0);
    }

    getPcap(p_packet_content,protocol_header,pcap_handler,1);
    return 0;
}