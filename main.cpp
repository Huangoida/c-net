#include "stdio.h"
#include "stdlib.h"
#include <pcap.h>
#include <netinet/in.h>
#include <time.h>
#include "string.h"
#include <string>
#include "cJSON.h"
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>

/**
 * 第一个命令行是选择在线抓包还是离线抓包
 * 第二个命令行是配置文件位置
 * 第三个命令行是拿配置文件第几个路径（从零开始）
 */

#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_IPV6 0x86DD
#define ETHERTYPE_PPPOE1 0x8864
#define ETHERTYPE_PPPOE2 0x8863
#define ETHERTYPE_PPP 0x880B
#define PCAP_DATABUF_MAX 65535

char filename[1024];
char str[65535];

int sockfd;
struct  sockaddr_in dest_addr;

void init(){
    sockfd = socket(AF_INET,SOCK_DGRAM,0);
    if (sockfd == -1){
        perror("socket()");
        return;
    }
    dest_addr.sin_family=AF_INET;
    dest_addr.sin_addr.s_addr = inet_addr("239.2.1.1");
    dest_addr.sin_port = htons(8000);

    while((sockfd == socket(AF_INET,SOCK_DGRAM,0)) == -1);
    while(connect(sockfd,(struct sockaddr *)&dest_addr, sizeof(struct sockaddr)) == -1);

    int sin_size = sizeof(struct sockaddr_in);
    int time_live= 64;
    setsockopt(sockfd,IPPROTO_IP,IP_MULTICAST_TTL,(void *)&time_live, sizeof(time_live));

}

int forware_pkt(char *buf,int length){
    send(sockfd,buf,length,0);
    return 0;
}


int net;
//读取配置文件
void ReadFile(char *path){
    FILE *fp=fopen(path,"r");
    char string[65535];

    if (!fp){
        printf("File open file");
        exit(-1);
    }
    int i=0;
    while (fgets(string, sizeof(string),fp)){
        int len=strlen(string);
        for (int j = 0; j < len; ++j) {
            if (string[j]==' '){
                continue;
            }
            if (string[j]=='\n'){
                continue;
            }
            str[i++]=string[j];
        }
    };
    fclose(fp);
    printf("%s\n",str);

}//读取文件到字符串
//解析JSON到JSON对象
cJSON *getJSONParse(){
    cJSON *root = cJSON_Parse(str);
    if (!root){
        printf("get root fail!\n");
        exit(-1);
    }
    return root;
}
//查找子节点
cJSON *getObjectItems(cJSON * root,char * title){
    cJSON *js_list = cJSON_GetObjectItem(root,title);
    if (!js_list){
        printf("no list!\n");
        exit(-1);
    }
    return js_list;
}
//查找最终的结点
cJSON *getfinalItems(cJSON *items,int number){
    cJSON *item=items->child;
    int k=cJSON_GetArraySize(items);
    if (number >= k){
        printf("超出json范围");
        return  NULL;
    }
    for (int i = 0; i < k; ++i) {
        if (i==number){
            return item;
        }
        item=item->next;
    }
    printf("没有找到");
}

char *getPath(char *path,char *numbers){
    ReadFile(path);
    int lens= strlen(str);
    cJSON *root=getJSONParse();
    cJSON *js_list=getObjectItems(root,"file");
    int number =atoi(numbers);

    cJSON *item=getfinalItems(js_list,number);
    printf("%s",item->valuestring);
    return item->valuestring;
}


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


void SaveFile(const unsigned char *p_packet_content,u_int32 lenth, u_int32 len){
    if (p_packet_content[lenth] == 0x47){
        FILE *file=fopen(filename,"ab+");
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
}

void printRDP(){
    printf("It's Rdp\n");
    printf("flag: %d\n",rdpHdr->flag);
    printf("Playload_type: %d\n",rdpHdr->Payload_type);
    printf("sequence-number: %d\n",rdpHdr->sequence_number);
    printf("identifier: %d\n",rdpHdr->identifier);
}
//解析RDP包头
void parseRDP(const unsigned char *p_packet_content, u_int32 lenth, u_int32 len){

    rdpHdr= static_cast<RDP_hdr *>(malloc(sizeof(RDP_hdr)));
    rdpHdr->flag=p_packet_content[lenth++];
    rdpHdr->Payload_type=p_packet_content[lenth++];
    rdpHdr->sequence_number=(p_packet_content[lenth++]<<8)+p_packet_content[lenth++];
    rdpHdr->Timestamp = (p_packet_content[lenth++]<<24)+(p_packet_content[lenth++]<<16)+(p_packet_content[lenth++]<<8)+p_packet_content[lenth++];
    rdpHdr->identifier=(p_packet_content[lenth++]<<24)+(p_packet_content[lenth++]<<16)+(p_packet_content[lenth++]<<8)+p_packet_content[lenth++];
    printRDP();
    SaveFile(p_packet_content,lenth,len);


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
    if (p_packet_content[lenth] == 0x80){
        parseRDP(p_packet_content,lenth,len);
    }else if(p_packet_content[lenth] == 0x47){

        if (net == 1){
            SaveFile(p_packet_content,lenth,len);
        }else
        {
            p_packet_content=p_packet_content+lenth;
            int length=len-lenth;
            char out[length];
            for (int i = 0; i < length; ++i) {
                out[i]=p_packet_content[i];
            }
            forware_pkt(out,length);
            //net
        }

    }else {
        system("pause");
    }

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

        parsePPPOE(p_packet_content, eth_len);
        printf("It's PPPOE! \n");
        printf("PPPOE Version_Type: %lu\n",pppoeHdr->version);
        printf("PPPOE length: %hu\n",pppoeHdr->LENGTH);
        printf("PPPOE session ID: %4x\n",pppoeHdr->SESSION_ID);
        if (pppoeHdr->ppp.protocol == 0x0021){
            printf("PPP protocol:IPV4\n",pppoeHdr->ppp.protocol);
        } else{
            printf("PPP protocol: %lu\n",pppoeHdr->ppp.protocol);
        }

        eth_len=eth_len+ sizeof(struct PPPOE_hdr);
        parseIp(p_packet_content,eth_len,protocol_header.len);
    }else if (ntohs(ethernet->eth_type)== ETHERTYPE_PPP){ //纯ppp
        printf("It's PPP");
    }

}
//获得数据报
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

        pcap_callback(p_packet_content,protocol_header);
        count++;

    }
    pcap_close(pcap_handler);
    printf("\n%d",count);
}


int main(int argc,char *argv[],char *envp[]){
    init();
    strcpy(filename,argv[4]);
    net=atoi(argv[5]);
    if (remove(filename) == 0){
        printf("Removed %s.\n",filename);
    } else{
        perror("remove");
    }
    pcap_t *pcap_handler = NULL;
    const unsigned  char *p_packet_content = NULL;
    char *dev,errbuf[PCAP_ERRBUF_SIZE];
    struct  pcap_pkthdr protocol_header;
    //获得设备名
    dev=pcap_lookupdev(errbuf);
    if (dev == NULL){
        printf("fail");
        return 1;
    }
    printf("Device: %s\n",dev);
    printf("argv :%s\n",argv[0]);
    //live
    //获得第一个命令行参数
    char * live=argv[1];
    std::string li;
    if (live == NULL){//如果没有填写，则为默认值
        li="1";
    } else{
        li = live;//如果有填写，按填写值
    }

    if (li == "1"){
        struct bpf_program filter;

        pcap_handler=pcap_open_live(dev,65535,1,10000,errbuf);
        pcap_compile(pcap_handler,&filter,"dst host 239.1.1.1",1,0);
        pcap_setfilter(pcap_handler,&filter);
    } else {
        char const *pcap_file=getPath(argv[2],argv[3]);
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