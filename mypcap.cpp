#include"mypcap.h"
int pcap_1()
{
	pcap_if_t *alldevs;//网卡列表，用指针保存
	char errbuf[PCAP_ERRBUF_SIZE];
	if (pcap_findalldevs(&alldevs, errbuf) == -1)//找到所有网卡信息，保存在alldevs，类似一个链表
	{
		fprintf_s(stderr, "Error!%s\n", errbuf);
		exit(1);
	}
	pcap_if_t *d;
	int i = 0;
	for (d = alldevs; d != NULL; d = d->next)//遍历这个链表
	{
		printf_s("%d,%s  ", ++i, d->name);
		if (d->description)
			printf_s("%s\n", d->description);
		else
			printf("No description!\n");
		pcap_addr_t *pca = d->addresses;
		pcap_addr_t *p_temp = pca;
		for (; p_temp; p_temp = p_temp->next)
		{
			if (p_temp->addr)
				std::cout << "addr: " << p_temp->addr->sa_family << " ";
			if (p_temp->netmask)
				std::cout << "netmask: " << p_temp->netmask->sa_family << " ";
			if (p_temp->broadaddr)
				std::cout << "broadaddr: " << p_temp->broadaddr->sa_family << " ";
			if (p_temp->dstaddr)
				std::cout << "dstaddr: " << p_temp->dstaddr->sa_family << " ";
			std::cout << std::endl;
		}
	}
	if (0 == i)
	{
		printf("no interfaces found!");
		return 0;
	}

	pcap_freealldevs(alldevs);
	return 0;
}
int pcap_3()
{
	pcap_if_t *alldevs;
	char errbuf[PCAP_ERRBUF_SIZE];
	if (pcap_findalldevs(&alldevs, errbuf) == -1)//在本地机器中获得网卡信息
	{
		fprintf(stderr, "ERROR! %s", errbuf);
		exit(1);
	}
	pcap_if_t *d;
	int i = 0;
	for (d = alldevs; d != NULL; d = d->next)//打印网卡信息
	{
		printf("%d:%s", ++i, d->name);
		if (d->description)
		{
			printf("  %s\n", d->description);
		}
		else
		{
			printf("No description!");
		}
	}
	if (0 == i)
		printf("\nNo interfaces found!\n");
	d = alldevs;
	pcap_t *handle;//打开网卡，获得句柄
	if ((handle = pcap_open(d->name, 65536, 1, 10, 0,errbuf)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	printf("\nlistening on %s.....\n", d->description);
	pcap_freealldevs(alldevs);
	pcap_loop(handle, 0, packet_handler_3, NULL);//从句柄中获得一组数据包
	return 0;
}
void packet_handler_3(u_char *param, const struct pcap_pkthdr *header, const u_char*pkt_data)
{
	struct tm ltime;
	char timestr[16];
	time_t local_tv_sec;//typedef long time_t

	/*
	* unused variables
	*/
	(VOID)(param);
	(VOID)(pkt_data);

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	localtime_s(&ltime, &local_tv_sec);//把long类型转换为struct tm类型
	strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);//把struct tm类型转换成字符串输出出来
	printf("%s %.6d len:%d caplen:%d\n", timestr, header->ts.tv_usec, header->len, header->caplen);

}
int pcap_4()//read packet by pcap_next_ex
{
	pcap_if_t *alldevs;
	char errbuf[PCAP_ERRBUF_SIZE];
	if (pcap_findalldevs(&alldevs, errbuf) == -1)//从本地中找到网卡，0是成功，-1是不成功
	{
		fprintf(stderr, "ERROR%s", errbuf);
		exit(1);
	}
	pcap_if_t *d;
	int i = 0;
	for (d = alldevs; d != NULL; d = d->next)
	{
		printf("%d %s", ++i, d->name);
		if (d->description)
		{
			printf(" %s\n", d->description);
		}
		else
			printf("no description!\n");
	}
	if (i == 0)
	{
		printf("\nthere is no devices!\n");
		return 0;
	}
	pcap_t *handle;
	d = alldevs;
	if ((handle = pcap_open_live(d->name/*网卡标识*/, 65536/*一个包所获得的最大字节数*/, 1/*混杂模式*/, 1000/*读取时间*/, errbuf)) == NULL)//从某一网卡中读取数据
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		return -1;
	}
	printf("listening on %s.....\n", d->name);
	int res = 0;
	struct pcap_pkthdr *pkt_header;
	const u_char *pkt_data;
	while ((res = pcap_next_ex(handle, &pkt_header, &pkt_data)) >= 0)//
	{
		if (res == 0)
			continue;
		struct tm timel;
		char timestr[16];
		time_t long_time_sec;
		long_time_sec = pkt_header->ts.tv_sec;
		localtime_s(&timel, &long_time_sec);
		strftime(timestr, sizeof(timestr), "%H:%M:%S", &timel);
		printf("%s %d %d\n", timestr, pkt_header->ts.tv_usec, pkt_header->len);
	}
	return 0;
}
int pcap_6()//compile filter and set filter
{
	pcap_if_t *alldevs;
	char errbuf[PCAP_ERRBUF_SIZE];
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "ERROR! %s", errbuf);
		exit(1);
	}
	pcap_if_t *d;
	int i = 0;
	for (d = alldevs; d != NULL; d = d->next)
	{
		printf("%d %s ", ++i, d->name);
		if (d->description)
			printf("%s\n", d->description);
		else
			printf("no description!\n");
	}
	if (i == 0)
	{
		printf("there is no device!\n");
		return 0;
	}
	pcap_t *handle;
	d = alldevs->next;
	if ((handle = pcap_open_live(d->name, 65536, 1, 1000, errbuf)) == NULL)
	{
		fprintf(stderr, "capture handle error! %s", errbuf);
		pcap_freealldevs(alldevs);
		return -1;
	}
	if (pcap_datalink(handle) != DLT_EN10MB)//判断链路类型，只能在以太网上运行,通过这个语句限制捕捉的只是MAC帧，是下面pkt_data+14的原因
	{
		printf("\n this program works only on ethernet net!\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	bpf_u_int32 netmask;
	if (d->addresses != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;//得到网关
	else
		netmask = 0xffffff;
	//编译过滤规则和设置规则
	char file_str[] = "ip and udp";
	bpf_program fp;
	if (pcap_compile(handle, &fp, file_str, 1, netmask) < 0)
	{
		printf("\n unble to compile filter!\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	if (pcap_setfilter(handle, &fp) < 0)
	{
		printf("\n set filter error!\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	printf("listening on %s.......\n", d->description);
	pcap_freealldevs(alldevs);//不管怎么样一定要释放设备
	pcap_loop(handle, 0, packet_handler_6, NULL);
	return 0;
}
void packet_handler_6(u_char *user, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	(VOID)user;
	tm ltime;
	char timestr[16];
	time_t long_local_vec;
	ip_header *ih;
	udp_header *uh;
	u_int ip_len;
	u_short sport, dport;
	long_local_vec = header->ts.tv_sec;
	localtime_s(&ltime, &long_local_vec);//time_t->struct tm
	strftime(timestr, sizeof(timestr), "%H:%M:%S", &ltime);//把时间struct tm的ltime按照格式H:M:S放到以timestr开头，大小为sizeof的字符串
	printf("%s %d %d  ", timestr, header->ts.tv_usec, header->len);//pkt_data指向的应该是网卡上的数据，即以太网帧
	ih = (ip_header*)(pkt_data + 14);//以太网帧的首部为14，以太网的地址移动14个是IP数据包
	ip_len = (ih->ver_ihl & 0xf) * 4;//ip数据报的首部长度不确定，只能读取数据才知道
	uh = (udp_header*)((u_char*)ih + ip_len);//IP数据的地址再移动ip的首部长度便是udp的数据
	sport = (uh->sport);
	dport = (uh->dport);
	printf("%d.%d.%d.%d.%d -> %d.%d.%d.%d.%d\n",
		ih->saddr.byte1,
		ih->saddr.byte2,
		ih->saddr.byte3,
		ih->saddr.byte4,
		sport,
		ih->daddr.byte1,
		ih->daddr.byte2,
		ih->daddr.byte3,
		ih->daddr.byte4,
		dport);
}
int pcap_7_1()// save packet to file 
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int i = 0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_dumper_t *dumpfile;

	/* Retrieve the device list on the local machine */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}
	d = alldevs->next;
	/* Open the device */
	if ((adhandle = pcap_open_live(d->name,          // name of the device
		65536,            // portion of the packet to capture
		// 65536 guarantees that the whole packet will be captured on all the link layers
		1,    // promiscuous mode
		1000,             // read timeout          
		errbuf            // error buffer
		)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Open the dump file */
	dumpfile = pcap_dump_open(adhandle, "F:\\time1.txt");//将句柄与文件相关联，与普通的读网卡程序中多了这句

	if (dumpfile == NULL)
	{
		fprintf(stderr, "\nError opening output file\n");
		return -1;
	}

	printf("\nlistening on %s... Press Ctrl+C to stop...\n", d->description);

	/* At this point, we no longer need the device list. Free it */
	pcap_freealldevs(alldevs);

	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler_7_1, (unsigned char *)dumpfile);//写到文件中也要一个包一个包写进去，所以要用到pcap_loop,
	//最后一个参数要用pcap_dumper_t经过格式转换的指针，具体写入在回调函数

	return 0;
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler_7_1(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	/* save the packet on the dump file */
	printf("%d %d %d\n", header->ts.tv_usec, header->ts.tv_sec, header->len);
	pcap_dump(dumpfile, header, pkt_data);
}
int pcap_7_2()//read packet from file
{
	char errbuf[PCAP_ERRBUF_SIZE];
	char source[1024];
	if (pcap_createsrcstr(source, 2, NULL, NULL, "F:\\time1.txt", errbuf) != 0)
	{
		printf("\nError to create source string!\n");
		return -1;
	}
	pcap_t *handle;
	if ((handle = pcap_open(source, 65536, 1, 1000, NULL, errbuf)) == NULL)
	{
		printf("\nUnable to open the file!\n");
		return -1;
	}
	pcap_loop(handle, 0, packet_handler_7_2, NULL);
}
void packet_handler_7_2(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	tm ltime;
	char strtime[16];
	time_t local_time;
	local_time = header->ts.tv_sec;
	localtime_s(&ltime, &local_time);
	strftime(strtime, sizeof(strtime), "%H:%M:%S", &ltime);
	printf("%s %d %d\n", strtime,header->ts.tv_usec,header->len);

}
void pcap_self()
{
	pcap_if_t *alldevs;
	char errbuf[PCAP_ERRBUF_SIZE];
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		printf("\nUnable find devices!\n");
		exit(1);
	}
	pcap_if_t *d;
	int i = 0;
	for (d = alldevs; d; d = d->next)
	{
		printf("%d %s ", ++i, d->name);
		if (d->description)
		{
			printf("%s\n", d->description);
		}
		else
		{
			printf("no description!\n");
		}

	}
	if (0 == i)
	{
		printf("\nthere is no devices!\n");
		pcap_freealldevs(alldevs);
		return;
	}
	pcap_t *handle;//捕获打开的设备
	d = alldevs->next;
	if ((handle = pcap_open(d->name, 65536, 1, 1000, NULL, errbuf)) == NULL)
	{
		printf("\nCan not open the devices!\n");
		pcap_freealldevs(alldevs);
		return;
	}
	if (pcap_datalink(handle) != DLT_EN10MB)//只处理以太网数据
	{
		printf("thie program only work on ethernt!\n");
		return;
	}
	pcap_freealldevs(alldevs);
	//pcap_dumper_t *dumperfile;//这是在写入文件中才使用
	char str[] = "ip and udp";//编译和设置规则
	bpf_program fp;
	u_int netmask;
	if (d->addresses)
	{
		netmask = ((sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	}
	else
		netmask = 0xffffff;
	if ( pcap_compile(handle, &fp, str, 1, netmask)<0)//compile
	{
		printf("\ncompile filter error!\n");
	}
	if (pcap_setfilter(handle, &fp) < 0)//set
	{
		printf("\nset filter error!\n");
	}
	pcap_dumper_t *dumperfile;//save packet to file
	if ((dumperfile = pcap_dump_open(handle, "F:\\time1.txt")) == NULL)
	{
		printf("associate file error!\n");
	}
	pcap_loop(handle, 0, packet_handler_self, (u_char *)dumperfile);
}
void packet_handler_self(u_char *param, const struct pcap_pkthdr*header, const u_char *pkt_data)
{
	tm ltime;
	time_t long_time;
	char strtime[16];
	long_time = header->ts.tv_sec;
	localtime_s(&ltime, &long_time);
	strftime(strtime, sizeof(strtime), "%H:%M:%S", &ltime);
	printf("%s ", strtime);
	ip_header *ip_head;
	udp_header *udp_head;
	u_int ip_len;
	ip_head = (ip_header *)(pkt_data + 14);
	ip_len = (ip_head->ver_ihl & 0xf) * 4;
	udp_head = (udp_header*)((u_char *)ip_head + ip_len);
	printf("%d.%d.%d.%d.%d ->%d.%d.%d.%d.%d\n", ip_head->saddr.byte1, ip_head->saddr.byte2, ip_head->saddr.byte3,
		ip_head->saddr.byte4, udp_head->sport, ip_head->daddr.byte1, ip_head->daddr.byte2, ip_head->daddr.byte3, ip_head->daddr.byte4,
		udp_head->dport);//读取
	pcap_dump(param, header, pkt_data);//写入到文件中
}
void pcap_8()
{
	pcap_if_t *alldevs;
	char errbuf[PCAP_ERRBUF_SIZE];
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, 0, &alldevs, errbuf) == -1)
	{
		printf("\nUnable find devices!\n");
		return;
	}
	pcap_if_t *d = alldevs;
	pcap_t *handle;
	printf("opening %s\n", d->description);
	if ((handle = pcap_open(d->name, 100/*每个数据包保留的长度*/, 1, 1000, NULL, errbuf)) == NULL)
	{
		printf("\nCan not open devices!\n");
		pcap_freealldevs(alldevs);
		return;
	}
	u_char packet[100];
	/* Supposing to be on ethernet, set mac destination to 1:1:1:1:1:1 */
	packet[0] = 1;
	packet[1] = 1;
	packet[2] = 1;
	packet[3] = 1;
	packet[4] = 1;
	packet[5] = 1;

	/* set mac source to 2:2:2:2:2:2 */
	packet[6] = 2;
	packet[7] = 2;
	packet[8] = 2;
	packet[9] = 2;
	packet[10] = 2;
	packet[11] = 2;
	int i = 0;
	/* Fill the rest of the packet */
	for (i = 12; i<99; i++)
	{
		packet[i] = (u_char)i;
	}
	packet[i] = '\0';
	if (pcap_sendpacket(handle, packet, 100) != 0)
	{
		printf("\nunable to send!\n", pcap_geterr(handle));
		return;
	}
}
void pcap_9()
{
	u_int seqlen = 0;//内存的大小，用来申请队列的长度
	FILE*f;
	fopen_s(&f,"F:\\time1.txt", "rb");//读取文件，获得文件内容的长度
	fseek(f, 0, SEEK_END);
	seqlen = ftell(f) - sizeof(pcap_file_header);//文件内容的长度，用来分配队列 ；文件末尾的位置减去头文件的大小便是数据部分的大小
	pcap_send_queue *queue;
	if ((queue = pcap_sendqueue_alloc(seqlen)) == NULL)
	{
		printf("\n Allocate buzeff to queue error!\n");
		return;
	}
	char source[PCAP_BUF_SIZE];
	char errbuf[PCAP_ERRBUF_SIZE];
	if (pcap_createsrcstr(source, 2, NULL, NULL, "F:\\time1.txt", errbuf) != 0)//根据指定的文件名来创建打开文件的标志符
	{
		printf("\n Unable to create source from file!\n");
		return;
	}
	pcap_t *inhandle, *outhandle;
	if ((inhandle = pcap_open(source, 65536, 1, 1000, NULL, errbuf)) == NULL)//配置从文件中读取内容的句柄
	{
		printf("\nUnable to open the file!\n");
		return;
	}
	pcap_if_t *alldevs;
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		printf("\nUnable to find devices!\n");
		return;
	}
	if ((outhandle = pcap_open(alldevs->name, 65536, 1, 1000, NULL, errbuf)) == NULL)//配置从网卡发出内容的句柄
	{
		printf("\nUnable to open the devices!\n");
		pcap_freealldevs(alldevs);
		return;
	}
	pcap_freealldevs(alldevs);
	if (pcap_datalink(inhandle) != pcap_datalink(outhandle))//判断读取的文件的链路类型和发送数据的网卡的链路类型是否一致
	{
		printf("\n the linktype must be same!\n");
		return;
	}
    struct pcap_pkthdr *header;//包的基本信息，时间，长度等
	const u_char *pkt_data;//指向包内容的指针
	u_int res = 0;
	u_int npackets = 0;
	while ((res=pcap_next_ex(inhandle, &header, &pkt_data)) == 1)//将文件内容分配到队列中，这里不要用pcap_loop因为无法把queue传到回调函数里
	{
		if (pcap_sendqueue_queue(queue, header, pkt_data) != 0)
		{
			printf("\n not all the packet be sent!\n");
			break;
		}
		npackets++;//计算读取到多少的packet
	}
	if (res == -1)
	{
		printf("input file error!\n");
		pcap_sendqueue_destroy(queue);
		return;
	}
	if ((res=pcap_sendqueue_transmit(outhandle, queue, 0)) < queue->len)
	{
		printf("Only %d bytes send!\n", res);
	}
	printf("\nthere is %d packet generated!\n", npackets);
	pcap_sendqueue_destroy(queue);
	pcap_close(inhandle);
	pcap_close(outhandle);
	return;
}
