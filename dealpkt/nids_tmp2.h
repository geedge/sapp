
typedef struct _stappinfo
{
  char op_state;   //deem
  char op_flag;    //deem
  short pad;
  struct lurker_node *listeners;
  int serverpkt;
  int clientpkt;
  unsigned long creattime;
  unsigned long lastmtime; 
  char *pkillinfo;
}stAppInfo;



struct tuple4 {
  u_short source;
  u_short dest;
  u_int saddr;
  u_int daddr;
};

#define MAX_CACHE_LEN 16

/*°ë½ṹÌ¶¨Ò£º*/
struct half_stream
{
  char *data;             /*Êµ½µÄCP¸ºÔÊ¾Ý/
  u_int offset;           /*dataÖµÚ»¸öÚÚCPÊ¾Ý÷Ä«Ò*/
  u_int count;            /*´Ó¬½ӽ¨bÆµ½ÏÔΪֹ£¬µ½´ïÊ¾Ýܳ¤¶ÈֽÚýu_int count_new;        /*±¾´Îµ½µÄýÚýu_int count_ideal;      /*´Ó¬½ӽ¨bÆµ½ÏÔΪֹ£¬ÀÂÉӦ¸õ½´ïÊ¾Ýܳ¤¶È/
  u_int pktcout;          /*±¾²à¼Ƶ½´ï°ü/
  u_int pktcout_new;      /*±¾´Îµ½´ï°ü/
  u_int seq;              /*±¾²à¾ÝڴýÐºÅ/
  u_int first_data_seq;   /*±¾²à¾ÝðĵÄeqÐºÅ/
  u_int ack_seq;          /*±¾²à¾ÝîʹÓµÄ¦´ð/
  
  u_short window;         /*±¾²à¾ݻ¬¶¯´°¿ڴó/
  u_short pad;            /*ԤÁ²¹Æ*/
  u_int  *sigpktlen;      /*µ¥°üý×³¤¶Èª	pktcout_new*/
  u_char *tcpflag;        /*µ¥°üg×,Ê×³¤¶Èª	pktcout_new*/
  void   *pktinfo;        /*µ¥°üÅ¢Ê×£¬ԤÁ£¬Ê×³¤¶Èª	pktcout_new*/
};


/*Á½ṹÌ¶¨Ò£º*/
/*struct stream½ṹ¶¨Ò£º*/
struct tcp_stream {
  struct tuple4 addr;        /*ͨѶ˫·½µÄÄª×*/
  u_char nids_state;         /*µ±ǰt½ӵÄ´̬*/
  u_char dir;                /*µ±ǰËԪ×²¶»ñý·µķ½Ï*/
  u_char appproto;           /*µ±ǰt½ӵÄ¦Ó²ãÒÀ±ð  u_char thread_num;          /*µ±ǰt½ÓùÁºÅ/
  struct half_stream client;  /*µ½clientµÄCPl½ÓÅ¢*/ 
  struct half_stream server;  /*µ½ serverµÄCPl½ÓÅ¢*/
  stAppInfo *appinfo;              /*ӦÓ²ãϢָÕ,t½Ӹս¨bΪNULL,ÓӦÓ²㸳ֵ,²¢ÇÔºóý¹Ó*/
};
/*
struct _sttcp_appinfo
{
#define MAX_APPCOUNT 8
  char appreg[MAX_APPCOUNT];
  int 	  appstat[MAX_APPCOUNT];
  void (*item)()[MAX_APPCOUNT];
  void *data[MAX_APPCOUNT];
}
*/
struct pktinfo{
 u_char ipproto; /*ip²ãÒÀ±ðx06 TCP 0x11 UDP ½ø×µÄýpЭÒ£¬δÖ×µÄ»ÂΪ0  */
 void *pdata; /*Á½ṹÌ£¬»òpÖ×ºóp±¨Î*/
};


