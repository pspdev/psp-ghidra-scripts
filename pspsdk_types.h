
// psptypes.h
typedef	uint8_t				u8;
typedef uint16_t			u16;
typedef uint32_t			u32;
typedef uint64_t			u64;
typedef int8_t				s8;
typedef int16_t				s16;
typedef int32_t				s32;
typedef int64_t				s64;
typedef	volatile uint8_t		vu8;
typedef volatile uint16_t		vu16;
typedef volatile uint32_t		vu32;
typedef volatile uint64_t		vu64;
typedef volatile int8_t			vs8;
typedef volatile int16_t		vs16;
typedef volatile int32_t		vs32;
typedef volatile int64_t		vs64;
typedef unsigned char SceUChar8;
typedef uint16_t SceUShort16;
typedef uint32_t SceUInt32;
typedef uint64_t SceUInt64;
typedef uint64_t SceULong64;
typedef char SceChar8;
typedef int16_t SceShort16;
typedef int32_t SceInt32;
typedef int64_t SceInt64;
typedef int64_t SceLong64;
typedef float SceFloat;
typedef float SceFloat32;
typedef short unsigned int SceWChar16;
typedef unsigned int SceWChar32;
typedef int SceBool;
typedef void SceVoid;
typedef void * ScePVoid;
typedef struct ScePspSRect {
	short int 	x;
	short int 	y;
	short int 	w;
	short int 	h;
} ScePspSRect;

typedef struct ScePspIRect {
	int 	x;
	int 	y;
	int 	w;
	int 	h;
} ScePspIRect;

typedef struct ScePspL64Rect {
	SceLong64 	x;
	SceLong64 	y;
	SceLong64 	w;
	SceLong64 	h;
} ScePspL64Rect;

typedef struct ScePspFRect {
	float 	x;
	float 	y;
	float 	w;
	float 	h;
} ScePspFRect;

typedef struct ScePspSVector2 {
	short int 	x;
	short int 	y;
} ScePspSVector2;

typedef struct ScePspIVector2 {
	int 	x;
	int 	y;
} ScePspIVector2;

typedef struct ScePspL64Vector2 {
	SceLong64 	x;
	SceLong64 	y;
} ScePspL64Vector2;

typedef struct ScePspFVector2 {
	float 	x;
	float 	y;
} ScePspFVector2;

typedef union ScePspVector2 {
	ScePspFVector2 	fv;
	ScePspIVector2 	iv;
	float 			f[2];
	int 			i[2];
} ScePspVector2;

typedef struct ScePspSVector3 {
	short int 	x;
	short int 	y;
	short int 	z;
} ScePspSVector3;

typedef struct ScePspIVector3 {
	int 	x;
	int 	y;
	int 	z;
} ScePspIVector3;

typedef struct ScePspL64Vector3 {
	SceLong64 	x;
	SceLong64 	y;
	SceLong64 	z;
} ScePspL64Vector3;

typedef struct ScePspFVector3 {
	float 	x;
	float 	y;
	float 	z;
} ScePspFVector3;

typedef union ScePspVector3 {
	ScePspFVector3 	fv;
	ScePspIVector3 	iv;
	float 			f[3];
	int 			i[3];
} ScePspVector3;

typedef struct ScePspSVector4 {
	short int 	x;
	short int 	y;
	short int 	z;
	short int 	w;
} ScePspSVector4;

typedef struct ScePspIVector4 {
	int 	x;
	int 	y;
	int 	z;
	int 	w;
} ScePspIVector4;

typedef struct ScePspL64Vector4 {
	SceLong64 	x;
	SceLong64 	y;
	SceLong64 	z;
	SceLong64 	w;
} ScePspL64Vector4;

typedef struct ScePspFVector4 {
	float 	x;
	float 	y;
	float 	z;
	float 	w;
} ScePspFVector4 __attribute__((aligned(16)));

typedef struct ScePspFVector4Unaligned {
	float 	x;
	float 	y;
	float 	z;
	float 	w;
} ScePspFVector4Unaligned;

typedef union ScePspVector4 {
	ScePspFVector4 	fv;
	ScePspIVector4 	iv;
	float 			f[4];
	int 			i[4];
} ScePspVector4 __attribute__((aligned(16)));

typedef struct ScePspIMatrix2 {
	ScePspIVector2 	x;
	ScePspIVector2 	y;
} ScePspIMatrix2;

typedef struct ScePspFMatrix2 {
	ScePspFVector2 	x;
	ScePspFVector2 	y;
} ScePspFMatrix2;

typedef union ScePspMatrix2 {
	ScePspFMatrix2 	fm;
	ScePspIMatrix2 	im;
	ScePspFVector2 	fv[2];
	ScePspIVector2 	iv[2];
	ScePspVector2 	v[2];
	float 			f[2][2];
	int 			i[2][2];
} ScePspMatrix2;

typedef struct ScePspIMatrix3 {
	ScePspIVector3 	x;
	ScePspIVector3 	y;
	ScePspIVector3 	z;
} ScePspIMatrix3;

typedef struct ScePspFMatrix3 {
	ScePspFVector3 	x;
	ScePspFVector3 	y;
	ScePspFVector3 	z;
} ScePspFMatrix3;

typedef union ScePspMatrix3 {
	ScePspFMatrix3 	fm;
	ScePspIMatrix3 	im;
	ScePspFVector3 	fv[3];
	ScePspIVector3 	iv[3];
	ScePspVector3 	v[3];
	float 			f[3][3];
	int 			i[3][3];
} ScePspMatrix3;

typedef struct ScePspIMatrix4 {
	ScePspIVector4 	x;
	ScePspIVector4 	y;
	ScePspIVector4 	z;
	ScePspIVector4 	w;
} ScePspIMatrix4 __attribute__((aligned(16)));

typedef struct ScePspIMatrix4Unaligned {
	ScePspIVector4 	x;
	ScePspIVector4 	y;
	ScePspIVector4 	z;
	ScePspIVector4 	w;
} ScePspIMatrix4Unaligned;

typedef struct ScePspFMatrix4 {
	ScePspFVector4 	x;
	ScePspFVector4 	y;
	ScePspFVector4 	z;
	ScePspFVector4 	w;
} ScePspFMatrix4 __attribute__((aligned(16)));

typedef struct ScePspFMatrix4Unaligned {
	ScePspFVector4 	x;
	ScePspFVector4 	y;
	ScePspFVector4 	z;
	ScePspFVector4 	w;
} ScePspFMatrix4Unaligned;

typedef union ScePspMatrix4 {
	ScePspFMatrix4 	fm;
	ScePspIMatrix4 	im;
	ScePspFVector4 	fv[4];
	ScePspIVector4 	iv[4];
	ScePspVector4 	v[4];
	float 			f[4][4];
	int 			i[4][4];
} ScePspMatrix4;

typedef struct ScePspFQuaternion {
	float 	x;
	float 	y;
	float 	z;
	float 	w;
} ScePspFQuaternion __attribute__((aligned(16)));

typedef struct ScePspFQuaternionUnaligned {
	float 	x;
	float 	y;
	float 	z;
	float 	w;
} ScePspFQuaternionUnaligned;

typedef struct ScePspFColor {
	float 	r;
	float 	g;
	float 	b;
	float 	a;
} ScePspFColor __attribute__((aligned(16)));

typedef struct ScePspFColorUnaligned {
	float 	r;
	float 	g;
	float 	b;
	float 	a;
} ScePspFColorUnaligned;

typedef unsigned int ScePspRGBA8888;
typedef unsigned short ScePspRGBA4444;
typedef unsigned short ScePspRGBA5551;
typedef unsigned short ScePspRGB565;
typedef union ScePspUnion32 {
	unsigned int 	ui;
	int 			i;
	unsigned short 	us[2];
	short int 		s[2];
	unsigned char 	uc[4];
	char 			c[4];
	float 			f;
	ScePspRGBA8888 	rgba8888;
	ScePspRGBA4444 	rgba4444[2];
	ScePspRGBA5551 	rgba5551[2];
	ScePspRGB565 	rgb565[2];
} ScePspUnion32;

typedef union ScePspUnion64 {
	SceULong64 		ul;
	SceLong64 		l;
	unsigned int 	ui[2];
	int 			i[2];
	unsigned short 	us[4];
	short int 		s[4];
	unsigned char 	uc[8];
	char 			c[8];
	float 			f[2];
	ScePspSRect 	sr;
	ScePspSVector4 	sv;
	ScePspRGBA8888 	rgba8888[2];
	ScePspRGBA4444 	rgba4444[4];
	ScePspRGBA5551 	rgba5551[4];
	ScePspRGB565 	rgb565[4];
} ScePspUnion64;

typedef union ScePspUnion128 {
	SceULong64		ul[2];
	SceLong64		l[2];
	unsigned int 	ui[4];
	int 			i[4];
	unsigned short 	us[8];
	short int 		s[8];
	unsigned char 	uc[16];
	char 			c[16];
	float 			f[4];
	ScePspFRect 	fr;
	ScePspIRect 	ir;
	ScePspFVector4 	fv;
	ScePspIVector4 	iv;
	ScePspFQuaternion fq;
	ScePspFColor 	fc;
	ScePspRGBA8888 	rgba8888[4];
	ScePspRGBA4444 	rgba4444[8];
	ScePspRGBA5551 	rgba5551[8];
	ScePspRGB565 	rgb565[8];
} ScePspUnion128 __attribute__((aligned(16)));

typedef struct ScePspDateTime {
	unsigned short	year;
	unsigned short 	month;
	unsigned short 	day;
	unsigned short 	hour;
	unsigned short 	minute;
	unsigned short 	second;
	unsigned int 	microsecond;
} ScePspDateTime;


// pspkerneltypes.h
typedef int SceUID;
typedef unsigned int SceSize;
typedef int SceSSize;
typedef unsigned char SceUChar;
typedef unsigned int SceUInt;
typedef int SceMode;
typedef SceInt64 SceOff;
typedef SceInt64 SceIores;

// pspgu.h
typedef void (*GuSwapBuffersCallback)(void** display,void** render);

// pspatrac3.h
typedef struct {
	u8 *pucWritePositionFirstBuf;
	u32 uiWritableByteFirstBuf;
	u32 uiMinWriteByteFirstBuf;
	u32 uiReadPositionFirstBuf;
	u8 *pucWritePositionSecondBuf;
	u32 uiWritableByteSecondBuf;
	u32 uiMinWriteByteSecondBuf;
	u32 uiReadPositionSecondBuf;
} PspBufferInfo;


// pspaudio.h
typedef struct
	{
	int unknown1;
	int gain;
	int unknown2;
	int unknown3;
	int unknown4;
	int unknown5;
} pspAudioInputParams;


// pspaudiolib.h
typedef void (* pspAudioCallback_t)(void *buf, unsigned int reqn, void *pdata);
typedef struct {
	int threadhandle;
	int handle;
	int volumeleft;
	int volumeright;
	pspAudioCallback_t callback;
	void *pdata;
} psp_audio_channelinfo;

typedef int (* pspAudioThreadfunc_t)(int args, void *argp);

// pspctrl.h
typedef struct SceCtrlData {
	unsigned int 	TimeStamp;
	unsigned int 	Buttons;
	unsigned char 	Lx;
	unsigned char 	Ly;
	unsigned char 	Rsrv[6];
} SceCtrlData;

typedef struct SceCtrlLatch {
	unsigned int 	uiMake;
	unsigned int 	uiBreak;
	unsigned int 	uiPress;
	unsigned int 	uiRelease;
} SceCtrlLatch;


// pspdebug.h
typedef struct _PspDebugRegBlock
	{
	u32 frame[6];
	u32 r[32];
	u32 status;
	u32 lo;
	u32 hi;
	u32 badvaddr;
	u32 cause;
	u32 epc;
	float fpr[32];
	u32 fsr;
	u32 fir;
	u32 frame_ptr;
	u32 unused;
	u32 index;
	u32 random;
	u32 entrylo0;
	u32 entrylo1;
	u32 context;
	u32 pagemask;
	u32 wired;
	u32 cop0_7;
	u32 cop0_8;
	u32 cop0_9;
	u32 entryhi;
	u32 cop0_11;
	u32 cop0_12;
	u32 cop0_13;
	u32 cop0_14;
	u32 prid;
	u32 padding[100];
} PspDebugRegBlock;

typedef void (*PspDebugErrorHandler)(PspDebugRegBlock *regs);
typedef int (*PspDebugKprintfHandler)(const char *format, u32 *args);
typedef struct _PspDebugStackTrace
	{
	u32 call_addr;
	u32 func_addr;
} PspDebugStackTrace;

typedef struct _PspDebugProfilerRegs
	{
	volatile u32 enable;
	volatile u32 systemck;
	volatile u32 cpuck;
	volatile u32 internal;
	volatile u32 memory;
	volatile u32 copz;
	volatile u32 vfpu;
	volatile u32 sleep;
	volatile u32 bus_access;
	volatile u32 uncached_load;
	volatile u32 uncached_store;
	volatile u32 cached_load;
	volatile u32 cached_store;
	volatile u32 i_miss;
	volatile u32 d_miss;
	volatile u32 d_writeback;
	volatile u32 cop0_inst;
	volatile u32 fpu_inst;
	volatile u32 vfpu_inst;
	volatile u32 local_bus;
} PspDebugProfilerRegs;

typedef int (*PspDebugPrintHandler)(const char *data, int len);
typedef int (*PspDebugInputHandler)(char *data, int len);

// pspge.h
typedef struct PspGeContext {
	unsigned int context[512];
} PspGeContext;

typedef struct
	{
	unsigned int stack[8];
} SceGeStack;

typedef void (*PspGeCallback)(int id, void *arg);
typedef struct PspGeCallbackData
	{
	PspGeCallback signal_func;
	void *signal_arg;
	PspGeCallback finish_func;
	void *finish_arg;
} PspGeCallbackData;

typedef struct PspGeListArgs
	{
	unsigned int	size;
	PspGeContext*	context;
	u32 numStacks;
	SceGeStack *stacks;
} PspGeListArgs;

typedef struct PspGeBreakParam {
	unsigned int	buf[4];
} PspGeBreakParam;

typedef struct
	{
	unsigned int stack[8];
} PspGeStack;


// guInternal.h
typedef void (*GuCallback)(int);
typedef struct
	{
	GuCallback sig;
	GuCallback fin;
	short signal_history[16];
	int signal_offset;
	int kernel_event_flag;
	int ge_callback_id;
	GuSwapBuffersCallback swapBuffersCallback;
	int swapBuffersBehaviour;
} GuSettings;

typedef struct
	{
	unsigned int* start;
	unsigned int* current;
	int parent_context;
} GuDisplayList;

typedef struct
	{
	GuDisplayList list;
	int scissor_enable;
	int scissor_start[2];
	int scissor_end[2];
	int near_plane;
	int far_plane;
	int depth_offset;
	int fragment_2x;
	int texture_function;
	int texture_proj_map_mode;
	int texture_map_mode;
	int sprite_mode[4];
	unsigned int clear_color;
	unsigned int clear_stencil;
	unsigned int clear_depth;
	int texture_mode;
} GuContext;

typedef struct
	{
	int pixel_size;
	int frame_width;
	void* frame_buffer;
	void* disp_buffer;
	void* depth_buffer;
	int depth_width;
	int width;
	int height;
} GuDrawBuffer;

typedef struct
	{
	unsigned char enable;
	unsigned char type;
	unsigned char xpos;
	unsigned char ypos;
	unsigned char zpos;
	unsigned char xdir;
	unsigned char ydir;
	unsigned char zdir;
	unsigned char ambient;
	unsigned char diffuse;
	unsigned char specular;
	unsigned char constant;
	unsigned char linear;
	unsigned char quadratic;
	unsigned char exponent;
	unsigned char cutoff;
} GuLightSettings;


// pspimpose_driver.h
typedef int SceImposeParam;

// pspiofilemgr_kernel.h
typedef struct PspIoDrvArg
	{
	struct PspIoDrv *drv;
	void *arg;
} PspIoDrvArg;

typedef struct PspIoDrvFileArg
	{
	u32 unk1;
	u32 fs_num;
	PspIoDrvArg *drv;
	u32 unk2;
	void *arg;
} PspIoDrvFileArg;

typedef struct PspIoDrvFuncs
	{
	int (*IoInit)(PspIoDrvArg* arg);
	int (*IoExit)(PspIoDrvArg* arg);
	int (*IoOpen)(PspIoDrvFileArg *arg, char *file, int flags, SceMode mode);
	int (*IoClose)(PspIoDrvFileArg *arg);
	int (*IoRead)(PspIoDrvFileArg *arg, char *data, int len);
	int (*IoWrite)(PspIoDrvFileArg *arg, const char *data, int len);
	SceOff (*IoLseek)(PspIoDrvFileArg *arg, SceOff ofs, int whence);
	int (*IoIoctl)(PspIoDrvFileArg *arg, unsigned int cmd, void *indata, int inlen, void *outdata, int outlen);
	int (*IoRemove)(PspIoDrvFileArg *arg, const char *name);
	int (*IoMkdir)(PspIoDrvFileArg *arg, const char *name, SceMode mode);
	int (*IoRmdir)(PspIoDrvFileArg *arg, const char *name);
	int (*IoDopen)(PspIoDrvFileArg *arg, const char *dirname);
	int (*IoDclose)(PspIoDrvFileArg *arg);
	int (*IoDread)(PspIoDrvFileArg *arg, SceIoDirent *dir);
	int (*IoGetstat)(PspIoDrvFileArg *arg, const char *file, SceIoStat *stat);
	int (*IoChstat)(PspIoDrvFileArg *arg, const char *file, SceIoStat *stat, int bits);
	int (*IoRename)(PspIoDrvFileArg *arg, const char *oldname, const char *newname);
	int (*IoChdir)(PspIoDrvFileArg *arg, const char *dir);
	int (*IoMount)(PspIoDrvFileArg *arg);
	int (*IoUmount)(PspIoDrvFileArg *arg);
	int (*IoDevctl)(PspIoDrvFileArg *arg, const char *devname, unsigned int cmd, void *indata, int inlen, void *outdata, int outlen);
	int (*IoUnk21)(PspIoDrvFileArg *arg);
} PspIoDrvFuncs;

typedef struct PspIoDrv
	{
	const char *name;
	u32 dev_type;
	u32 unk2;
	const char *name2;
	PspIoDrvFuncs *funcs;
} PspIoDrv;


// pspkdebug.h
typedef void (*PspDebugPutChar)(unsigned short* args, unsigned int ch);

// psploadcore.h
typedef struct SceModule {
	struct SceModule	*next;
	unsigned short		attribute;
	unsigned char		version[2];
	char				modname[27];
	char				terminal;
	unsigned int		unknown1;
	unsigned int		unknown2;
	SceUID				modid;
	unsigned int		unknown3[4];
	void *				ent_top;
	unsigned int		ent_size;
	void *				stub_top;
	unsigned int		stub_size;
	unsigned int		unknown4[4];
	unsigned int		entry_addr;
	unsigned int		gp_value;
	unsigned int		text_addr;
	unsigned int		text_size;
	unsigned int		data_size;
	unsigned int		bss_size;
	unsigned int		nsegment;
	unsigned int		segmentaddr[4];
	unsigned int		segmentsize[4];
} __attribute__((packed)) SceModule;

typedef struct SceLibraryEntryTable {
	const char *		libname;
	unsigned char		version[2];
	unsigned short		attribute;
	unsigned char		len;
	unsigned char		vstubcount;
	unsigned short		stubcount;
	void *				entrytable;
} SceLibraryEntryTable;

typedef struct SceLibraryStubTable {
	const char *		libname;
	unsigned char		version[2];
	unsigned short		attribute;
	unsigned char		len;
	unsigned char		vstubcount;
	unsigned short		stubcount;
	unsigned int *		nidtable;
	void *				stubtable;
	void *				vstubtable;
} SceLibraryStubTable;


// psploadexec_kernel.h
struct SceKernelLoadExecVSHParam {
	SceSize     size;
	SceSize     args;
	void * argp;
	const char * key;
	u32 vshmain_args_size;
	void *vshmain_args;
	char *configfile;
	u32 unk4;
	u32 unk5;
};


// pspsysclib.h
typedef void (*prnt_callback)(void *ctx, int ch);

// pspsysevent.h
typedef struct PspSysEventHandler _PspSysEventHandler;
typedef int (*PspSysEventHandlerFunc)(int ev_id, char* ev_name, void* param, int* result);
typedef struct PspSysEventHandler{
	int size;
	char* name;
	int type_mask;
	int (*handler)(int ev_id, char* ev_name, void* param, int* result);
	int r28;
	int busy;
	_PspSysEventHandler *next;
	int reserved[9];
}PspSysEventHandler;


// pspsysmem_kernel.h
typedef struct _PspSysmemPartitionInfo
	{
	SceSize size;
	unsigned int startaddr;
	unsigned int memsize;
	unsigned int attr;
} PspSysmemPartitionInfo;

struct _uidControlBlock {
	struct _uidControlBlock *parent;
	struct _uidControlBlock *nextChild;
	struct _uidControlBlock *type;
	u32 UID;
	char *name;
	unsigned char unk;
	unsigned char size;
	short attribute;
	struct _uidControlBlock *nextEntry;
} __attribute__((packed));

typedef struct _uidControlBlock uidControlBlock;

// pspsystimer.h
typedef int SceSysTimerId;

// pspthreadman_kernel.h
struct SceThreadContext {
	unsigned int   type;
	unsigned int   gpr[31];
	unsigned int   fpr[32];
	unsigned int   fc31;
	unsigned int   hi;
	unsigned int   lo;
	unsigned int   SR;
	unsigned int   EPC;
	unsigned int   field_114;
	unsigned int   field_118;
};

struct SceSCContext
	{
	unsigned int status;
	unsigned int epc;
	unsigned int sp;
	unsigned int ra;
	unsigned int k1;
	unsigned int unk[3];
};

typedef struct SceKernelThreadKInfo {
	SceSize     size;
	char    	name[32];
	SceUInt     attr;
	int     	status;
	SceKernelThreadEntry    entry;
	void *  	stack;
	int     	stackSize;
	void *		kstack;
	void *		kstackSize;
	void *  	gpReg;
	SceSize     args;
	void *      argp;
	int     	initPriority;
	int     	currentPriority;
	int     	waitType;
	SceUID  	waitId;
	int     	wakeupCount;
	SceKernelSysClock   runClocks;
	#if _PSP_FW_VERSION >= 200
	SceUInt unk3;
	#endif
	SceUInt     intrPreemptCount;
	SceUInt     threadPreemptCount;
	SceUInt     releaseCount;
	struct SceThreadContext *thContext;
	float *      vfpuContext;
	void  *      retAddr;
	SceUInt      unknown1;
	struct SceSCContext *scContext;
} SceKernelThreadKInfo;


// stdio.h
typedef long fpos_t;
typedef struct {
	int  type;
	int  fd;
	int  cnt;
	int  flag;
	int  has_putback;
	u8   putback;
} FILE;


// stdlib.h
typedef struct {
	int quot;
	int rem;
} div_t;

typedef struct {
	long quot;
	long rem;
} ldiv_t;

typedef struct {
	long long quot;
	long long rem;
} lldiv_t;


// time.h
typedef unsigned long clock_t;
typedef unsigned long time_t;
struct tm
	{
	int	tm_sec;
	int	tm_min;
	int	tm_hour;
	int	tm_mday;
	int	tm_mon;
	int	tm_year;
	int	tm_wday;
	int	tm_yday;
	int	tm_isdst;
};


// pspmp3.h
typedef struct SceMp3InitArg {
	SceUInt32	mp3StreamStart;
	SceUInt32	unk1;
	SceUInt32	mp3StreamEnd;
	SceUInt32	unk2;
	SceVoid*	mp3Buf;
	SceInt32	mp3BufSize;
	SceVoid*	pcmBuf;
	SceInt32	pcmBufSize;
} SceMp3InitArg;


// pspmpeg.h
typedef ScePVoid SceMpeg;
typedef SceVoid  SceMpegStream;
typedef SceInt32 (*sceMpegRingbufferCB)(ScePVoid pData, SceInt32 iNumPackets, ScePVoid pParam);
typedef struct SceMpegRingbuffer
	{
	SceInt32			iPackets;
	SceUInt32			iUnk0;
	SceUInt32			iUnk1;
	SceUInt32			iUnk2;
	SceUInt32			iUnk3;
	ScePVoid			pData;
	sceMpegRingbufferCB	Callback;
	ScePVoid			pCBparam;
	SceUInt32			iUnk4;
	SceUInt32			iUnk5;
	SceMpeg				pSceMpeg;
} SceMpegRingbuffer;

typedef struct SceMpegAu
	{
	SceUInt32			iPtsMSB;
	SceUInt32			iPts;
	SceUInt32			iDtsMSB;
	SceUInt32			iDts;
	SceUInt32			iEsBuffer;
	SceUInt32			iAuSize;
} SceMpegAu;

typedef struct SceMpegAvcMode
	{
	SceInt32			iUnk0;
	SceInt32			iPixelFormat;
} SceMpegAvcMode;


// pspmpegbase.h
typedef struct SceMpegLLI
	{
	ScePVoid pSrc;
	ScePVoid pDst;
	ScePVoid Next;
	SceInt32 iSize;
} __attribute__((aligned(64))) SceMpegLLI;

typedef struct SceMpegYCrCbBuffer
	{
	SceInt32	iFrameBufferHeight16;
	SceInt32	iFrameBufferWidth16;
	SceInt32	iUnknown;
	SceInt32	iUnknown2;
	ScePVoid	pYBuffer;
	ScePVoid	pYBuffer2;
	ScePVoid	pCrBuffer;
	ScePVoid	pCbBuffer;
	ScePVoid	pCrBuffer2;
	ScePVoid	pCbBuffer2;
	SceInt32	iFrameHeight;
	SceInt32	iFrameWidth;
	SceInt32	iFrameBufferWidth;
	SceInt32	iUnknown3[11];
} __attribute__((aligned(64))) SceMpegYCrCbBuffer;


// psphttp.h
typedef void *(*PspHttpMallocFunction)(SceSize size);
typedef void *(*PspHttpReallocFunction)(void *p, SceSize size);
typedef void (*PspHttpFreeFunction)(void *p);
typedef int (*PspHttpPasswordCB)(

// pspnet.h
typedef struct SceNetMallocStat
	{
	int pool;
	int maximum;
	int free;
} SceNetMallocStat;


// pspnet_adhoc.h
typedef struct pdpStatStruct
	{
	struct pdpStatStruct *next;
	int pdpId;
	unsigned char mac[6];
	unsigned short port;
	unsigned int rcvdData;
} pdpStatStruct;

typedef struct ptpStatStruct
	{
	struct ptpStatStruct *next;
	int ptpId;
	unsigned char mac[6];
	unsigned char peermac[6];
	unsigned short port;
	unsigned short peerport;
	unsigned int sentData;
	unsigned int rcvdData;
	int unk1;
} ptpStatStruct;


// pspnet_adhocctl.h
struct productStruct
	{
	int unknown;
	char product[9];
	char unk[3];
};

struct SceNetAdhocctlPeerInfo
	{
	struct SceNetAdhocctlPeerInfo *next;
	char nickname[128];
	unsigned char mac[6];
	unsigned char unknown[6];
	unsigned long timestamp;
};

struct SceNetAdhocctlScanInfo
	{
	struct SceNetAdhocctlScanInfo *next;
	int channel;
	char name[8];
	unsigned char bssid[6];
	unsigned char unknown[2];
	int unknown2;
};

struct SceNetAdhocctlGameModeInfo
	{
	int count;
	unsigned char macs[16][6];
};

struct SceNetAdhocctlParams
	{
	int channel;
	char name[8];
	unsigned char bssid[6];
	char nickname[128];
};

typedef void (*sceNetAdhocctlHandler)(int flag, int error, void *unknown);

// pspnet_adhocmatching.h
struct pspAdhocMatchingMember
	{
	struct pspAdhocMatchingMember *next;
	unsigned char mac[6];
	char unknown[2];
};

struct pspAdhocPoolStat
	{
	int size;
	int maxsize;
	int freesize;
};

typedef void (*pspAdhocMatchingCallback)(int matchingid, int event, unsigned char *mac, int optlen, void *optdata);

// pspnet_apctl.h
typedef void (*sceNetApctlHandler)(int oldState, int newState, int event, int error, void *pArg);

// pspopenpsid.h
typedef struct PspOpenPSID
	{
	unsigned char data[16];
} PspOpenPSID;


// psppower.h
typedef void (*powerCallback_t)(int unknown, int powerInfo);

// pspreg.h
typedef unsigned int REGHANDLE;
struct RegParam
	{
	unsigned int regtype;
	char name[256];
	unsigned int namelen;
	unsigned int unk2;
	unsigned int unk3;
};


// psprtc.h
typedef struct {
	u16 year;
	u16 month;
	u16 day;
	u16 hour;
	u16 minutes;
	u16 seconds;
	u32 microseconds;
} pspTime;


// geometry.h
typedef struct
	{
	ScePspFVector2 texture;
	u32 color;
	ScePspFVector3 normal;
	ScePspFVector3 position;
} TCNPVertex;

typedef struct
	{
	ScePspFVector2 texture;
	u32 color;
	ScePspFVector3 position;
} TCPVertex;

typedef struct
	{
	ScePspFVector2 texture;
	ScePspFVector3 position;
} TPVertex;

typedef struct
	{
	ScePspFVector3 normal;
	ScePspFVector3 position;
} NPVertex;


// menu.h
typedef struct MenuItem
	{
	const char* name;
	MenuItemType type;
	int id;
	int data;
	int state;
	struct MenuItem* parent;
	struct MenuItem* next;
	struct MenuItem* children;
	struct MenuItem* selected;
} MenuItem;

typedef struct MenuContext
	{
	int open;
	SceCtrlData lastState;
	MenuItem* root;
	MenuItem* active;
} MenuContext;


// pspsircs.h
struct sircs_data {
	u8 type;
	u8 cmd;
	u16 dev;
} __packed__;


// pspumd.h
typedef struct pspUmdInfo
	{
	unsigned int size;
	unsigned int type;
} pspUmdInfo;

typedef int (*UmdCallback)(int unknown, int event);

// pspusbbus.h
struct UsbInterface
	{
	int expect_interface;
	int unk8;
	int num_interface;
};

struct UsbEndpoint
	{
	int endpnum;
	int unk2;
	int unk3;
};

struct StringDescriptor
	{
	unsigned char bLength;
	unsigned char bDescriptorType;
	short bString[32];
} __attribute__((packed));

struct DeviceDescriptor
	{
	unsigned char bLength;
	unsigned char bDescriptorType;
	unsigned short bcdUSB;
	unsigned char bDeviceClass;
	unsigned char bDeviceSubClass;
	unsigned char bDeviceProtocol;
	unsigned char bMaxPacketSize;
	unsigned short idVendor;
	unsigned short idProduct;
	unsigned short bcdDevice;
	unsigned char iManufacturer;
	unsigned char iProduct;
	unsigned char iSerialNumber;
	unsigned char bNumConfigurations;
} __attribute__((packed));

struct ConfigDescriptor
	{
	unsigned char bLength;
	unsigned char bDescriptorType;
	unsigned short wTotalLength;
	unsigned char bNumInterfaces;
	unsigned char bConfigurationValue;
	unsigned char iConfiguration;
	unsigned char bmAttributes;
	unsigned char bMaxPower;
} __attribute__((packed));

struct InterfaceDescriptor
	{
	unsigned char bLength;
	unsigned char bDescriptorType;
	unsigned char bInterfaceNumber;
	unsigned char bAlternateSetting;
	unsigned char bNumEndpoints;
	unsigned char bInterfaceClass;
	unsigned char bInterfaceSubClass;
	unsigned char bInterfaceProtocol;
	unsigned char iInterface;
} __attribute__((packed));

struct EndpointDescriptor
	{
	unsigned char bLength;
	unsigned char bDescriptorType;
	unsigned char bEndpointAddress;
	unsigned char bmAttributes;
	unsigned short wMaxPacketSize;
	unsigned char bInterval;
} __attribute__((packed));

struct UsbInterfaces
	{
	struct InterfaceDescriptor *infp[2];
	unsigned int num;
};

struct UsbConfiguration
	{
	struct ConfigDescriptor *confp;
	struct UsbInterfaces *infs;
	struct InterfaceDescriptor *infp;
	struct EndpointDescriptor *endp;
};

struct UsbData
	{
	unsigned char devdesc[20];
	struct Config
	{
	void *pconfdesc;
	void *pinterfaces;
	void *pinterdesc;
	void *pendp;
} config;

struct ConfDesc
	{
	unsigned char desc[12];
	void *pinterfaces;
} confdesc;

struct Interfaces
	{
	void *pinterdesc[2];
	unsigned int intcount;
} interfaces;

struct InterDesc
	{
	unsigned char desc[12];
	void *pendp;
	unsigned char pad[32];
} interdesc;

struct Endp
	{
	unsigned char desc[16];
} endp[4];

struct DeviceRequest
	{
	unsigned char bmRequestType;
	unsigned char bRequest;
	unsigned short wValue;
	unsigned short wIndex;
	unsigned short wLength;
} __attribute__((packed));

struct UsbDriver
	{
	const char *name;
	int endpoints;
	struct UsbEndpoint *endp;
	struct UsbInterface *intp;
	void *devp_hi;
	void *confp_hi;
	void *devp;
	void *confp;
	struct StringDescriptor *str;
	int (*recvctl)(int arg1, int arg2, struct DeviceRequest *req);
	int (*func28)(int arg1, int arg2, int arg3);
	int (*attach)(int speed, void *arg2, void *arg3);
	int (*detach)(int arg1, int arg2, int arg3);
	int unk34;
	int (*start_func)(int size, void *args);
	int (*stop_func)(int size, void *args);
	struct UsbDriver *link;
};

struct UsbdDeviceReq
	{
	struct UsbEndpoint *endp;
	void *data;
	int  size;
	int  unkc;
	void *func;
	int  recvsize;
	int  retcode;
	int  unk1c;
	void *arg;
	void *link;
};


// pspusbcam.h
typedef struct PspUsbCamSetupStillParam {
	int size;
	int resolution;
	int	jpegsize;
	int reverseflags;
	int delay;
	int complevel;
} PspUsbCamSetupStillParam;

typedef struct PspUsbCamSetupStillExParam {
	int size;
	u32 unk;
	int resolution;
	int jpegsize;
	int complevel;
	u32 unk2;
	u32 unk3;
	int flip;
	int mirror;
	int delay;
	u32 unk4[5];
} PspUsbCamSetupStillExParam;

typedef struct PspUsbCamSetupVideoParam {
	int size;
	int resolution;
	int framerate;
	int wb;
	int saturation;
	int brightness;
	int contrast;
	int sharpness;
	int effectmode;
	int framesize;
	u32 unk;
	int evlevel;
} PspUsbCamSetupVideoParam;

typedef struct PspUsbCamSetupVideoExParam {
	int size;
	u32 unk;
	int resolution;
	int framerate;
	u32 unk2;
	u32 unk3;
	int wb;
	int saturation;
	int brightness;
	int contrast;
	int sharpness;
	u32 unk4;
	u32 unk5;
	u32 unk6[3];
	int effectmode;
	u32 unk7;
	u32 unk8;
	u32 unk9;
	u32 unk10;
	u32 unk11;
	int framesize;
	u32 unk12;
	int evlevel;
} PspUsbCamSetupVideoExParam;


// pspintrman.h
typedef struct tag_IntrHandlerOptionParam{
	int size;
	u32	entry;
	u32	common;
	u32	gp;
	u16	intr_code;
	u16	sub_count;
	u16	intr_level;
	u16	enabled;
	u32	calls;
	u32	field_1C;
	u32	total_clock_lo;
	u32	total_clock_hi;
	u32	min_clock_lo;
	u32	min_clock_hi;
	u32	max_clock_lo;
	u32	max_clock_hi;
} PspIntrHandlerOptionParam;


// pspiofilemgr_dirent.h
typedef struct SceIoDirent {
	SceIoStat 	d_stat;
	char 		d_name[256];
	void * 		d_private;
	int 		dummy;
} SceIoDirent;


// pspiofilemgr_stat.h
typedef struct SceIoStat {
	SceMode 		st_mode;
	unsigned int 	st_attr;
	SceOff 			st_size;
	ScePspDateTime 	st_ctime;
	ScePspDateTime 	st_atime;
	ScePspDateTime 	st_mtime;
	unsigned int 	st_private[6];
} SceIoStat;


// psploadexec.h
struct SceKernelLoadExecParam {
	SceSize     size;
	SceSize     args;
	void *  argp;
	const char *    key;
};


// pspmoduleexport.h
struct _PspLibraryEntry {
	const char *	name;
	unsigned short	version;
	unsigned short	attribute;
	unsigned char	entLen;
	unsigned char	varCount;
	unsigned short	funcCount;
	void *			entrytable;
};


// pspmoduleinfo.h
typedef struct _scemoduleinfo {
	unsigned short		modattribute;
	unsigned char		modversion[2];
	char			modname[27];
	char			terminal;
	void *			gp_value;
	void *			ent_top;
	void *			ent_end;
	void *			stub_top;
	void *			stub_end;
} _sceModuleInfo;

typedef const _sceModuleInfo SceModuleInfo;

// pspmodulemgr.h
typedef struct SceKernelLMOption {
	SceSize 		size;
	SceUID 			mpidtext;
	SceUID 			mpiddata;
	unsigned int 	flags;
	char 			position;
	char 			access;
	char 			creserved[2];
} SceKernelLMOption;

typedef struct SceKernelSMOption {
	SceSize 		size;
	SceUID 			mpidstack;
	SceSize 		stacksize;
	int 			priority;
	unsigned int 	attribute;
} SceKernelSMOption;

typedef struct SceKernelModuleInfo {
	SceSize 		size;
	char 			nsegment;
	char 			reserved[3];
	int 			segmentaddr[4];
	int 			segmentsize[4];
	unsigned int 	entry_addr;
	unsigned int 	gp_value;
	unsigned int 	text_addr;
	unsigned int 	text_size;
	unsigned int 	data_size;
	unsigned int 	bss_size;
	unsigned short  attribute;
	unsigned char   version[2];
	char            name[28];
} SceKernelModuleInfo;


// pspsysmem.h
typedef int SceKernelSysMemAlloc_t;

// pspthreadman.h
typedef struct SceKernelSysClock {
	SceUInt32   low;
	SceUInt32   hi;
} SceKernelSysClock;

typedef int (*SceKernelThreadEntry)(SceSize args, void *argp);
typedef struct SceKernelThreadOptParam {
	SceSize 	size;
	SceUID 		stackMpid;
} SceKernelThreadOptParam;

typedef struct SceKernelThreadInfo {
	SceSize     size;
	char    	name[32];
	SceUInt     attr;
	int     	status;
	SceKernelThreadEntry    entry;
	void *  	stack;
	int     	stackSize;
	void *  	gpReg;
	int     	initPriority;
	int     	currentPriority;
	int     	waitType;
	SceUID  	waitId;
	int     	wakeupCount;
	int     	exitStatus;
	SceKernelSysClock   runClocks;
	SceUInt     intrPreemptCount;
	SceUInt     threadPreemptCount;
	SceUInt     releaseCount;
} SceKernelThreadInfo;

typedef struct SceKernelThreadRunStatus {
	SceSize 	size;
	int 		status;
	int 		currentPriority;
	int 		waitType;
	int 		waitId;
	int 		wakeupCount;
	SceKernelSysClock runClocks;
	SceUInt 	intrPreemptCount;
	SceUInt 	threadPreemptCount;
	SceUInt 	releaseCount;
} SceKernelThreadRunStatus;

typedef struct SceKernelSemaOptParam {
	SceSize 	size;
} SceKernelSemaOptParam;

typedef struct SceKernelSemaInfo {
	SceSize 	size;
	char 		name[32];
	SceUInt 	attr;
	int 		initCount;
	int 		currentCount;
	int 		maxCount;
	int 		numWaitThreads;
} SceKernelSemaInfo;

typedef struct SceKernelEventFlagInfo {
	SceSize 	size;
	char 		name[32];
	SceUInt 	attr;
	SceUInt 	initPattern;
	SceUInt 	currentPattern;
	int 		numWaitThreads;
} SceKernelEventFlagInfo;

struct SceKernelEventFlagOptParam {
	SceSize 	size;
};

typedef struct SceKernelEventFlagOptParam SceKernelEventFlagOptParam;
typedef struct SceKernelMbxOptParam {
	SceSize 	size;
} SceKernelMbxOptParam;

typedef struct SceKernelMbxInfo {
	SceSize 	size;
	char 		name[32];
	SceUInt 	attr;
	int 		numWaitThreads;
	int 		numMessages;
	void		*firstMessage;
} SceKernelMbxInfo;

typedef struct SceKernelMsgPacket {
	struct SceKernelMsgPacket *next;
	SceUChar    msgPriority;
	SceUChar    dummy[3];
} SceKernelMsgPacket;

typedef SceUInt (*SceKernelAlarmHandler)(void *common);
typedef struct SceKernelAlarmInfo {
	SceSize		size;
	SceKernelSysClock schedule;
	SceKernelAlarmHandler handler;
	void *		common;
} SceKernelAlarmInfo;

typedef int (*SceKernelCallbackFunction)(int arg1, int arg2, void *arg);
typedef struct SceKernelCallbackInfo {
	SceSize 	size;
	char 	name[32];
	SceUID 	threadId;
	SceKernelCallbackFunction 	callback;
	void * 	common;
	int 	notifyCount;
	int 	notifyArg;
} SceKernelCallbackInfo;

typedef struct SceKernelSystemStatus {
	SceSize 	size;
	SceUInt 	status;
	SceKernelSysClock 	idleClocks;
	SceUInt 	comesOutOfIdleCount;
	SceUInt 	threadSwitchCount;
	SceUInt 	vfpuSwitchCount;
} SceKernelSystemStatus;

typedef struct SceKernelMppInfo {
	SceSize 	size;
	char 	name[32];
	SceUInt 	attr;
	int 	bufSize;
	int 	freeSize;
	int 	numSendWaitThreads;
	int 	numReceiveWaitThreads;
} SceKernelMppInfo;

struct SceKernelVplOptParam {
	SceSize 	size;
};

typedef struct SceKernelVplInfo {
	SceSize 	size;
	char 	name[32];
	SceUInt 	attr;
	int 	poolSize;
	int 	freeSize;
	int 	numWaitThreads;
} SceKernelVplInfo;

struct SceKernelFplOptParam {
	SceSize 	size;
};

typedef struct SceKernelFplInfo {
	SceSize 	size;
	char 	name[32];
	SceUInt 	attr;
	int 	blockSize;
	int 	numBlocks;
	int 	freeBlocks;
	int 	numWaitThreads;
} SceKernelFplInfo;

struct SceKernelVTimerOptParam {
	SceSize 	size;
};

typedef SceUInt (*SceKernelVTimerHandler)(SceUID uid, SceKernelSysClock *, SceKernelSysClock *, void *);
typedef SceUInt (*SceKernelVTimerHandlerWide)(SceUID uid, SceInt64, SceInt64, void *);
typedef struct SceKernelVTimerInfo {
	SceSize 	size;
	char 	name[32];
	int 	active;
	SceKernelSysClock 	base;
	SceKernelSysClock 	current;
	SceKernelSysClock 	schedule;
	SceKernelVTimerHandler 	handler;
	void * 	common;
} SceKernelVTimerInfo;

typedef int (*SceKernelThreadEventHandler)(int mask, SceUID thid, void *common);
typedef struct SceKernelThreadEventHandlerInfo {
	SceSize 	size;
	char 	name[32];
	SceUID 	threadId;
	int 	mask;
	SceKernelThreadEventHandler 	handler;
	void * 	common;
} SceKernelThreadEventHandlerInfo;


// psputils.h
typedef struct _SceKernelUtilsMt19937Context {
	unsigned int 	count;
	unsigned int 	state[624];
} SceKernelUtilsMt19937Context;

typedef struct _SceKernelUtilsMd5Context {
	unsigned int 	h[4];
	unsigned int 	pad;
	SceUShort16 	usRemains;
	SceUShort16 	usComputed;
	SceULong64 	ullTotalLen;
	unsigned char 	buf[64];
} SceKernelUtilsMd5Context;

typedef struct _SceKernelUtilsSha1Context {
	unsigned int 	h[5];
	SceUShort16 	usRemains;
	SceUShort16 	usComputed;
	SceULong64 	ullTotalLen;
	unsigned char 	buf[64];
} SceKernelUtilsSha1Context;


// psputility.h
typedef struct
	{
	unsigned int size;
	int language;
	int buttonSwap;
	int graphicsThread;
	int accessThread;
	int fontThread;
	int soundThread;
	int result;
	int reserved[4];
} pspUtilityDialogCommon;


// psputility_gamesharing.h
typedef struct _pspUtilityGameSharingParams
	{
	pspUtilityDialogCommon base;
	int unknown1;
	int unknown2;
	char name[8];
	int unknown3;
	int unknown4;
	int unknown5;
	int result;
	char *filepath;
	pspUtilityGameSharingMode mode;
	pspUtilityGameSharingDataType datatype;
	void *data;
	unsigned int datasize;
} pspUtilityGameSharingParams;


// psputility_htmlviewer.h
typedef struct pspUtilityHtmlViewerParam
	{
	pspUtilityDialogCommon base;
	void* memaddr;
	unsigned int memsize;
	int	unknown1;
	int	unknown2;
	char* initialurl;
	unsigned int numtabs;
	unsigned int interfacemode;
	unsigned int options;
	char* dldirname;
	char* dlfilename;
	char* uldirname;
	char* ulfilename;
	unsigned int cookiemode;
	unsigned int unknown3;
	char* homeurl;
	unsigned int textsize;
	unsigned int displaymode;
	unsigned int connectmode;
	unsigned int disconnectmode;
	unsigned int memused;
	int unknown4[10];
} pspUtilityHtmlViewerParam;


// psputility_msgdialog.h
typedef struct _pspUtilityMsgDialogParams
	{
	pspUtilityDialogCommon base;
	int unknown;
	pspUtilityMsgDialogMode mode;
	unsigned int errorValue;
	char message[512];
	int options;
	pspUtilityMsgDialogPressed buttonPressed;
} pspUtilityMsgDialogParams;


// psputility_netconf.h
struct pspUtilityNetconfAdhoc
	{
	unsigned char name[8];
	unsigned int timeout;
};

typedef struct _pspUtilityNetconfData
	{
	pspUtilityDialogCommon base;
	int action;
	struct pspUtilityNetconfAdhoc *adhocparam;
	int hotspot;
	int hotspot_connected;
	int wifisp;
} pspUtilityNetconfData;


// psputility_netparam.h
typedef union {
	u32 asUint;
	char asString[128];
} netData;


// psputility_osk.h
typedef struct _SceUtilityOskData
	{
	int unk_00;
	int unk_04;
	int language;
	int unk_12;
	int inputtype;
	int lines;
	int unk_24;
	unsigned short* desc;
	unsigned short* intext;
	int outtextlength;
	unsigned short* outtext;
	int result;
	int outtextlimit;
} SceUtilityOskData;

typedef struct _SceUtilityOskParams
	{
	pspUtilityDialogCommon base;
	int datacount;
	SceUtilityOskData* data;
	int state;
	int unk_60;
} SceUtilityOskParams;


// psputility_savedata.h
typedef struct PspUtilitySavedataSFOParam
	{
	char title[0x80];
	char savedataTitle[0x80];
	char detail[0x400];
	unsigned char parentalLevel;
	unsigned char unknown[3];
} PspUtilitySavedataSFOParam;

typedef struct PspUtilitySavedataFileData {
	void *buf;
	SceSize bufSize;
	SceSize size;
	int unknown;
} PspUtilitySavedataFileData;

typedef struct PspUtilitySavedataListSaveNewData
	{
	PspUtilitySavedataFileData icon0;
	char *title;
} PspUtilitySavedataListSaveNewData;

typedef struct SceUtilitySavedataParam
	{
	pspUtilityDialogCommon base;
	PspUtilitySavedataMode mode;
	int unknown1;
	int overwrite;
	char gameName[13];
	char reserved[3];
	char saveName[20];
	char (*saveNameList)[20];
	char fileName[13];
	char reserved1[3];
	void *dataBuf;
	SceSize dataBufSize;
	SceSize dataSize;
	PspUtilitySavedataSFOParam sfoParam;
	PspUtilitySavedataFileData icon0FileData;
	PspUtilitySavedataFileData icon1FileData;
	PspUtilitySavedataFileData pic1FileData;
	PspUtilitySavedataFileData snd0FileData;
	PspUtilitySavedataListSaveNewData *newData;
	PspUtilitySavedataFocus focus;
	int unknown2[4];
	#if _PSP_FW_VERSION >= 200
	char key[16];
	char unknown3[20];
	#endif
} SceUtilitySavedataParam;


// pspvfpu.h
typedef unsigned char vfpumatrixset_t;
void pspvfpu_use_matrices(struct pspvfpu_context *context,
	vfpumatrixset_t keepset, vfpumatrixset_t tempset);
	#ifdef __cplusplus
}


// pspchnnlsv.h
typedef struct _pspChnnlsvContext1 {
	int	mode;
	char	buffer1[0x10];
	char    buffer2[0x10];
	int	unknown;
} pspChnnlsvContext1;

typedef struct _pspChnnlsvContext2 {
	char    unknown[0x100];
} pspChnnlsvContext2;


// elftypes.h
struct ElfSection
	{
	u32 iName;
	u32 iType;
	u32 iFlags;
	u32 iAddr;
	u32 iOffset;
	u32 iSize;
	u32 iLink;
	u32 iInfo;
	u32 iAddralign;
	u32 iEntsize;
	u8 *pData;
	char szName[ELF_SECT_MAX_NAME];
	int iIndex;
	struct ElfSection *pRef;
	int blOutput;
};

struct ElfProgram
	{
	u32 iType;
	u32 iOffset;
	u32 iVaddr;
	u32 iPaddr;
	u32 iFilesz;
	u32 iMemsz;
	u32 iFlags;
	u32 iAlign;
	u8  *pData;
};

struct ElfHeader
	{
	u32 iMagic;
	u32 iClass;
	u32 iData;
	u32 iIdver;
	u32 iType;
	u32 iMachine;
	u32 iVersion;
	u32 iEntry;
	u32 iPhoff;
	u32 iShoff;
	u32 iFlags;
	u32 iEhsize;
	u32 iPhentsize;
	u32 iPhnum;
	u32 iShentsize;
	u32 iShnum;
	u32 iShstrndx;
};

struct ElfReloc
	{
	const char* secname;
	u32 base;
	u32 type;
	u32 symbol;
	u32 offset;
	u32 addr;
};

typedef u32 Elf32_Addr;
typedef u16 Elf32_Half;
typedef u32 Elf32_Off;
typedef s32 Elf32_Sword;
typedef u32 Elf32_Word;
typedef struct {
	Elf32_Word e_magic;
	u8 e_class;
	u8 e_data;
	u8 e_idver;
	u8 e_pad[9];
	Elf32_Half e_type;
	Elf32_Half e_machine;
	Elf32_Word e_version;
	Elf32_Addr e_entry;
	Elf32_Off e_phoff;
	Elf32_Off e_shoff;
	Elf32_Word e_flags;
	Elf32_Half e_ehsize;
	Elf32_Half e_phentsize;
	Elf32_Half e_phnum;
	Elf32_Half e_shentsize;
	Elf32_Half e_shnum;
	Elf32_Half e_shstrndx;
} __attribute__((packed)) Elf32_Ehdr;

typedef struct {
	Elf32_Word sh_name;
	Elf32_Word sh_type;
	Elf32_Word sh_flags;
	Elf32_Addr sh_addr;
	Elf32_Off sh_offset;
	Elf32_Word sh_size;
	Elf32_Word sh_link;
	Elf32_Word sh_info;
	Elf32_Word sh_addralign;
	Elf32_Word sh_entsize;
} __attribute__((packed)) Elf32_Shdr;

typedef struct {
	Elf32_Word p_type;
	Elf32_Off p_offset;
	Elf32_Addr p_vaddr;
	Elf32_Addr p_paddr;
	Elf32_Word p_filesz;
	Elf32_Word p_memsz;
	Elf32_Word p_flags;
	Elf32_Word p_align;
} Elf32_Phdr;

typedef struct {
	Elf32_Addr r_offset;
	Elf32_Word r_info;
} Elf32_Rel;

typedef struct {
	Elf32_Word st_name;
	Elf32_Addr st_value;
	Elf32_Word st_size;
	unsigned char st_info;
	unsigned char st_other;
	Elf32_Half st_shndx;
} __attribute__((packed)) Elf32_Sym;


// getopt.h
struct option {
	const char *name;
	int has_arg;
	int *flag;
	int val;
};


// prxtypes.h
struct PspModuleExport
	{
	u32 name;
	u32 flags;
	u32 counts;
	u32 exports;
} __attribute__((packed));

struct PspModuleImport
	{
	u32 name;
	u32 flags;
	u8  entry_size;
	u8  var_count;
	u16 func_count;
	u32 nids;
	u32 funcs;
};

struct PspModuleInfo
	{
	u32 flags;
	char name[PSP_MODULE_MAX_NAME];
	u32 gp;
	u32 exports;
	u32 exp_end;
	u32 imports;
	u32 imp_end;
};

struct PspEntry
	{
	char name[PSP_ENTRY_MAX_NAME];
	u32 nid;
	enum PspEntryType type;
	u32 addr;
	u32 nid_addr;
};

struct PspLibImport
	{
	struct PspLibImport *prev;
	struct PspLibImport *next;
	char name[PSP_LIB_MAX_NAME];
	u32 addr;
	struct PspModuleImport stub;
	struct PspEntry funcs[PSP_MAX_F_ENTRIES];
	int f_count;
	struct PspEntry vars[PSP_MAX_V_ENTRIES];
	int v_count;
};

struct PspLibExport
	{
	struct PspLibExport *prev;
	struct PspLibExport *next;
	char name[PSP_LIB_MAX_NAME];
	u32 addr;
	struct PspModuleExport stub;
	struct PspEntry funcs[PSP_MAX_F_ENTRIES];
	int f_count;
	struct PspEntry vars[PSP_MAX_V_ENTRIES];
	int v_count;
};

struct PspModule
	{
	char name[PSP_MODULE_MAX_NAME+1];
	struct PspModuleInfo info;
	u32 addr;
	struct PspLibExport *exp_head;
	struct PspLibImport *imp_head;
};


// sha1.h
typedef   unsigned long    sha1_32t;
typedef   unsigned long    sha1_32t;
typedef   unsigned int     sha1_32t;
typedef struct
	{   sha1_32t count[2];
	sha1_32t hash[5];
	sha1_32t wbuf[16];
} sha1_ctx;


// types.h
typedef uint8_t 	u8;
typedef uint16_t 	u16;
typedef uint32_t	u32;
typedef uint64_t	u64;
typedef int8_t		s8;
typedef int16_t		s16;
typedef int32_t		s32;
typedef int64_t		s64;

// crypto.h
typedef struct
	{
	int	enc_only;
	int	Nr;
	u32	ek[4*(AES_MAXROUNDS + 1)];
	u32	dk[4*(AES_MAXROUNDS + 1)];
} rijndael_ctx;

typedef struct
	{
	int	enc_only;
	int	Nr;
	u32	ek[4*(AES_MAXROUNDS + 1)];
	u32	dk[4*(AES_MAXROUNDS + 1)];
} AES_ctx;

typedef struct SHA1Context
	{
	unsigned Message_Digest[5];
	unsigned Length_Low;
	unsigned Length_High;
	unsigned char Message_Block[64];
	int Message_Block_Index;
	int Computed;
	int Corrupted;
} SHA1Context;

