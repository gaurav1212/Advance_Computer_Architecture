//sbajpai
#define SCHEDULE_ON (scheduler_method!=0)
#define MAX_CONTEXT_SWITCH 5
#define MAX_LATENCY 100
//method on switch, must be one at a time
#define METHOD1 (scheduler_method==1)
#define METHOD2 (scheduler_method==2)
#define METHOD3 (scheduler_method==3)
#define METHOD4 (scheduler_method==4)
//parameters for method 1
#define UOPS_LIMIT_FOR_SCHEDULING_HIGH_LATENCY_METHOD1 400
//parameters for method 2
#define UOPS_WINDOW_FOR_SCHEDULING_HIGH_LATENCY_METHOD2 1000
//parameters for method 3
#define UOPS_WINDOW_FOR_SCHEDULING_HIGH_LATENCY_METHOD3 1000
#define UOP_STRIDE_FOR_METHOD3 5;
//parameters for method 4
#define CLOCK_CYCLES_FOR_METHOD4 10000

