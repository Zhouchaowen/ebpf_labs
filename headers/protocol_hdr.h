#define MAX_DNS_NAME_LENGTH 256

struct dnshdr {
  __u16 transaction_id;
  __u8 rd : 1;      // Recursion desired
  __u8 tc : 1;      // Truncated
  __u8 aa : 1;      // Authoritive answer
  __u8 opcode : 4;  // Opcode
  __u8 qr : 1;      // Query/response flag
  __u8 r_code : 4;  // Response code
  __u8 cd : 1;      // Checking disabled
  __u8 ad : 1;      // Authenticated data
  __u8 z : 1;       // Z reserved bit
  __u8 ra : 1;      // Recursion available
  __u16 q_count;    // Number of questions
  __u16 ans_count;  // Number of answer RRs
  __u16 auth_count; // Number of authority RRs
  __u16 add_count;  // Number of resource RRs
};
