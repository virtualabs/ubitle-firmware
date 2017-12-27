#pragma once

#include "MicroBit.h"

#define PREAMBLE          0xBC
#define PKT_COMMAND       0x01
#define PKT_RESPONSE      0x02
#define PKT_NOTIFICATION  0x04
#define MAX_PACKET_SIZE  0x0110

typedef enum {
  LK_WAITING,
  LK_RCV_PACKET,
} T_LINK_STATUS;

typedef enum {
  N_ACCESS_ADDRESS,
  N_CRC,
  N_CHANNEL_MAP,
  N_HOP_INTERVAL,
  N_HOP_INCREMENT,
  N_PACKET
} T_NOTIFICATION_TYPE, *PT_NOTIFICATION;

typedef enum {
  VERSION = 0x01,
  RESET, /* 0x02 */
  LIST_AA, /* 0x03 */
  RECOVER_AA, /* 0x04 */
  RECOVER_AA_CHM, /* 0x05 */
  RECOVER_AA_CHM_HOPINTER, /* 0x06 */
  /*
  MODE_SET,
  MODE_GET,
  NOTIFY = 0x80,
  ERROR,
  */
  DEBUG = 0x0E,
  VERBOSE = 0x0F
} T_OPERATION, *PT_OPERATION;

class Link
{
private:
  MicroBitSerial *m_serial;
  MicroBit *m_bit;

  /* Temporary payload buffer. */
  uint8_t m_payload[MAX_PACKET_SIZE];

  /* Number of bytes received so far. */
  int m_nbRecvBytes;

  /* Number of bytes expected (packet payload size). */
  int m_nbExpectedBytes;

  T_LINK_STATUS m_status;

  uint8_t crc(uint8_t *data, int size, uint8_t prevCrc);
  uint8_t crc(uint8_t *data, int size);

public:

  /* Constructor. */
  Link(MicroBit *ubit);

  /* Interface. */
  bool readPacket(PT_OPERATION ptOperation, uint8_t *pData, int *pnCount, uint8_t *pubFlags);
  bool sendPacket(T_OPERATION tOperation, uint8_t *pData, int nCount, uint8_t ubFlags);
  bool sendNotification(T_NOTIFICATION_TYPE tNotification, uint8_t *pData, int nCount);

  /* Notifications. */
  bool notifyAccessAddress(uint32_t accessAddress, int channel, uint8_t rssi);
  bool notifyCrc(uint32_t accessAddress, uint32_t crc);
  bool notifyChannelMap(uint32_t accessAddress, uint8_t *chm);
  bool notifyHopInterval(uint32_t accessAddress, uint16_t hopInterval);
  bool notifyHopIncrement(uint32_t accessAddress, uint8_t hopIncrement);
  bool notifyBlePacket(uint8_t *pPacket, int nPacketSize);

  /* Helpers. */
  bool version(uint8_t major, uint8_t minor);
  bool debug(uint8_t *pData);
  bool verbose(uint8_t *pData);
};
