#include "link.h"
#include "helpers.h"

Link::Link(MicroBit *ubit)
{
  /* Set microbit instance. */
  m_serial = &ubit->serial;
  m_bit = ubit;

  /* Upgrade the default tx buffer. */
  m_serial->baud(115200);
  m_serial->setTxBufferSize(254);
  m_serial->setRxBufferSize(254);

  /* Clear RX and TX. */
  m_serial->clearRxBuffer();
  m_serial->clearTxBuffer();

  /* Current status: waiting. */
  m_status = LK_WAITING;
  m_nbRecvBytes = 0;
}

uint8_t Link::crc(uint8_t *pData, int size, uint8_t prevCrc)
{

  for (int i=0; i<size; i++)
    prevCrc ^= pData[i];

  return prevCrc;
}

uint8_t Link::crc(uint8_t *pData, int size)
{
  return crc(pData, size, 0xff);
}



bool Link::readPacket(PT_OPERATION ptOperation, uint8_t *pData, int *pnCount, uint8_t *pubFlags)
{
  int nbBytesRead=0, i, pktSize, dataSize;
  uint8_t checksum;

  /* Pipe data in if any. */
  if (m_serial->isReadable())
  {
    nbBytesRead = (uint8_t)m_serial->read(&m_payload[m_nbRecvBytes], 1);
    if (nbBytesRead != MICROBIT_SERIAL_IN_USE)
      m_nbRecvBytes += nbBytesRead;
  }

  if (nbBytesRead > 0)
  {
    /* Packet must start with 0xBC. */
    if ((m_payload[0] == 0xBC))
    {
      if (m_nbRecvBytes>4)
      {
        /* Parse packet. */
        pktSize = m_payload[2] | (m_payload[3]<<8);
        if (m_nbRecvBytes >= (pktSize + 5))
        {
            /* Check crc. */
            checksum = crc(m_payload, pktSize + 4);
            if (checksum == m_payload[pktSize+4])
            {
              /* Fill data. */
              *ptOperation = (T_OPERATION)(m_payload[1] & 0x0F);
              *pubFlags = (m_payload[1]>>4);

              /* Copy data. */
              if (*pnCount < pktSize)
                dataSize = *pnCount;
              else
                dataSize = pktSize;

              for (i=0; i<dataSize; i++)
                pData[i] = m_payload[i+4];

              /* Chomp packet. */
              for (i=pktSize+5; i<m_nbRecvBytes; i++)
                m_payload[i - (pktSize+5)] = m_payload[i];
              m_nbRecvBytes -= (pktSize + 5);

              /* Success/ */
              return true;
            }
        }
      }
    }
    else
    {
      /* Chomp one byte. */
      for (i=1; i<m_nbRecvBytes; i++)
        m_payload[i-1] = m_payload[i];
      m_nbRecvBytes--;
    }
  }

  /* No packet waiting. */
  return false;
}

bool Link::sendPacket(T_OPERATION tOperation, uint8_t *pData, int nCount, uint8_t ubFlags)
{
  int i;
  uint8_t header[4];
  uint8_t checksum = 0xff;

  /* Fill header. */
  header[0] = PREAMBLE;
  header[1] = (tOperation | ((ubFlags&0x0F) << 4));
  header[2] = (nCount & 0x00ff);
  header[3] = (nCount >> 8);

  /* Compute checksum. */
  for (i=0; i<4; i++)
      checksum ^= header[i];

  /* Send header first. */
  m_serial->send(header, 4, ASYNC);

  /* Send payload next. */
  for (i=0; i<nCount; i++)
    checksum ^= pData[i];

  m_serial->send(pData, nCount, ASYNC);

  /* Send checksum. */
  m_serial->send(&checksum, 1, ASYNC);

  return true;
}


bool Link::sendNotification(T_NOTIFICATION_TYPE tNotification, uint8_t *pData, int nCount)
{
  return sendPacket((T_OPERATION)tNotification, pData, nCount, PKT_NOTIFICATION);
}


bool Link::debug(uint8_t *pData)
{
  /* Send debug message. */
  return sendPacket(DEBUG, pData, strlen((char *)pData), PKT_RESPONSE);
}

bool Link::verbose(uint8_t *pData)
{
  /* Send debug message. */
  return sendPacket(VERBOSE, pData, strlen((char *)pData), PKT_RESPONSE);
}

bool Link::version(uint8_t major, uint8_t minor)
{
  uint8_t buffer[2];

  /* Set major and minor. */
  buffer[0] = major;
  buffer[1] = minor;

  /* Send version. */
  return sendPacket(VERSION, buffer, 2, PKT_RESPONSE);
}


bool Link::notifyAccessAddress(uint32_t accessAddress, int channel, uint8_t rssi)
{
  uint8_t buffer[6];
  uint32_t *paa = (uint32_t *)&buffer[2];

  /* Fill in the buffer. */
  buffer[0] = channel;
  buffer[1] = rssi;
  *paa = accessAddress;

  /* Send packet. */
  return sendNotification(N_ACCESS_ADDRESS, buffer, 6);
}

bool Link::notifyCrc(uint32_t accessAddress, uint32_t crc)
{
  uint8_t buffer[8];
  uint32_t *paa = (uint32_t *)&buffer[0];
  uint32_t *pcrc = (uint32_t *)&buffer[4];

  /* Fill in the buffer. */
  *paa = accessAddress;
  *pcrc = crc;

  /* Send packet. */
  return sendNotification(N_CRC, buffer, 8);
}

bool Link::notifyChannelMap(uint32_t accessAddress, uint8_t *chm)
{
  uint8_t buffer[9];
  uint32_t *paa = (uint32_t *)&buffer[0];

  /* Fill in the buffer. */
  *paa = accessAddress;
  array_to_chm(chm, &buffer[4]);

  /* Send packet. */
  return sendNotification(N_CHANNEL_MAP, buffer, 9);
}

bool Link::notifyHopInterval(uint32_t accessAddress, uint16_t hopInterval)
{
  uint8_t buffer[6];
  uint32_t *paa = (uint32_t *)&buffer[0];
  uint16_t *phi = (uint16_t *)&buffer[4];

  *paa = accessAddress;
  *phi = hopInterval;

  /* Send packet. */
  return sendNotification(N_HOP_INTERVAL, buffer, 6);
}

bool Link::notifyHopIncrement(uint32_t accessAddress, uint8_t hopIncrement)
{
  uint8_t buffer[5];
  uint32_t *paa = (uint32_t *)&buffer[0];

  *paa = accessAddress;
  buffer[4] = hopIncrement;

  /* Send packet. */
  return sendNotification(N_HOP_INCREMENT, buffer, 5);
}


bool Link::notifyBlePacket(uint8_t *pPacket, int nPacketSize)
{
  /* Send notification. */
  return sendNotification(N_PACKET, pPacket, nPacketSize);
}
