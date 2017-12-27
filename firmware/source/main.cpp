#include "MicroBit.h"
#include "nrf_delay.h"
#include "helpers.h"
#include "sequence.h"
#include "link.h"
#include "radio.h"

#define VERSION_MAJOR   0x01
#define VERSION_MINOR   0x00

#define MAX_QUEUE_LEN   10
#define PKT_SIZE        10  /* Access Address + 2 bytes PDU + CRC */
#define MAX_PACKETS     10  /* 10 packets max. */

#define DIVIDE_ROUND(N, D) ((N) + (D)/2) / (D)

#define B(x) ((uint8_t *)x)

MicroBit uBit;
static Link *pLink;

/**
 * BLE Sniffer action.
 **/

typedef enum {
    IDLE,
    SNIFF_AA,
    RECOVER_CHM,
    RECOVER_CRC,
    RECOVER_HOPINC,
    RECOVER_HOPINTER,
    FOLLOW
} current_action_t;

typedef struct tSnifferState {
    current_action_t action;
    uint32_t access_address;
    uint32_t candidates_aa[MAX_QUEUE_LEN];
    uint8_t count_aa[MAX_QUEUE_LEN];
    uint8_t n_aa;
    uint32_t crcinit;
    uint16_t hop_interval;
    bool interval_provided;
    uint32_t hop_increment;
    uint8_t n;
    uint64_t smallest_interval;
    uint64_t prev_time;
    uint32_t observed_interval;
    uint16_t pkt_count;
    uint8_t channel;

    /* Channel map */
    uint8_t channels_mapped;
    uint8_t chm[37];
    bool chm_provided;

    bool measuring;
    bool synced;
    Ticker ticker;
    SequenceGenerator sg;
} sniffer_state_t;

static sniffer_state_t g_sniffer;
static uint8_t hexbuf[23];
static uint32_t measures;
uint8_t rx_buffer[254];                     /* Rx buffer used by RF to store packets. */

static void recover_crc(uint32_t access_address);
static void recover_hop_interval(void);
static void recover_chm();
static void recover_chm_next();
static void recover_hop_inc(void);
static void follow_connection(void);

void map_channel(int channel)
{
    if ((channel >= 0) && (channel <=37))
        g_sniffer.chm[channel] = 1;
}

uint8_t is_channel_mapped(int channel)
{
    return (g_sniffer.chm[channel] == 1);
}

uint8_t find_first_channel()
{
    int i;
    for (i=0;i<37;i++)
        if (g_sniffer.chm[i] > 0)
            return i;
    return 0xff;
}

uint8_t count_channels()
{
    uint8_t channels = 0;
    int i;

    for (i=0;i<37;i++)
        if (g_sniffer.chm[i] > 0)
            channels++;

    return channels;
}

void hop_tick()
{
    measures++;
}

static void next_channel_tick()
{
    /* Compute next channel. */
    g_sniffer.channel = g_sniffer.sg.getNextChannel();

    /* Go listening on the new channel. */
    NVIC_DisableIRQ(RADIO_IRQn);
    NRF_RADIO->EVENTS_DISABLED = 0;
    NRF_RADIO->TASKS_DISABLE = 1;
    while (NRF_RADIO->EVENTS_DISABLED == 0);

    NRF_RADIO->FREQUENCY = channel_to_freq(g_sniffer.channel);
    NRF_RADIO->DATAWHITEIV = g_sniffer.channel;

    NVIC_ClearPendingIRQ(RADIO_IRQn);
    NVIC_EnableIRQ(RADIO_IRQn);

    // enable receiver
    NRF_RADIO->SHORTS = RADIO_SHORTS_READY_START_Msk;

    // enable receiver (once enabled, it will listen)
    NRF_RADIO->EVENTS_READY = 0;
    NRF_RADIO->EVENTS_END = 0;
    NRF_RADIO->TASKS_RXEN = 1;
}

static void start_connection_follow()
{
    g_sniffer.ticker.detach();
    g_sniffer.ticker.attach_us(next_channel_tick, 1250*g_sniffer.hop_interval);

    /* Compute next channel. */
    g_sniffer.channel = g_sniffer.sg.getNextChannel();
    radio_set_channel_fast(g_sniffer.channel);
}


int seen_aa(uint32_t aa)
{
    int i,j;
    int change;
    uint32_t z;
    uint8_t x;

    /* Look for this access address in our list. */
    for (i=0; i<g_sniffer.n_aa; i++)
    {
        if (g_sniffer.candidates_aa[i] == aa)
        {
            /* We found our AA, update count. */
            if (g_sniffer.count_aa[i] < 5)
                g_sniffer.count_aa[i]++;
            return g_sniffer.count_aa[i];
        }
    }

    /* Not found, we need to add it to our list. */
    /* First, we check if there is an empty slot. */
    if (g_sniffer.n_aa < MAX_QUEUE_LEN) {
        g_sniffer.candidates_aa[g_sniffer.n_aa] = aa;
        g_sniffer.count_aa[g_sniffer.n_aa] = 1;
        g_sniffer.n_aa++;
        return 1;
    } else {
        /* If not, we sort our list, remove half the values and add our AA. */
        do
        {
            change = 0;
            for (i=0; i<(g_sniffer.n_aa-1); i++)
            {
                for (j=i+1; j<g_sniffer.n_aa; j++)
                {
                    if (g_sniffer.count_aa[i] < g_sniffer.count_aa[j])
                    {
                        x = g_sniffer.count_aa[i];
                        g_sniffer.count_aa[i] = g_sniffer.count_aa[j];
                        g_sniffer.count_aa[j] = x;
                        z = g_sniffer.candidates_aa[i];
                        g_sniffer.candidates_aa[i] = g_sniffer.candidates_aa[j];
                        g_sniffer.candidates_aa[j] = z;
                        change = 1;
                    }
                }
            }
        } while (change > 0);

        /* Remove half the values. */
        g_sniffer.n_aa /= 2;

        /* Insert our AA. */
        g_sniffer.candidates_aa[g_sniffer.n_aa] = aa;
        g_sniffer.count_aa[g_sniffer.n_aa] = 1;
        g_sniffer.n_aa++;

        return 1;
    }
}


/**
 * nRF51822 RADIO handler.
 *
 * This handler is called whenever a RADIO event occurs (IRQ).
 **/

extern "C" void RADIO_IRQHandler(void)
{
    uint32_t aa,crc_rev, crc;
    uint64_t inter, curtime;
    uint8_t candidate_pdu[2];
    int i,j;

    if (NRF_RADIO->EVENTS_READY) {
        NRF_RADIO->EVENTS_READY = 0;
        NRF_RADIO->TASKS_START = 1;
    }

    if (NRF_RADIO->EVENTS_END) {
        NRF_RADIO->EVENTS_END = 0;

        if (g_sniffer.action == SNIFF_AA) {
            g_sniffer.pkt_count++;

            /* Dewhiten bytes 4 and 5. */
            candidate_pdu[0] = rx_buffer[4];
            candidate_pdu[1] = rx_buffer[5];
            dewhiten(candidate_pdu, 2, g_sniffer.channel);
            if (((candidate_pdu[0] & 0xF3) == 1) && (candidate_pdu[1] == 0))
            {
                /* Check AA */
                aa = rx_buffer[0] | rx_buffer[1]<<8 | rx_buffer[2]<<16 | rx_buffer[3]<<24;
                if (seen_aa(aa) > 1) {
                    /* We may have a candidate AA. */
                    pLink->notifyAccessAddress(aa, g_sniffer.channel, NRF_RADIO->RSSISAMPLE);
                }
            }
            else
            {
              /* Shit right by one bit once and twice */
              for (j=0; j<2; j++)
              {
                /* Shift right. */
                for (i=0; i<9; i++)
                  rx_buffer[i] = rx_buffer[i]>>1 | ((rx_buffer[i+1]&0x01) << 7);

                /* Dewhiten candidate PDU. */
                candidate_pdu[0] = rx_buffer[4];
                candidate_pdu[1] = rx_buffer[5];
                dewhiten(candidate_pdu, 2, g_sniffer.channel);

                /* Check if PDU is the one expected. */
                if (((candidate_pdu[0] & 0xF3) == 1) && (candidate_pdu[1] == 0))
                {
                    aa = rx_buffer[0] | rx_buffer[1]<<8 | rx_buffer[2]<<16 | rx_buffer[3]<<24;
                    if (seen_aa(aa) > 1) {
                        /* We may have a candidate AA. */
                        pLink->notifyAccessAddress(aa, g_sniffer.channel, NRF_RADIO->RSSISAMPLE);
                    }
                }
              }
            }
            if (g_sniffer.pkt_count > 100)
            {
                g_sniffer.channel = (g_sniffer.channel + 1)%37;
                radio_set_sniff(g_sniffer.channel);
                g_sniffer.pkt_count = 0;
            }
        }
        else if (g_sniffer.action == RECOVER_CRC)
        {
            /* Extract crc and recover CRCInit */
            if (((rx_buffer[0]&0xF3) == 1) && (rx_buffer[1]==0))
            {
                crc = rx_buffer[2] | rx_buffer[3]<<8 | rx_buffer[4]<<16;
                crc_rev = btle_reverse_crc(crc, rx_buffer, 2);
                if (crc_rev != g_sniffer.crcinit)
                {
                    g_sniffer.crcinit = crc_rev;
                    g_sniffer.n = 0;

                }
                else
                {
                    if (g_sniffer.n > 5)
                    {
                        /* Notify CRC. */
                        pLink->notifyCrc(
                          g_sniffer.access_address,
                          g_sniffer.crcinit
                        );

                        if (!g_sniffer.chm_provided)
                          recover_chm();
                        else if (!g_sniffer.interval_provided)
                          recover_hop_interval();
                        else
                          recover_hop_inc();
                    }
                    else
                        g_sniffer.n++;
                }
            }

        }
        else if (g_sniffer.action == RECOVER_CHM)
        {
            if ((NRF_RADIO->CRCSTATUS == 1)) {
                if (!is_channel_mapped(g_sniffer.channel))
                {
                    map_channel(g_sniffer.channel);
                    pLink->verbose(B("I"));
                    recover_chm_next();
                }
            }
        }
        else if (g_sniffer.action == RECOVER_HOPINTER)
        {
            /* We expect a correct CRC for this packet. */
            if ((NRF_RADIO->CRCSTATUS == 1)) {
                /* If we were not measuring, then start our counting timer. */
                if (g_sniffer.measuring == false)
                {
                    measures = 0;
                    g_sniffer.prev_time = 0;
                    g_sniffer.measuring = true;
                    g_sniffer.ticker.attach_us(hop_tick, 1250);

                    /* Compute interval. */
                    pLink->verbose(B("Recovering hop interval ..."));
                }
                else
                {
                    /* compute interval based on measures. */
                    curtime = measures;
                    inter = (curtime - g_sniffer.prev_time);
                    if (inter > 2)
                    {
                        g_sniffer.prev_time = curtime;
                        if ((inter/37) != (g_sniffer.observed_interval/37))
                        {
                            g_sniffer.observed_interval = inter;
                            g_sniffer.n = 0;

                            /* Compute interval. */
                            snprintf((char *)hexbuf, 20, (char *)"inter: %08x", (uint32_t)inter);
                            pLink->verbose(hexbuf);

                        } else {
                            g_sniffer.n++;
                            if (g_sniffer.n >= 5)
                            {
                                /* Done with hop interval, then recover hop increment. */
                                g_sniffer.hop_interval = inter/37;

                                pLink->notifyHopInterval(
                                  g_sniffer.access_address,
                                  (uint16_t)g_sniffer.hop_interval
                                );

                                recover_hop_inc();
                            }
                        }

                    }
                }
            }
        } else if (g_sniffer.action == RECOVER_HOPINC)
        {
            /* We expect a correct CRC for this packet. */
            if ((NRF_RADIO->CRCSTATUS == 1)) {
                /* If we were not measuring, then start our counting timer. */
                if (g_sniffer.measuring == false)
                {
                    measures = 0;
                    g_sniffer.measuring = true;
                    g_sniffer.ticker.attach_us(hop_tick, 1250);

                }
                else if (g_sniffer.channel == g_sniffer.sg.getFirstChannel())
                {
                    /* First packet receive. */
                    g_sniffer.observed_interval = measures;

                    /* Jump to second channel. */
                    g_sniffer.channel = g_sniffer.sg.getSecondChannel();
                    radio_follow_aa(g_sniffer.access_address, g_sniffer.channel, g_sniffer.crcinit);
                } else if (g_sniffer.channel == g_sniffer.sg.getSecondChannel())
                {
                    /* Second packet received, deduce hop increment. */
                    inter = DIVIDE_ROUND((measures - g_sniffer.observed_interval), g_sniffer.hop_interval);
                    g_sniffer.hop_increment = g_sniffer.sg.getHopIncrement(inter);

                    if (g_sniffer.hop_increment != 0)
                    {
                      g_sniffer.sg.setHopIncrement(g_sniffer.hop_increment);
                      pLink->notifyHopIncrement(g_sniffer.access_address, g_sniffer.hop_increment);

                      /* Follow connection. */
                      follow_connection();
                    }
                    else
                    {
                      /* Restart measure. */
                      g_sniffer.measuring = false;
                      g_sniffer.ticker.detach();
                    }
                }
            }
        } else if (g_sniffer.action == FOLLOW)
        {
            if ((NRF_RADIO->CRCSTATUS == 1)) {
                /* If not synced, then sync. */
                if (g_sniffer.synced == false)
                {
                    /*
                        Start our delay timer.
                        We substract 300us as it is normally the time spent sending an empty Data PDU.
                    */
                    g_sniffer.ticker.attach_us(start_connection_follow, 1250*g_sniffer.hop_interval - 300);
                    g_sniffer.synced = true;
                } else {
                    /* Got a packet. */
                    if (rx_buffer[1] > 0)
                    {
                      /* Report LL data, header included. */
                      pLink->notifyBlePacket(rx_buffer, (int)rx_buffer[1] + 2);
                    }
                }
            }
        }
        NRF_RADIO->TASKS_START = 1;
    }
}



/**
 * Initialize sniffer state.
 **/

static void reset(void)
{
  /* Currently doing nothing =). */
  g_sniffer.action = IDLE;

  /* Reset BLE parameters. */
  g_sniffer.access_address = 0x0;
  g_sniffer.n_aa = 0;
  g_sniffer.crcinit = 0;
  g_sniffer.hop_interval = 0;
  g_sniffer.interval_provided = false;
  g_sniffer.hop_increment = 0;
  g_sniffer.smallest_interval = 0L;
  g_sniffer.prev_time = 0L;
  g_sniffer.observed_interval = 0;
  g_sniffer.pkt_count = 0;

  /* Reset channel map. */
  for (int i=0; i<37; i++)
    g_sniffer.chm[i] = 0;
  g_sniffer.chm_provided = false;

  g_sniffer.measuring = false;
  g_sniffer.synced = false;

  /* Reset timers. */
  g_sniffer.ticker.detach();
}

static void start_scanning(void)
{
    /* Sniffer is idling. */
    g_sniffer.action = SNIFF_AA;

    /* No access address candidates. */
    g_sniffer.n_aa = 0;
    g_sniffer.pkt_count = 0;
    g_sniffer.channel = 1;

    /* Start sniffing BLE packets on channel 1. */
    radio_set_sniff(g_sniffer.channel);
}

static void recover_connection_parameters(uint32_t accessAddress)
{
  g_sniffer.pkt_count = 0;
  recover_crc(accessAddress);
}

static void recover_connection_parameters(uint32_t accessAddress, uint8_t *chm)
{
  /* Convert 5-byte chm into 37-byte array. */
  chm_to_array(chm, g_sniffer.chm);

  /* Channel map is provided. */
  g_sniffer.chm_provided = true;

  /* Start CRC recovery. */
  g_sniffer.pkt_count = 0;
  recover_crc(accessAddress);
}

static void recover_connection_parameters(uint32_t accessAddress, uint8_t *chm, uint16_t hopInterval)
{
  /* Convert 5-byte chm into 37-byte array. */
  chm_to_array(chm, g_sniffer.chm);

  /* Channel map is provided. */
  g_sniffer.chm_provided = true;

  /* Initialize sequence generator. */
  g_sniffer.sg.initialize(g_sniffer.chm);

  /* Set hop interval. */
  g_sniffer.hop_interval = hopInterval;
  g_sniffer.interval_provided = true;

  /* Start CRC recovery. */
  g_sniffer.pkt_count = 0;
  recover_crc(accessAddress);
}


static void chm_tick()
{
    if (g_sniffer.channel < 36)
    {
        /* If channel not used, mark it. */
        if (!is_channel_mapped(g_sniffer.channel))
          pLink->verbose(B("_"));

        /* Tune to next channel. */
        g_sniffer.channel++;
        radio_follow_aa(g_sniffer.access_address, g_sniffer.channel, g_sniffer.crcinit);
    }
    else
    {
        /* We processed all of our channels, stop here. */
        if (!is_channel_mapped(g_sniffer.channel))
          pLink->verbose(B("_"));

        g_sniffer.ticker.detach();

        /* Count mapped channels. */
        g_sniffer.channels_mapped = count_channels();

        /* Notify the channel map. */
        pLink->notifyChannelMap(
          g_sniffer.access_address,
          g_sniffer.chm
        );

        /* Then, try to recover HopInterval. */
        recover_hop_interval();
    }
}

static void recover_chm_next()
{
    if (g_sniffer.channel < 36)
    {
        g_sniffer.ticker.detach();
        g_sniffer.ticker.attach_us(&chm_tick, 4000000);
    }
    chm_tick();
}

static void recover_chm()
{
    int i;

    /* Reset chm. */
    for (i=0;i<37;i++)
        g_sniffer.chm[i] = 0;

    /* We start CHM recovery. */
    g_sniffer.action = RECOVER_CHM;

    /* Set our timer. */
    g_sniffer.channel = 0;
    radio_follow_aa(g_sniffer.access_address, g_sniffer.channel, g_sniffer.crcinit);
    g_sniffer.ticker.attach_us(&chm_tick, 4000000);
}

static void recover_crc(uint32_t access_address)
{
    g_sniffer.action = RECOVER_CRC;
    g_sniffer.n_aa = 0;
    g_sniffer.crcinit = 0;
    g_sniffer.n = 0;
    g_sniffer.access_address = access_address;

    /* We sniff on the last used channel. */
    radio_sniff_aa(access_address, g_sniffer.channel);
}

/**
 * We now have the correct CRCInit and Access Address, let's recover
 * the hop interval.
 **/

static void recover_hop_interval(void)
{
    /* Update state. */
    g_sniffer.action = RECOVER_HOPINTER;
    g_sniffer.observed_interval = 0;
    g_sniffer.smallest_interval = 0xffffffffffffffff;
    g_sniffer.prev_time = 0xffffffff;
    g_sniffer.n = 0;

    /* Initialize sequence generator. */
    g_sniffer.sg.initialize(g_sniffer.chm);
    g_sniffer.channel = g_sniffer.sg.getFirstChannel();

    /* Start measuring. */
    measures = 0;
    g_sniffer.measuring = false;

    /* Reconfigure radio. */
    radio_follow_aa(g_sniffer.access_address, g_sniffer.channel, g_sniffer.crcinit);

}

static void recover_hop_inc(void)
{
    /* switch to Hop increment recovery. */
    g_sniffer.action = RECOVER_HOPINC;
    g_sniffer.ticker.detach();
    g_sniffer.measuring = false;

    /* configure radio and follow AA. */
    g_sniffer.channel = g_sniffer.sg.getFirstChannel();
    radio_follow_aa(g_sniffer.access_address, g_sniffer.channel, g_sniffer.crcinit);
}

static void follow_connection(void)
{
    /* Switch to connection following mode. */
    g_sniffer.action = FOLLOW;

    /* Stop any timer. */
    g_sniffer.ticker.detach();

    /* Start from first channel. */
    g_sniffer.synced = false;
    g_sniffer.sg.prepareToFollow();
    g_sniffer.channel = g_sniffer.sg.getCurrentChannel();

    radio_follow_conn(g_sniffer.access_address, g_sniffer.channel, g_sniffer.crcinit);
}

void dispatchMessage(T_OPERATION op, uint8_t *payload, int nSize, uint8_t ubflags)
{
  uint32_t accessAddress;
  uint8_t chm[5];
  uint16_t hopInterval;
  int i;

  switch (op)
  {

    /**
     * No data required for RESET.
     **/

    case RESET:
      {
        /* Reset state. */
        reset();

        /* Send command ACK. */
        pLink->sendPacket(RESET, NULL, 0, PKT_COMMAND | PKT_RESPONSE);
      }
      break;

    /**
     * Only support version command.
     **/

    case VERSION:
      {
        if (ubflags & PKT_COMMAND)
        {
          /* Send current version. */
          pLink->version(VERSION_MAJOR, VERSION_MINOR);
        }
        else
        {
          pLink->verbose(B("Version response not supported"));
        }
      }
      break;

    /**
     * List access addresses.
     **/

    case LIST_AA:
      {
        if (ubflags & PKT_COMMAND)
        {
          /* Send ACK. */
          pLink->sendPacket(LIST_AA, NULL, 0, PKT_COMMAND | PKT_RESPONSE);

          /* Start scanning. */
          start_scanning();

        }
        else
        {
          pLink->verbose(B("Version response not supported"));
        }
      }
      break;

    /**
     * Recover parameters for a specific connection.
     *
     * Payload structure: [AA (4 bytes)]
     **/

    case RECOVER_AA:
      {
        if (ubflags & PKT_COMMAND)
        {
          /* Extract access address. */
          accessAddress = payload[0] | (payload[1] << 8) | (payload[2] << 16) | (payload[3] << 24);

          /* Send ACK. */
          pLink->sendPacket(RECOVER_AA, NULL, 0, PKT_COMMAND | PKT_RESPONSE);

          /* Recover parameters. */
          recover_connection_parameters(accessAddress);
        }
      }
      break;

    /**
     * Recover parameters for a specific connection, given a channel map.
     *
     * Payload structure: [AA (4 bytes)][ChM (5 bytes)]
     **/

    case RECOVER_AA_CHM:
      {
        /* Extract access address. */
        accessAddress = payload[0] | (payload[1] << 8) | (payload[2] << 16) | (payload[3] << 24);

        /* Extract channel map. */
        for (i=0; i<5; i++)
          chm[i] = payload[4+i];

        /* Send ACK. */
        pLink->sendPacket(RECOVER_AA, NULL, 0, PKT_COMMAND | PKT_RESPONSE);

        /* Recover parameters. */
        recover_connection_parameters(accessAddress, chm);

      }
      break;

    case RECOVER_AA_CHM_HOPINTER:
      {
        /* Extract access address. */
        accessAddress = payload[0] | (payload[1] << 8) | (payload[2] << 16) | (payload[3] << 24);

        /* Extract channel map. */
        for (i=0; i<5; i++)
          chm[i] = payload[4+i];

        /* Extract hop interval. */
        hopInterval = payload[9] | payload[10];

        /* Send ACK. */
        pLink->sendPacket(RECOVER_AA, NULL, 0, PKT_COMMAND | PKT_RESPONSE);

        /* Recover parameters. */
        recover_connection_parameters(accessAddress, chm, hopInterval);
      }
      break;

    /* Other packets. */
    default:
      break;
  }
}

int main() {
    T_OPERATION op;
    uint8_t packet[200];
    int nbSize;
    uint8_t flags;

    /* Initalize Micro:Bit and serial link. */
    uBit.init();
    pLink = new Link(&uBit);

    /* Reset radio and state. */
    reset();

    /* Process serial inquiries. */
    while (1) {
        /* Wait for a packet */
        if (pLink->readPacket(&op, packet, &nbSize, &flags))
        {
          dispatchMessage(op, packet, nbSize, flags);
        }

        __WFE();
    }

    /* Done, release fiber. */
    release_fiber();
}
