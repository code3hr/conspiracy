/*
 * CyxWiz Protocol - LoRa Transport Driver
 *
 * Full implementation supporting:
 * - Serial/AT command LoRa modules (RYLR890/RYLR896, E32, etc.)
 * - Linux SPI for direct SX127x/SX126x access
 *
 * LoRa is critical for long-range, low-power mesh networking.
 * All packets are broadcast - addressing is done at protocol level.
 */

#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "cyxwiz/transport.h"
#include "cyxwiz/memory.h"
#include "cyxwiz/log.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef CYXWIZ_HAS_LORA

/* ============ Platform Abstraction ============ */

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
typedef HANDLE serial_handle_t;
#define INVALID_SERIAL INVALID_HANDLE_VALUE
#else
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <linux/spi/spidev.h>
typedef int serial_handle_t;
#define INVALID_SERIAL (-1)
#endif

/* ============ Constants ============ */

/* LoRa-specific constraints */
#define LORA_MAX_PACKET_SIZE    250     /* LoRa packet size limit */
#define LORA_MAX_PAYLOAD        200     /* Max payload after headers */
#define LORA_HEADER_SIZE        33      /* Type (1) + Node ID (32) */

/* LoRa radio parameters */
#define LORA_DEFAULT_FREQ_US    915000000   /* 915 MHz (US ISM) */
#define LORA_DEFAULT_FREQ_EU    868000000   /* 868 MHz (EU ISM) */
#define LORA_DEFAULT_SF         9           /* Spreading factor (7-12) */
#define LORA_DEFAULT_BW         125000      /* Bandwidth in Hz */
#define LORA_DEFAULT_CR         5           /* Coding rate (5=4/5, 8=4/8) */
#define LORA_DEFAULT_POWER      14          /* TX power in dBm */

/* Timing constants */
#define LORA_ANNOUNCE_INTERVAL_MS   10000   /* Announce every 10s */
#define LORA_PEER_TIMEOUT_MS        60000   /* Peer timeout 60s */
#define LORA_KEEPALIVE_INTERVAL_MS  30000   /* Keepalive every 30s */
#define LORA_CAD_TIMEOUT_MS         100     /* Channel activity detect */
#define LORA_TX_TIMEOUT_MS          5000    /* TX timeout */
#define LORA_SLOT_TIME_MS           50      /* Time slot for CSMA */
#define LORA_MAX_BACKOFF_SLOTS      8       /* Max random backoff */

/* Peer management */
#define LORA_MAX_PEERS  32

/* Serial port settings */
#define LORA_SERIAL_BAUD    115200
#define LORA_SERIAL_TIMEOUT 100     /* ms */

/* SX127x Register addresses */
#define SX127X_REG_FIFO             0x00
#define SX127X_REG_OP_MODE          0x01
#define SX127X_REG_FRF_MSB          0x06
#define SX127X_REG_FRF_MID          0x07
#define SX127X_REG_FRF_LSB          0x08
#define SX127X_REG_PA_CONFIG        0x09
#define SX127X_REG_FIFO_ADDR_PTR    0x0D
#define SX127X_REG_FIFO_TX_BASE     0x0E
#define SX127X_REG_FIFO_RX_BASE     0x0F
#define SX127X_REG_FIFO_RX_CURRENT  0x10
#define SX127X_REG_IRQ_FLAGS        0x12
#define SX127X_REG_RX_NB_BYTES      0x13
#define SX127X_REG_PKT_SNR          0x19
#define SX127X_REG_PKT_RSSI         0x1A
#define SX127X_REG_MODEM_CONFIG_1   0x1D
#define SX127X_REG_MODEM_CONFIG_2   0x1E
#define SX127X_REG_PAYLOAD_LENGTH   0x22
#define SX127X_REG_MODEM_CONFIG_3   0x26
#define SX127X_REG_DIO_MAPPING_1    0x40
#define SX127X_REG_VERSION          0x42

/* SX127x Operating modes */
#define SX127X_MODE_SLEEP           0x00
#define SX127X_MODE_STANDBY         0x01
#define SX127X_MODE_TX              0x03
#define SX127X_MODE_RX_CONTINUOUS   0x05
#define SX127X_MODE_RX_SINGLE       0x06
#define SX127X_MODE_CAD             0x07
#define SX127X_MODE_LORA            0x80

/* SX127x IRQ flags */
#define SX127X_IRQ_RX_DONE          0x40
#define SX127X_IRQ_PAYLOAD_CRC_ERR  0x20
#define SX127X_IRQ_TX_DONE          0x08
#define SX127X_IRQ_CAD_DONE         0x04
#define SX127X_IRQ_CAD_DETECTED     0x01

/* ============ Message Types (0xF0-0xFF range) ============ */

#define CYXWIZ_LORA_ANNOUNCE        0xF0    /* Broadcast "I'm here" */
#define CYXWIZ_LORA_ANNOUNCE_ACK    0xF1    /* Acknowledge announce */
#define CYXWIZ_LORA_DATA            0xF2    /* Data packet */
#define CYXWIZ_LORA_KEEPALIVE       0xF3    /* Keepalive beacon */
#define CYXWIZ_LORA_GOODBYE         0xF4    /* Graceful disconnect */

/* ============ Message Structures ============ */

#pragma pack(push, 1)

/* Announce message - broadcast to all */
typedef struct {
    uint8_t type;                       /* CYXWIZ_LORA_ANNOUNCE */
    cyxwiz_node_id_t node_id;           /* Sender's node ID */
    uint8_t capabilities;               /* Node capabilities */
    int8_t tx_power;                    /* TX power in dBm */
} cyxwiz_lora_announce_t;

/* Announce ACK */
typedef struct {
    uint8_t type;                       /* CYXWIZ_LORA_ANNOUNCE_ACK */
    cyxwiz_node_id_t node_id;           /* Responder's node ID */
    cyxwiz_node_id_t to_node_id;        /* Who we're ACKing */
} cyxwiz_lora_announce_ack_t;

/* Data message */
typedef struct {
    uint8_t type;                       /* CYXWIZ_LORA_DATA */
    cyxwiz_node_id_t from_id;           /* Sender's node ID */
    cyxwiz_node_id_t to_id;             /* Recipient's node ID (or broadcast) */
    uint8_t payload[LORA_MAX_PAYLOAD];  /* Actual data */
} cyxwiz_lora_data_t;

/* Keepalive beacon */
typedef struct {
    uint8_t type;                       /* CYXWIZ_LORA_KEEPALIVE */
    cyxwiz_node_id_t node_id;           /* Sender's node ID */
    uint8_t peer_count;                 /* Number of known peers */
} cyxwiz_lora_keepalive_t;

/* Goodbye message */
typedef struct {
    uint8_t type;                       /* CYXWIZ_LORA_GOODBYE */
    cyxwiz_node_id_t node_id;           /* Sender's node ID */
} cyxwiz_lora_goodbye_t;

#pragma pack(pop)

/* ============ Hardware Backend Types ============ */

typedef enum {
    LORA_BACKEND_NONE = 0,
    LORA_BACKEND_SERIAL,    /* AT command module via serial port */
    LORA_BACKEND_SPI        /* Direct SX127x via SPI (Linux only) */
} lora_backend_t;

/* ============ Peer Structure ============ */

typedef struct {
    cyxwiz_node_id_t node_id;
    bool valid;
    bool has_node_id;
    int8_t rssi;                /* Last received RSSI */
    int8_t snr;                 /* Last received SNR */
    uint64_t last_seen;
    uint64_t last_keepalive;
} lora_peer_t;

/* ============ LoRa State Structure ============ */

typedef struct {
    bool initialized;
    bool discovering;
    lora_backend_t backend;

    /* Radio parameters */
    uint32_t frequency;
    uint8_t spreading_factor;
    uint32_t bandwidth;
    uint8_t coding_rate;
    int8_t tx_power;

    /* Serial backend */
    serial_handle_t serial;
    char serial_port[64];
    char serial_rx_buf[512];
    size_t serial_rx_len;

#ifndef _WIN32
    /* SPI backend (Linux only) */
    int spi_fd;
    char spi_device[32];
#endif

    /* Peer management */
    lora_peer_t peers[LORA_MAX_PEERS];
    size_t peer_count;

    /* Timing */
    uint64_t last_announce;
    uint64_t last_keepalive;
    uint64_t last_rx_time;

    /* TX state for CSMA/CA */
    bool tx_pending;
    uint8_t tx_buffer[LORA_MAX_PACKET_SIZE];
    size_t tx_len;
    uint8_t backoff_slots;

    /* Last received packet info */
    int8_t last_rssi;
    int8_t last_snr;

} lora_state_t;

/* ============ Time Helper ============ */

static uint64_t get_time_ms(void)
{
#ifdef _WIN32
    return GetTickCount64();
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + (uint64_t)tv.tv_usec / 1000;
#endif
}

/* ============ Serial Port Functions ============ */

#ifdef _WIN32

static serial_handle_t serial_open(const char *port, int baud)
{
    HANDLE h = CreateFileA(port, GENERIC_READ | GENERIC_WRITE,
                           0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        return INVALID_SERIAL;
    }

    DCB dcb;
    memset(&dcb, 0, sizeof(dcb));
    dcb.DCBlength = sizeof(dcb);

    if (!GetCommState(h, &dcb)) {
        CloseHandle(h);
        return INVALID_SERIAL;
    }

    dcb.BaudRate = baud;
    dcb.ByteSize = 8;
    dcb.Parity = NOPARITY;
    dcb.StopBits = ONESTOPBIT;
    dcb.fBinary = TRUE;
    dcb.fDtrControl = DTR_CONTROL_ENABLE;
    dcb.fRtsControl = RTS_CONTROL_ENABLE;

    if (!SetCommState(h, &dcb)) {
        CloseHandle(h);
        return INVALID_SERIAL;
    }

    COMMTIMEOUTS timeouts;
    timeouts.ReadIntervalTimeout = MAXDWORD;
    timeouts.ReadTotalTimeoutMultiplier = 0;
    timeouts.ReadTotalTimeoutConstant = LORA_SERIAL_TIMEOUT;
    timeouts.WriteTotalTimeoutMultiplier = 0;
    timeouts.WriteTotalTimeoutConstant = 1000;
    SetCommTimeouts(h, &timeouts);

    return h;
}

static void serial_close(serial_handle_t h)
{
    if (h != INVALID_SERIAL) {
        CloseHandle(h);
    }
}

static int serial_write(serial_handle_t h, const uint8_t *data, size_t len)
{
    DWORD written;
    if (!WriteFile(h, data, (DWORD)len, &written, NULL)) {
        return -1;
    }
    return (int)written;
}

static int serial_read(serial_handle_t h, uint8_t *buf, size_t max_len)
{
    DWORD bytesRead;
    if (!ReadFile(h, buf, (DWORD)max_len, &bytesRead, NULL)) {
        return -1;
    }
    return (int)bytesRead;
}

static int serial_available(serial_handle_t h)
{
    COMSTAT cs;
    DWORD errors;
    if (!ClearCommError(h, &errors, &cs)) {
        return 0;
    }
    return (int)cs.cbInQue;
}

#else /* Linux/Unix */

static serial_handle_t serial_open(const char *port, int baud)
{
    int fd = open(port, O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (fd < 0) {
        return INVALID_SERIAL;
    }

    struct termios tty;
    memset(&tty, 0, sizeof(tty));

    if (tcgetattr(fd, &tty) != 0) {
        close(fd);
        return INVALID_SERIAL;
    }

    speed_t speed;
    switch (baud) {
        case 9600:   speed = B9600;   break;
        case 19200:  speed = B19200;  break;
        case 38400:  speed = B38400;  break;
        case 57600:  speed = B57600;  break;
        case 115200: speed = B115200; break;
        default:     speed = B115200; break;
    }

    cfsetispeed(&tty, speed);
    cfsetospeed(&tty, speed);

    tty.c_cflag &= ~PARENB;         /* No parity */
    tty.c_cflag &= ~CSTOPB;         /* 1 stop bit */
    tty.c_cflag &= ~CSIZE;
    tty.c_cflag |= CS8;             /* 8 bits */
    tty.c_cflag &= ~CRTSCTS;        /* No hardware flow control */
    tty.c_cflag |= CREAD | CLOCAL;  /* Enable receiver, ignore modem */

    tty.c_lflag &= ~ICANON;         /* Raw mode */
    tty.c_lflag &= ~ECHO;
    tty.c_lflag &= ~ECHOE;
    tty.c_lflag &= ~ECHONL;
    tty.c_lflag &= ~ISIG;

    tty.c_iflag &= ~(IXON | IXOFF | IXANY);
    tty.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL);

    tty.c_oflag &= ~OPOST;
    tty.c_oflag &= ~ONLCR;

    tty.c_cc[VTIME] = 1;    /* 100ms timeout */
    tty.c_cc[VMIN] = 0;

    if (tcsetattr(fd, TCSANOW, &tty) != 0) {
        close(fd);
        return INVALID_SERIAL;
    }

    /* Flush buffers */
    tcflush(fd, TCIOFLUSH);

    return fd;
}

static void serial_close(serial_handle_t fd)
{
    if (fd != INVALID_SERIAL) {
        close(fd);
    }
}

static int serial_write(serial_handle_t fd, const uint8_t *data, size_t len)
{
    return (int)write(fd, data, len);
}

static int serial_read(serial_handle_t fd, uint8_t *buf, size_t max_len)
{
    return (int)read(fd, buf, max_len);
}

static int serial_available(serial_handle_t fd)
{
    int bytes;
    if (ioctl(fd, FIONREAD, &bytes) < 0) {
        return 0;
    }
    return bytes;
}

#endif /* _WIN32 */

/* ============ SPI Functions (Linux only) ============ */

#ifndef _WIN32

static int spi_open(const char *device)
{
    int fd = open(device, O_RDWR);
    if (fd < 0) {
        return -1;
    }

    /* SPI mode 0, MSB first */
    uint8_t mode = SPI_MODE_0;
    uint8_t bits = 8;
    uint32_t speed = 8000000;  /* 8 MHz */

    if (ioctl(fd, SPI_IOC_WR_MODE, &mode) < 0 ||
        ioctl(fd, SPI_IOC_WR_BITS_PER_WORD, &bits) < 0 ||
        ioctl(fd, SPI_IOC_WR_MAX_SPEED_HZ, &speed) < 0) {
        close(fd);
        return -1;
    }

    return fd;
}

static void spi_close(int fd)
{
    if (fd >= 0) {
        close(fd);
    }
}

static uint8_t spi_transfer(int fd, uint8_t addr, uint8_t value)
{
    uint8_t tx[2] = {addr, value};
    uint8_t rx[2] = {0, 0};

    struct spi_ioc_transfer tr;
    memset(&tr, 0, sizeof(tr));
    tr.tx_buf = (unsigned long)tx;
    tr.rx_buf = (unsigned long)rx;
    tr.len = 2;
    tr.speed_hz = 8000000;
    tr.bits_per_word = 8;

    if (ioctl(fd, SPI_IOC_MESSAGE(1), &tr) < 0) {
        return 0;
    }

    return rx[1];
}

static uint8_t sx127x_read_reg(int fd, uint8_t reg)
{
    return spi_transfer(fd, reg & 0x7F, 0x00);
}

static void sx127x_write_reg(int fd, uint8_t reg, uint8_t value)
{
    spi_transfer(fd, reg | 0x80, value);
}

static void sx127x_write_burst(int fd, uint8_t reg, const uint8_t *data, size_t len)
{
    uint8_t *tx = malloc(len + 1);
    if (!tx) return;

    tx[0] = reg | 0x80;
    memcpy(tx + 1, data, len);

    struct spi_ioc_transfer tr;
    memset(&tr, 0, sizeof(tr));
    tr.tx_buf = (unsigned long)tx;
    tr.rx_buf = 0;
    tr.len = (uint32_t)(len + 1);
    tr.speed_hz = 8000000;
    tr.bits_per_word = 8;

    ioctl(fd, SPI_IOC_MESSAGE(1), &tr);
    free(tx);
}

static void sx127x_read_burst(int fd, uint8_t reg, uint8_t *data, size_t len)
{
    uint8_t *tx = calloc(1, len + 1);
    uint8_t *rx = malloc(len + 1);
    if (!tx || !rx) {
        free(tx);
        free(rx);
        return;
    }

    tx[0] = reg & 0x7F;

    struct spi_ioc_transfer tr;
    memset(&tr, 0, sizeof(tr));
    tr.tx_buf = (unsigned long)tx;
    tr.rx_buf = (unsigned long)rx;
    tr.len = (uint32_t)(len + 1);
    tr.speed_hz = 8000000;
    tr.bits_per_word = 8;

    if (ioctl(fd, SPI_IOC_MESSAGE(1), &tr) >= 0) {
        memcpy(data, rx + 1, len);
    }

    free(tx);
    free(rx);
}

/* Initialize SX127x radio */
static bool sx127x_init(lora_state_t *state)
{
    int fd = state->spi_fd;

    /* Check version register */
    uint8_t version = sx127x_read_reg(fd, SX127X_REG_VERSION);
    if (version != 0x12) {
        CYXWIZ_ERROR("SX127x not detected (version: 0x%02X)", version);
        return false;
    }

    /* Set sleep mode */
    sx127x_write_reg(fd, SX127X_REG_OP_MODE, SX127X_MODE_SLEEP);

    /* Set LoRa mode */
    sx127x_write_reg(fd, SX127X_REG_OP_MODE, SX127X_MODE_SLEEP | SX127X_MODE_LORA);

    /* Set frequency */
    uint64_t frf = ((uint64_t)state->frequency << 19) / 32000000;
    sx127x_write_reg(fd, SX127X_REG_FRF_MSB, (uint8_t)(frf >> 16));
    sx127x_write_reg(fd, SX127X_REG_FRF_MID, (uint8_t)(frf >> 8));
    sx127x_write_reg(fd, SX127X_REG_FRF_LSB, (uint8_t)(frf));

    /* Set bandwidth, coding rate, implicit header mode */
    uint8_t bw_reg;
    switch (state->bandwidth) {
        case 7800:   bw_reg = 0; break;
        case 10400:  bw_reg = 1; break;
        case 15600:  bw_reg = 2; break;
        case 20800:  bw_reg = 3; break;
        case 31250:  bw_reg = 4; break;
        case 41700:  bw_reg = 5; break;
        case 62500:  bw_reg = 6; break;
        case 125000: bw_reg = 7; break;
        case 250000: bw_reg = 8; break;
        case 500000: bw_reg = 9; break;
        default:     bw_reg = 7; break;
    }
    uint8_t cr_reg = state->coding_rate - 4;
    sx127x_write_reg(fd, SX127X_REG_MODEM_CONFIG_1, (bw_reg << 4) | (cr_reg << 1) | 0x00);

    /* Set spreading factor, CRC on */
    sx127x_write_reg(fd, SX127X_REG_MODEM_CONFIG_2,
                     (state->spreading_factor << 4) | 0x04);

    /* LNA gain, low data rate optimize */
    uint8_t ldr = (state->spreading_factor >= 11 && state->bandwidth == 125000) ? 0x08 : 0x00;
    sx127x_write_reg(fd, SX127X_REG_MODEM_CONFIG_3, 0x04 | ldr);

    /* Set TX power */
    if (state->tx_power > 17) {
        sx127x_write_reg(fd, SX127X_REG_PA_CONFIG, 0x8F);  /* PA_BOOST, max power */
    } else {
        sx127x_write_reg(fd, SX127X_REG_PA_CONFIG, 0x80 | (state->tx_power - 2));
    }

    /* Set FIFO base addresses */
    sx127x_write_reg(fd, SX127X_REG_FIFO_TX_BASE, 0x00);
    sx127x_write_reg(fd, SX127X_REG_FIFO_RX_BASE, 0x00);

    /* Set to standby mode */
    sx127x_write_reg(fd, SX127X_REG_OP_MODE, SX127X_MODE_STANDBY | SX127X_MODE_LORA);

    CYXWIZ_INFO("SX127x initialized: %lu Hz, SF%d, BW %lu",
                (unsigned long)state->frequency,
                state->spreading_factor,
                (unsigned long)state->bandwidth);

    return true;
}

/* Set SX127x to receive mode */
static void sx127x_start_rx(lora_state_t *state)
{
    int fd = state->spi_fd;

    /* Clear IRQ flags */
    sx127x_write_reg(fd, SX127X_REG_IRQ_FLAGS, 0xFF);

    /* Set FIFO address to RX base */
    sx127x_write_reg(fd, SX127X_REG_FIFO_ADDR_PTR,
                     sx127x_read_reg(fd, SX127X_REG_FIFO_RX_BASE));

    /* Enter continuous RX mode */
    sx127x_write_reg(fd, SX127X_REG_OP_MODE, SX127X_MODE_RX_CONTINUOUS | SX127X_MODE_LORA);
}

/* Transmit packet via SX127x */
static bool sx127x_transmit(lora_state_t *state, const uint8_t *data, size_t len)
{
    int fd = state->spi_fd;

    if (len > 255) {
        return false;
    }

    /* Set to standby */
    sx127x_write_reg(fd, SX127X_REG_OP_MODE, SX127X_MODE_STANDBY | SX127X_MODE_LORA);

    /* Clear IRQ flags */
    sx127x_write_reg(fd, SX127X_REG_IRQ_FLAGS, 0xFF);

    /* Set FIFO address */
    sx127x_write_reg(fd, SX127X_REG_FIFO_ADDR_PTR,
                     sx127x_read_reg(fd, SX127X_REG_FIFO_TX_BASE));

    /* Write data to FIFO */
    sx127x_write_burst(fd, SX127X_REG_FIFO, data, len);

    /* Set payload length */
    sx127x_write_reg(fd, SX127X_REG_PAYLOAD_LENGTH, (uint8_t)len);

    /* Start transmission */
    sx127x_write_reg(fd, SX127X_REG_OP_MODE, SX127X_MODE_TX | SX127X_MODE_LORA);

    /* Wait for TX done */
    uint64_t start = get_time_ms();
    while ((get_time_ms() - start) < LORA_TX_TIMEOUT_MS) {
        uint8_t irq = sx127x_read_reg(fd, SX127X_REG_IRQ_FLAGS);
        if (irq & SX127X_IRQ_TX_DONE) {
            /* Clear IRQ */
            sx127x_write_reg(fd, SX127X_REG_IRQ_FLAGS, SX127X_IRQ_TX_DONE);
            /* Return to RX mode */
            sx127x_start_rx(state);
            return true;
        }
#ifdef _WIN32
        Sleep(1);
#else
        usleep(1000);
#endif
    }

    CYXWIZ_WARN("SX127x TX timeout");
    sx127x_start_rx(state);
    return false;
}

/* Check for received packet via SX127x */
static int sx127x_receive(lora_state_t *state, uint8_t *buf, size_t max_len)
{
    int fd = state->spi_fd;

    uint8_t irq = sx127x_read_reg(fd, SX127X_REG_IRQ_FLAGS);

    if (!(irq & SX127X_IRQ_RX_DONE)) {
        return 0;  /* No packet */
    }

    /* Check CRC error */
    if (irq & SX127X_IRQ_PAYLOAD_CRC_ERR) {
        CYXWIZ_DEBUG("LoRa RX CRC error");
        sx127x_write_reg(fd, SX127X_REG_IRQ_FLAGS, 0xFF);
        return -1;
    }

    /* Get packet length */
    uint8_t len = sx127x_read_reg(fd, SX127X_REG_RX_NB_BYTES);
    if (len > max_len) {
        len = (uint8_t)max_len;
    }

    /* Get packet RSSI and SNR */
    state->last_rssi = (int8_t)(sx127x_read_reg(fd, SX127X_REG_PKT_RSSI) - 157);
    state->last_snr = (int8_t)sx127x_read_reg(fd, SX127X_REG_PKT_SNR) / 4;

    /* Set FIFO address to start of packet */
    sx127x_write_reg(fd, SX127X_REG_FIFO_ADDR_PTR,
                     sx127x_read_reg(fd, SX127X_REG_FIFO_RX_CURRENT));

    /* Read packet from FIFO */
    sx127x_read_burst(fd, SX127X_REG_FIFO, buf, len);

    /* Clear IRQ flags */
    sx127x_write_reg(fd, SX127X_REG_IRQ_FLAGS, 0xFF);

    return len;
}

/* Channel Activity Detection */
static bool sx127x_channel_busy(lora_state_t *state)
{
    int fd = state->spi_fd;

    /* Set to standby */
    sx127x_write_reg(fd, SX127X_REG_OP_MODE, SX127X_MODE_STANDBY | SX127X_MODE_LORA);

    /* Clear IRQ flags */
    sx127x_write_reg(fd, SX127X_REG_IRQ_FLAGS, 0xFF);

    /* Start CAD */
    sx127x_write_reg(fd, SX127X_REG_OP_MODE, SX127X_MODE_CAD | SX127X_MODE_LORA);

    /* Wait for CAD done */
    uint64_t start = get_time_ms();
    while ((get_time_ms() - start) < LORA_CAD_TIMEOUT_MS) {
        uint8_t irq = sx127x_read_reg(fd, SX127X_REG_IRQ_FLAGS);
        if (irq & SX127X_IRQ_CAD_DONE) {
            bool detected = (irq & SX127X_IRQ_CAD_DETECTED) != 0;
            sx127x_write_reg(fd, SX127X_REG_IRQ_FLAGS, 0xFF);
            sx127x_start_rx(state);
            return detected;
        }
#ifdef _WIN32
        Sleep(1);
#else
        usleep(1000);
#endif
    }

    sx127x_start_rx(state);
    return true;  /* Assume busy on timeout */
}

#endif /* !_WIN32 */

/* ============ AT Command Functions (Serial Modules) ============ */

/* Send AT command and get response */
static bool at_command(lora_state_t *state, const char *cmd, char *response, size_t resp_size)
{
    if (state->serial == INVALID_SERIAL) {
        return false;
    }

    /* Send command */
    size_t cmd_len = strlen(cmd);
    serial_write(state->serial, (const uint8_t *)cmd, cmd_len);
    serial_write(state->serial, (const uint8_t *)"\r\n", 2);

    /* Wait for response */
    size_t resp_len = 0;
    uint64_t start = get_time_ms();

    while ((get_time_ms() - start) < 2000 && resp_len < resp_size - 1) {
        int avail = serial_available(state->serial);
        if (avail > 0) {
            int n = serial_read(state->serial, (uint8_t *)response + resp_len,
                               resp_size - 1 - resp_len);
            if (n > 0) {
                resp_len += (size_t)n;
                response[resp_len] = '\0';

                /* Check for complete response */
                if (strstr(response, "+OK") || strstr(response, "+ERR")) {
                    return strstr(response, "+OK") != NULL;
                }
            }
        }
#ifdef _WIN32
        Sleep(10);
#else
        usleep(10000);
#endif
    }

    return false;
}

/* Configure RYLR module */
static bool rylr_configure(lora_state_t *state)
{
    char response[256];

    /* Test connection */
    if (!at_command(state, "AT", response, sizeof(response))) {
        CYXWIZ_ERROR("RYLR module not responding");
        return false;
    }

    /* Set network ID (use 0 for broadcast) */
    if (!at_command(state, "AT+NETWORKID=0", response, sizeof(response))) {
        CYXWIZ_WARN("Failed to set network ID");
    }

    /* Set address (use 0 for this node, others will use different addresses) */
    if (!at_command(state, "AT+ADDRESS=0", response, sizeof(response))) {
        CYXWIZ_WARN("Failed to set address");
    }

    /* Set parameters: SF, BW, CR, Preamble */
    char param_cmd[64];
    snprintf(param_cmd, sizeof(param_cmd), "AT+PARAMETER=%d,7,%d,12",
             state->spreading_factor, state->coding_rate);
    if (!at_command(state, param_cmd, response, sizeof(response))) {
        CYXWIZ_WARN("Failed to set parameters");
    }

    /* Set TX power */
    char power_cmd[32];
    snprintf(power_cmd, sizeof(power_cmd), "AT+CRFOP=%d", state->tx_power);
    at_command(state, power_cmd, response, sizeof(response));

    /* Set to receive mode */
    at_command(state, "AT+MODE=0", response, sizeof(response));

    CYXWIZ_INFO("RYLR module configured");
    return true;
}

/* Send data via RYLR module */
static bool rylr_transmit(lora_state_t *state, const uint8_t *data, size_t len)
{
    if (len > 240) {
        return false;  /* RYLR max payload */
    }

    /* Format: AT+SEND=<address>,<len>,<data> */
    char cmd[512];
    int offset = snprintf(cmd, sizeof(cmd), "AT+SEND=0,%zu,", len);

    /* Convert to hex for binary safety */
    for (size_t i = 0; i < len && offset < (int)sizeof(cmd) - 3; i++) {
        offset += snprintf(cmd + offset, sizeof(cmd) - (size_t)offset, "%02X", data[i]);
    }

    char response[64];
    return at_command(state, cmd, response, sizeof(response));
}

/* Parse received data from RYLR module */
static int rylr_parse_rx(lora_state_t *state, uint8_t *buf, size_t max_len)
{
    /* Check for +RCV=<address>,<len>,<data>,<rssi>,<snr> */
    char *rcv = strstr(state->serial_rx_buf, "+RCV=");
    if (!rcv) {
        return 0;
    }

    int addr, len, rssi, snr;
    char hex_data[512];

    if (sscanf(rcv, "+RCV=%d,%d,%[^,],%d,%d", &addr, &len, hex_data, &rssi, &snr) < 3) {
        /* Remove processed data */
        char *newline = strchr(rcv, '\n');
        if (newline) {
            memmove(state->serial_rx_buf, newline + 1,
                    state->serial_rx_len - (size_t)(newline + 1 - state->serial_rx_buf));
            state->serial_rx_len -= (size_t)(newline + 1 - state->serial_rx_buf);
        }
        return 0;
    }

    state->last_rssi = (int8_t)rssi;
    state->last_snr = (int8_t)snr;

    /* Convert hex to binary */
    size_t hex_len = strlen(hex_data);
    size_t bin_len = hex_len / 2;
    if (bin_len > max_len) {
        bin_len = max_len;
    }

    for (size_t i = 0; i < bin_len; i++) {
        unsigned int byte;
        if (sscanf(hex_data + i * 2, "%02X", &byte) == 1) {
            buf[i] = (uint8_t)byte;
        }
    }

    /* Remove processed data */
    char *newline = strchr(rcv, '\n');
    if (newline) {
        memmove(state->serial_rx_buf, newline + 1,
                state->serial_rx_len - (size_t)(newline + 1 - state->serial_rx_buf));
        state->serial_rx_len -= (size_t)(newline + 1 - state->serial_rx_buf);
    } else {
        state->serial_rx_len = 0;
    }

    return (int)bin_len;
}

/* ============ Peer Management ============ */

static lora_peer_t *find_peer_by_id(lora_state_t *state, const cyxwiz_node_id_t *id)
{
    for (size_t i = 0; i < LORA_MAX_PEERS; i++) {
        if (state->peers[i].valid && state->peers[i].has_node_id &&
            memcmp(&state->peers[i].node_id, id, sizeof(cyxwiz_node_id_t)) == 0) {
            return &state->peers[i];
        }
    }
    return NULL;
}

static lora_peer_t *add_peer(lora_state_t *state, const cyxwiz_node_id_t *id)
{
    /* Check if already exists */
    lora_peer_t *peer = find_peer_by_id(state, id);
    if (peer) {
        return peer;
    }

    /* Find empty slot */
    for (size_t i = 0; i < LORA_MAX_PEERS; i++) {
        if (!state->peers[i].valid) {
            memset(&state->peers[i], 0, sizeof(lora_peer_t));
            memcpy(&state->peers[i].node_id, id, sizeof(cyxwiz_node_id_t));
            state->peers[i].valid = true;
            state->peers[i].has_node_id = true;
            state->peers[i].last_seen = get_time_ms();
            state->peer_count++;
            return &state->peers[i];
        }
    }

    return NULL;  /* Table full */
}

static void remove_peer(lora_state_t *state, lora_peer_t *peer)
{
    if (peer && peer->valid) {
        peer->valid = false;
        if (state->peer_count > 0) {
            state->peer_count--;
        }
    }
}

/* ============ Message Handling ============ */

static void send_announce(cyxwiz_transport_t *transport);
static void send_announce_ack(cyxwiz_transport_t *transport, const cyxwiz_node_id_t *to);

static void handle_announce(cyxwiz_transport_t *transport,
                           lora_state_t *state,
                           const cyxwiz_lora_announce_t *announce)
{
    /* Skip our own announcements */
    if (memcmp(&announce->node_id, &transport->local_id, sizeof(cyxwiz_node_id_t)) == 0) {
        return;
    }

    /* Add or update peer */
    lora_peer_t *peer = add_peer(state, &announce->node_id);
    if (peer) {
        peer->rssi = state->last_rssi;
        peer->snr = state->last_snr;
        peer->last_seen = get_time_ms();

        CYXWIZ_INFO("LoRa peer announced (RSSI: %d, SNR: %d)", peer->rssi, peer->snr);

        /* Notify upper layer */
        if (transport->on_peer) {
            cyxwiz_peer_info_t info;
            memcpy(&info.id, &peer->node_id, sizeof(cyxwiz_node_id_t));
            info.rssi = peer->rssi;
            info.via = CYXWIZ_TRANSPORT_LORA;
            transport->on_peer(transport, &info, transport->peer_user_data);
        }
    }

    /* Send ACK */
    send_announce_ack(transport, &announce->node_id);
}

static void handle_announce_ack(cyxwiz_transport_t *transport,
                                lora_state_t *state,
                                const cyxwiz_lora_announce_ack_t *ack)
{
    /* Check if this ACK is for us */
    if (memcmp(&ack->to_node_id, &transport->local_id, sizeof(cyxwiz_node_id_t)) != 0) {
        return;
    }

    /* Add or update peer */
    lora_peer_t *peer = add_peer(state, &ack->node_id);
    if (peer) {
        peer->rssi = state->last_rssi;
        peer->snr = state->last_snr;
        peer->last_seen = get_time_ms();

        CYXWIZ_DEBUG("LoRa announce ACK received");

        /* Notify upper layer */
        if (transport->on_peer) {
            cyxwiz_peer_info_t info;
            memcpy(&info.id, &peer->node_id, sizeof(cyxwiz_node_id_t));
            info.rssi = peer->rssi;
            info.via = CYXWIZ_TRANSPORT_LORA;
            transport->on_peer(transport, &info, transport->peer_user_data);
        }
    }
}

static void handle_data(cyxwiz_transport_t *transport,
                       lora_state_t *state,
                       const uint8_t *packet,
                       size_t len)
{
    if (len < sizeof(uint8_t) + 2 * sizeof(cyxwiz_node_id_t)) {
        return;
    }

    const cyxwiz_lora_data_t *data = (const cyxwiz_lora_data_t *)packet;

    /* Check if this is for us or broadcast */
    bool is_broadcast = true;
    for (size_t i = 0; i < sizeof(cyxwiz_node_id_t); i++) {
        if (data->to_id.bytes[i] != 0xFF) {
            is_broadcast = false;
            break;
        }
    }

    if (!is_broadcast &&
        memcmp(&data->to_id, &transport->local_id, sizeof(cyxwiz_node_id_t)) != 0) {
        return;  /* Not for us */
    }

    /* Update peer info */
    lora_peer_t *peer = find_peer_by_id(state, &data->from_id);
    if (peer) {
        peer->rssi = state->last_rssi;
        peer->snr = state->last_snr;
        peer->last_seen = get_time_ms();
    }

    /* Calculate payload length */
    size_t header_size = sizeof(uint8_t) + 2 * sizeof(cyxwiz_node_id_t);
    size_t payload_len = len - header_size;

    /* Deliver to upper layer */
    if (transport->on_recv && payload_len > 0) {
        transport->on_recv(transport, &data->from_id, data->payload, payload_len,
                          transport->recv_user_data);
    }
}

static void handle_keepalive(cyxwiz_transport_t *transport,
                            lora_state_t *state,
                            const cyxwiz_lora_keepalive_t *keepalive)
{
    /* Skip our own keepalives */
    if (memcmp(&keepalive->node_id, &transport->local_id, sizeof(cyxwiz_node_id_t)) == 0) {
        return;
    }

    /* Update peer */
    lora_peer_t *peer = find_peer_by_id(state, &keepalive->node_id);
    if (peer) {
        peer->rssi = state->last_rssi;
        peer->snr = state->last_snr;
        peer->last_seen = get_time_ms();
    }
}

static void handle_goodbye(cyxwiz_transport_t *transport,
                          lora_state_t *state,
                          const cyxwiz_lora_goodbye_t *goodbye)
{
    (void)transport;

    lora_peer_t *peer = find_peer_by_id(state, &goodbye->node_id);
    if (peer) {
        CYXWIZ_INFO("LoRa peer said goodbye");
        remove_peer(state, peer);
    }
}

static void process_packet(cyxwiz_transport_t *transport,
                          lora_state_t *state,
                          const uint8_t *data,
                          size_t len)
{
    if (len < 1) {
        return;
    }

    uint8_t type = data[0];
    state->last_rx_time = get_time_ms();

    switch (type) {
        case CYXWIZ_LORA_ANNOUNCE:
            if (len >= sizeof(cyxwiz_lora_announce_t)) {
                handle_announce(transport, state, (const cyxwiz_lora_announce_t *)data);
            }
            break;

        case CYXWIZ_LORA_ANNOUNCE_ACK:
            if (len >= sizeof(cyxwiz_lora_announce_ack_t)) {
                handle_announce_ack(transport, state, (const cyxwiz_lora_announce_ack_t *)data);
            }
            break;

        case CYXWIZ_LORA_DATA:
            handle_data(transport, state, data, len);
            break;

        case CYXWIZ_LORA_KEEPALIVE:
            if (len >= sizeof(cyxwiz_lora_keepalive_t)) {
                handle_keepalive(transport, state, (const cyxwiz_lora_keepalive_t *)data);
            }
            break;

        case CYXWIZ_LORA_GOODBYE:
            if (len >= sizeof(cyxwiz_lora_goodbye_t)) {
                handle_goodbye(transport, state, (const cyxwiz_lora_goodbye_t *)data);
            }
            break;

        default:
            /* Unknown LoRa message, might be higher-layer protocol */
            CYXWIZ_DEBUG("Unknown LoRa message type: 0x%02X", type);
            break;
    }
}

/* ============ Transmission with CSMA/CA ============ */

static bool do_transmit(lora_state_t *state, const uint8_t *data, size_t len)
{
    switch (state->backend) {
        case LORA_BACKEND_SERIAL:
            return rylr_transmit(state, data, len);

#ifndef _WIN32
        case LORA_BACKEND_SPI:
            return sx127x_transmit(state, data, len);
#endif

        default:
            return false;
    }
}

static bool channel_is_busy(lora_state_t *state)
{
#ifndef _WIN32
    if (state->backend == LORA_BACKEND_SPI) {
        return sx127x_channel_busy(state);
    }
#endif

    /* For serial modules, use time-based approach */
    uint64_t now = get_time_ms();
    return (now - state->last_rx_time) < LORA_SLOT_TIME_MS;
}

static bool transmit_with_csma(lora_state_t *state, const uint8_t *data, size_t len)
{
    /* CSMA/CA: Listen before talk */
    int attempts = 0;
    int max_attempts = LORA_MAX_BACKOFF_SLOTS;

    while (attempts < max_attempts) {
        if (!channel_is_busy(state)) {
            if (do_transmit(state, data, len)) {
                return true;
            }
        }

        /* Random backoff */
        int slots = (rand() % (1 << attempts)) + 1;
        if (slots > LORA_MAX_BACKOFF_SLOTS) {
            slots = LORA_MAX_BACKOFF_SLOTS;
        }

#ifdef _WIN32
        Sleep((DWORD)(slots * LORA_SLOT_TIME_MS));
#else
        usleep((useconds_t)(slots * LORA_SLOT_TIME_MS * 1000));
#endif

        attempts++;
    }

    CYXWIZ_WARN("LoRa CSMA/CA failed after %d attempts", attempts);
    return false;
}

/* ============ Message Sending ============ */

static void send_announce(cyxwiz_transport_t *transport)
{
    lora_state_t *state = (lora_state_t *)transport->driver_data;

    cyxwiz_lora_announce_t announce;
    announce.type = CYXWIZ_LORA_ANNOUNCE;
    memcpy(&announce.node_id, &transport->local_id, sizeof(cyxwiz_node_id_t));
    announce.capabilities = 0x01;  /* Basic node */
    announce.tx_power = state->tx_power;

    transmit_with_csma(state, (uint8_t *)&announce, sizeof(announce));
}

static void send_announce_ack(cyxwiz_transport_t *transport, const cyxwiz_node_id_t *to)
{
    lora_state_t *state = (lora_state_t *)transport->driver_data;

    cyxwiz_lora_announce_ack_t ack;
    ack.type = CYXWIZ_LORA_ANNOUNCE_ACK;
    memcpy(&ack.node_id, &transport->local_id, sizeof(cyxwiz_node_id_t));
    memcpy(&ack.to_node_id, to, sizeof(cyxwiz_node_id_t));

    /* Small delay to avoid collision with other ACKs */
    int delay = (rand() % 5 + 1) * LORA_SLOT_TIME_MS;
#ifdef _WIN32
    Sleep((DWORD)delay);
#else
    usleep((useconds_t)(delay * 1000));
#endif

    transmit_with_csma(state, (uint8_t *)&ack, sizeof(ack));
}

static void send_keepalive(cyxwiz_transport_t *transport)
{
    lora_state_t *state = (lora_state_t *)transport->driver_data;

    cyxwiz_lora_keepalive_t keepalive;
    keepalive.type = CYXWIZ_LORA_KEEPALIVE;
    memcpy(&keepalive.node_id, &transport->local_id, sizeof(cyxwiz_node_id_t));
    keepalive.peer_count = (uint8_t)state->peer_count;

    transmit_with_csma(state, (uint8_t *)&keepalive, sizeof(keepalive));
}

static void send_goodbye(cyxwiz_transport_t *transport)
{
    lora_state_t *state = (lora_state_t *)transport->driver_data;

    cyxwiz_lora_goodbye_t goodbye;
    goodbye.type = CYXWIZ_LORA_GOODBYE;
    memcpy(&goodbye.node_id, &transport->local_id, sizeof(cyxwiz_node_id_t));

    do_transmit(state, (uint8_t *)&goodbye, sizeof(goodbye));
}

/* ============ Transport Operations ============ */

static cyxwiz_error_t lora_init(cyxwiz_transport_t *transport)
{
    lora_state_t *state = cyxwiz_calloc(1, sizeof(lora_state_t));
    if (state == NULL) {
        return CYXWIZ_ERR_NOMEM;
    }

    /* Set default radio parameters */
    state->frequency = LORA_DEFAULT_FREQ_US;
    state->spreading_factor = LORA_DEFAULT_SF;
    state->bandwidth = LORA_DEFAULT_BW;
    state->coding_rate = LORA_DEFAULT_CR;
    state->tx_power = LORA_DEFAULT_POWER;
    state->serial = INVALID_SERIAL;
#ifndef _WIN32
    state->spi_fd = -1;
#endif

    /* Check environment for configuration */
    const char *freq_env = getenv("CYXWIZ_LORA_FREQ");
    if (freq_env) {
        state->frequency = (uint32_t)atol(freq_env);
    }

    const char *sf_env = getenv("CYXWIZ_LORA_SF");
    if (sf_env) {
        int sf = atoi(sf_env);
        if (sf >= 7 && sf <= 12) {
            state->spreading_factor = (uint8_t)sf;
        }
    }

    const char *power_env = getenv("CYXWIZ_LORA_POWER");
    if (power_env) {
        int power = atoi(power_env);
        if (power >= 2 && power <= 20) {
            state->tx_power = (int8_t)power;
        }
    }

    /* Try to detect and initialize hardware */
    bool hw_found = false;

    /* Try serial port first (most common for development) */
    const char *serial_port = getenv("CYXWIZ_LORA_SERIAL");
    if (!serial_port) {
#ifdef _WIN32
        serial_port = "COM3";  /* Common default on Windows */
#else
        serial_port = "/dev/ttyUSB0";  /* Common default on Linux */
#endif
    }

    strncpy(state->serial_port, serial_port, sizeof(state->serial_port) - 1);
    state->serial = serial_open(serial_port, LORA_SERIAL_BAUD);

    if (state->serial != INVALID_SERIAL) {
        CYXWIZ_INFO("LoRa serial port opened: %s", serial_port);

        if (rylr_configure(state)) {
            state->backend = LORA_BACKEND_SERIAL;
            hw_found = true;
        } else {
            serial_close(state->serial);
            state->serial = INVALID_SERIAL;
        }
    }

#ifndef _WIN32
    /* Try SPI on Linux */
    if (!hw_found) {
        const char *spi_device = getenv("CYXWIZ_LORA_SPI");
        if (!spi_device) {
            spi_device = "/dev/spidev0.0";
        }

        strncpy(state->spi_device, spi_device, sizeof(state->spi_device) - 1);
        state->spi_fd = spi_open(spi_device);

        if (state->spi_fd >= 0) {
            if (sx127x_init(state)) {
                state->backend = LORA_BACKEND_SPI;
                hw_found = true;
                sx127x_start_rx(state);
            } else {
                spi_close(state->spi_fd);
                state->spi_fd = -1;
            }
        }
    }
#endif

    if (!hw_found) {
        CYXWIZ_WARN("No LoRa hardware detected, running in stub mode");
        state->backend = LORA_BACKEND_NONE;
    }

    state->initialized = true;
    transport->driver_data = state;

    CYXWIZ_INFO("LoRa driver initialized (backend: %s)",
                state->backend == LORA_BACKEND_SERIAL ? "Serial" :
                state->backend == LORA_BACKEND_SPI ? "SPI" : "None");

    return CYXWIZ_OK;
}

static cyxwiz_error_t lora_shutdown(cyxwiz_transport_t *transport)
{
    lora_state_t *state = (lora_state_t *)transport->driver_data;
    if (state == NULL) {
        return CYXWIZ_OK;
    }

    /* Send goodbye to peers */
    if (state->backend != LORA_BACKEND_NONE && state->peer_count > 0) {
        send_goodbye(transport);
    }

    /* Close hardware */
    if (state->serial != INVALID_SERIAL) {
        serial_close(state->serial);
    }

#ifndef _WIN32
    if (state->spi_fd >= 0) {
        /* Put radio in sleep mode */
        sx127x_write_reg(state->spi_fd, SX127X_REG_OP_MODE, SX127X_MODE_SLEEP);
        spi_close(state->spi_fd);
    }
#endif

    cyxwiz_free(state, sizeof(lora_state_t));
    transport->driver_data = NULL;

    CYXWIZ_INFO("LoRa driver shutdown");
    return CYXWIZ_OK;
}

static cyxwiz_error_t lora_send(
    cyxwiz_transport_t *transport,
    const cyxwiz_node_id_t *to,
    const uint8_t *data,
    size_t len)
{
    lora_state_t *state = (lora_state_t *)transport->driver_data;
    if (!state || !state->initialized) {
        return CYXWIZ_ERR_NOT_INITIALIZED;
    }

    if (len > LORA_MAX_PAYLOAD) {
        CYXWIZ_ERROR("LoRa packet too large: %zu > %d", len, LORA_MAX_PAYLOAD);
        return CYXWIZ_ERR_PACKET_TOO_LARGE;
    }

    if (state->backend == LORA_BACKEND_NONE) {
        CYXWIZ_DEBUG("LoRa send (stub): %zu bytes", len);
        return CYXWIZ_OK;
    }

    /* Build data packet */
    uint8_t packet[LORA_MAX_PACKET_SIZE];
    cyxwiz_lora_data_t *msg = (cyxwiz_lora_data_t *)packet;

    msg->type = CYXWIZ_LORA_DATA;
    memcpy(&msg->from_id, &transport->local_id, sizeof(cyxwiz_node_id_t));

    if (to) {
        memcpy(&msg->to_id, to, sizeof(cyxwiz_node_id_t));
    } else {
        /* Broadcast */
        memset(&msg->to_id, 0xFF, sizeof(cyxwiz_node_id_t));
    }

    memcpy(msg->payload, data, len);

    size_t total_len = sizeof(uint8_t) + 2 * sizeof(cyxwiz_node_id_t) + len;

    if (transmit_with_csma(state, packet, total_len)) {
        CYXWIZ_DEBUG("LoRa sent %zu bytes", len);
        return CYXWIZ_OK;
    }

    return CYXWIZ_ERR_TRANSPORT;
}

static cyxwiz_error_t lora_discover(cyxwiz_transport_t *transport)
{
    lora_state_t *state = (lora_state_t *)transport->driver_data;
    if (!state || !state->initialized) {
        return CYXWIZ_ERR_NOT_INITIALIZED;
    }

    state->discovering = true;
    state->last_announce = 0;  /* Force immediate announce */

    CYXWIZ_INFO("LoRa discovery started");
    return CYXWIZ_OK;
}

static cyxwiz_error_t lora_stop_discover(cyxwiz_transport_t *transport)
{
    lora_state_t *state = (lora_state_t *)transport->driver_data;
    if (!state) {
        return CYXWIZ_OK;
    }

    state->discovering = false;

    CYXWIZ_INFO("LoRa discovery stopped");
    return CYXWIZ_OK;
}

static size_t lora_max_packet_size(cyxwiz_transport_t *transport)
{
    CYXWIZ_UNUSED(transport);
    return LORA_MAX_PACKET_SIZE;
}

static cyxwiz_error_t lora_poll(cyxwiz_transport_t *transport, uint32_t timeout_ms)
{
    lora_state_t *state = (lora_state_t *)transport->driver_data;
    if (!state || !state->initialized) {
        return CYXWIZ_ERR_NOT_INITIALIZED;
    }

    uint64_t now = get_time_ms();
    uint64_t end_time = now + timeout_ms;

    /* Poll for received packets */
    while (get_time_ms() < end_time) {
        uint8_t rx_buf[LORA_MAX_PACKET_SIZE];
        int rx_len = 0;

        switch (state->backend) {
            case LORA_BACKEND_SERIAL:
                /* Read from serial port */
                if (serial_available(state->serial) > 0) {
                    int n = serial_read(state->serial,
                                       (uint8_t *)state->serial_rx_buf + state->serial_rx_len,
                                       sizeof(state->serial_rx_buf) - state->serial_rx_len - 1);
                    if (n > 0) {
                        state->serial_rx_len += (size_t)n;
                        state->serial_rx_buf[state->serial_rx_len] = '\0';
                    }
                }

                /* Parse any complete messages */
                rx_len = rylr_parse_rx(state, rx_buf, sizeof(rx_buf));
                break;

#ifndef _WIN32
            case LORA_BACKEND_SPI:
                rx_len = sx127x_receive(state, rx_buf, sizeof(rx_buf));
                break;
#endif

            default:
                break;
        }

        if (rx_len > 0) {
            process_packet(transport, state, rx_buf, (size_t)rx_len);
        }

        /* Small sleep to prevent busy loop */
#ifdef _WIN32
        Sleep(1);
#else
        usleep(1000);
#endif
    }

    now = get_time_ms();

    /* Send periodic announcements when discovering */
    if (state->discovering &&
        (now - state->last_announce) >= LORA_ANNOUNCE_INTERVAL_MS) {
        send_announce(transport);
        state->last_announce = now;
    }

    /* Send keepalives */
    if (state->peer_count > 0 &&
        (now - state->last_keepalive) >= LORA_KEEPALIVE_INTERVAL_MS) {
        send_keepalive(transport);
        state->last_keepalive = now;
    }

    /* Clean up stale peers */
    for (size_t i = 0; i < LORA_MAX_PEERS; i++) {
        if (state->peers[i].valid &&
            (now - state->peers[i].last_seen) > LORA_PEER_TIMEOUT_MS) {
            CYXWIZ_INFO("LoRa peer timed out");
            remove_peer(state, &state->peers[i]);
        }
    }

    return CYXWIZ_OK;
}

const cyxwiz_transport_ops_t cyxwiz_lora_ops = {
    .init = lora_init,
    .shutdown = lora_shutdown,
    .send = lora_send,
    .discover = lora_discover,
    .stop_discover = lora_stop_discover,
    .max_packet_size = lora_max_packet_size,
    .poll = lora_poll
};

#endif /* CYXWIZ_HAS_LORA */
