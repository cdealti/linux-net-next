#ifndef __ATUSB_H__
#define __ATUSB_H__

#define ATUSB_VENDOR_ID     0x20b7
#define ATUSB_PRODUCT_ID    0x1540

#define ATUSB_DRIVER_NAME	"atusb at86rf230"

#define ATUSB_BUILDSTR_SIZE	256

/* system status/control grp */
#define ATUSB_ID			0x00
#define ATUSB_BUILD			0x01
#define ATUSB_RESET			0x02
/* debug/test group */
#define ATUSB_RF_RESET		0x10
#define ATUSB_POLL_INT		0x11
/* atusb-sil only */
#define ATUSB_TEST			0x12
#define ATUSB_TIMER			0x13
#define ATUSB_GPIO			0x14
#define ATUSB_SLP_TR		0x15
#define ATUSB_GPIO_CLEANUP	0x16
/* transceiver group */
#define ATUSB_REG_WRITE		0x20
#define ATUSB_REG_READ		0x21
#define ATUSB_BUF_WRITE		0x22
#define ATUSB_BUF_READ		0x23
#define ATUSB_SRAM_WRITE	0x24
#define ATUSB_SRAM_READ		0x25
/* SPI group */
#define ATUSB_SPI_WRITE		0x30
#define ATUSB_SPI_READ1		0x31
#define ATUSB_SPI_READ2		0x32
#define ATUSB_SPI_WRITE2_SYNC	0x33
/*  HardMAC group */
#define ATUSB_RX_MODE		0x40
#define ATUSB_TX			0x41

#define ATUSB_CTRL_TIMEOUT	1000

#define ATUSB_CMD_MASK			0xe0
#define ATUSB_DATA_MASK			0x3f

#define ATUSB_CMD_REG_READ		0x80
#define ATUSB_CMD_REG_WRITE		0xc0
#define ATUSB_CMD_FB_READ		0x20
#define ATUSB_CMD_FB_WRITE		0x60
#define ATUSB_CMD_SRAM_READ		0x00
#define ATUSB_CMD_SRAM_WRITE	0x40

#define AT86RF230_MAX_BUF_SIZE	128

#define MAX_URBS 32

struct atusb_dev_info {
	__u8 major;
	__u8 minor;
	__u8 hw_info;
};

struct atusb {
	struct usb_device *udev;
	struct urb *urb;

	struct spi_master *master;
	struct spi_device *spi;

	struct atusb_dev_info dev_info;
	struct tasklet_struct tasklet;

	uint8_t irq_buf;
};

static inline int atusb_rcv_ctrl(struct usb_device *udev,
		__u8 request, __u16 value, __u16 index, void *data, __u16 size)
{
	return usb_control_msg(udev, usb_rcvctrlpipe(udev, 0),
			request, USB_TYPE_VENDOR | USB_DIR_IN,
			value, index, data, size, ATUSB_CTRL_TIMEOUT);
}

static inline int atusb_snd_ctrl(struct usb_device *udev,
		__u8 request, __u16 value, __u16 index, const void *data, __u16 size)
{
	return usb_control_msg(udev, usb_sndctrlpipe(udev, 0),
			request, (USB_TYPE_VENDOR | USB_DIR_OUT),
			value, index, (void *)data, size, ATUSB_CTRL_TIMEOUT);
}

#endif /* __ATUSB_H__ */
