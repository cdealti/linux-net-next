#include <linux/module.h>
#include <linux/usb.h>

#include <linux/spi/spi.h>
#include <linux/spi/at86rf230.h>

#include <linux/gpio.h>

#include "atusb.h"

static struct at86rf230_platform_data at86rf230_platform_data = {
	.rstn	= -1,
	.slp_tr	= -1,
	.dig2	= -1,
};

static struct spi_board_info spi_board_info = {
	.modalias = "at86rf230",
	.max_speed_hz = 8 * 1000 * 1000,
	.bus_num = -1,
	.chip_select = 0,
	.platform_data = &at86rf230_platform_data,
	.irq = -1,
};

static int atusb_setup(struct spi_device *spi)
{
	return 0;
}

static int handle_spi_req(struct atusb *atusb,
		struct spi_message *msg)
{
	int ret;
	struct spi_transfer *first_xfer, *xfer;
	uint8_t req;
	uint8_t tmp_buf[256];

	first_xfer = container_of(msg->transfers.next,
			struct spi_transfer, transfer_list);

	req = *((uint8_t *)first_xfer->tx_buf) &
		0xc0;

	switch (req) {
	case ATUSB_CMD_REG_READ:
		ret = atusb_rcv_ctrl(atusb->udev, ATUSB_REG_READ,
				0, *((uint8_t *)first_xfer->tx_buf),
				first_xfer->rx_buf + 1, 1);
		if (ret < 0)
			goto err;

		dev_vdbg(&atusb->udev->dev,
				"atusb_cmd_reg_read:\t"
				"addr: 0x%02x, \tdata: 0x%02x\n",
				 *((uint8_t *)first_xfer->tx_buf) & ATUSB_DATA_MASK,
				 *((uint8_t *)first_xfer->rx_buf + 1));
		goto done;
	case ATUSB_CMD_REG_WRITE:
		if ((*((uint8_t *)first_xfer->tx_buf) &
				ATUSB_DATA_MASK) == 0x03) {
			goto done;
		}

		ret = atusb_snd_ctrl(atusb->udev, ATUSB_REG_WRITE,
				*((uint8_t *)first_xfer->tx_buf+1),
				*((uint8_t *)first_xfer->tx_buf), NULL, 0);
		if (ret < 0)
			goto err;

		dev_vdbg(&atusb->udev->dev,
				"atusb_cmd_reg_write:\t"
				"addr: 0x%02x, \tdata: 0x%02x\n",
				*((uint8_t *)first_xfer->tx_buf) & ATUSB_DATA_MASK,
				*((uint8_t *)first_xfer->tx_buf + 1));
		goto done;
	default:
		dev_vdbg(&atusb->udev->dev, "not a reg cmd\n");
	}

	req = *((uint8_t *)first_xfer->tx_buf) &
		0xe0;

	switch (req) {
	case ATUSB_CMD_FB_READ:
		xfer = container_of(msg->transfers.prev,
				struct spi_transfer, transfer_list);

		if (xfer == first_xfer) {
			ret = atusb_rcv_ctrl(atusb->udev, ATUSB_SPI_READ1,
					*((uint8_t *)xfer->tx_buf), 0,
					(uint8_t *)xfer->rx_buf + 1, 1);
			if (ret < 0)
				goto err;

			goto done;
		} else {
			ret = atusb_rcv_ctrl(atusb->udev, ATUSB_SPI_READ1,
					*((uint8_t *)first_xfer->tx_buf), 0,
					tmp_buf, xfer->len + 1);
			if (ret < 0)
				goto err;

			memcpy(xfer->rx_buf, tmp_buf + 1, xfer->len);
#if 0
			ret = atusb_rcv_ctrl(atusb->udev, ATUSB_BUF_READ,
					0, 0, (uint8_t *)xfer->rx_buf, AT86RF230_MAX_BUF_SIZE);
			if (ret < 0)
				goto err;
#endif
			dev_vdbg(&atusb->udev->dev,
					"atusb_cmd_fb_read:\t"
					"length: %d\n",
					xfer->len);
		}
		goto done;
	case ATUSB_CMD_FB_WRITE:
		xfer = container_of(msg->transfers.prev,
				struct spi_transfer, transfer_list);

		dev_vdbg(&atusb->udev->dev,
				"atusb_cmd_fb_write:\t"
				"length: %d\n",
				xfer->len);

		ret = atusb_snd_ctrl(atusb->udev, ATUSB_SPI_WRITE,
				*((uint8_t *)first_xfer->tx_buf),
				*((uint8_t *)first_xfer->tx_buf + 1),
				(uint8_t *)xfer->tx_buf, xfer->len + 1);
		if (ret < 0)
			goto err;
#if 0
		ret = atusb_snd_ctrl(atusb->udev, ATUSB_BUF_WRITE,
				0, 0,
				(uint8_t *)xfer->tx_buf,
				xfer->len + 2);
		if (ret < 0)
			goto err;
#endif

		goto done;
	case ATUSB_CMD_SRAM_READ:
		dev_vdbg(&atusb->udev->dev, "atusb_cmd_sram_read:\t"
				"not implemented.\n");
		ret = -EIO;
		goto err;
	case ATUSB_CMD_SRAM_WRITE:
		dev_vdbg(&atusb->udev->dev, "atusb_cmd_sram_write:\t"
				"not implemented.\n");
		ret = -EIO;
		goto err;
	default:
		dev_err(&atusb->udev->dev, "Invalid cmd to transfer: cmd: 0x%x.\n",
				req);
		BUG();
		ret = -EINVAL;
		goto err;
	}

	msg->actual_length = first_xfer->len;
done:
	return 0;
err:
	return ret;
}

static int atusb_transfer_one_message(struct spi_master *master,
		struct spi_message *msg)
{
	int ret;
	struct atusb *atusb = spi_master_get_devdata(master);

	if (unlikely(list_empty(&msg->transfers))) {
		ret = -EINVAL;
		goto err;
	}

	ret = handle_spi_req(atusb, msg);
	if (ret < 0)
		goto err;

	//msg->actual_length = xfer->len;
	msg->status = 0;
	msg->complete(msg->context);

	spi_finalize_current_message(master);
	return 0;
err:
	dev_err(&atusb->udev->dev, "Failed to send spi message "
			"to usb bus, err: %d.\n", ret);
	msg->status = ret;
	spi_finalize_current_message(master);
	return ret;
}

static int atusb_show_dev_info(struct atusb *atusb)
{
	int ret;
	char buildstr[ATUSB_BUILDSTR_SIZE+1];

	memset(buildstr, 0, ATUSB_BUILDSTR_SIZE+1);

	ret = atusb_rcv_ctrl(atusb->udev, ATUSB_ID, 0, 0,
			&atusb->dev_info, sizeof(struct atusb_dev_info));
	if (ret < 0) {
		goto err;
	}

	dev_info(&atusb->udev->dev,
	    "Firmware: major: %u, minor: %u, hardware type: %u\n",
	    atusb->dev_info.major, atusb->dev_info.minor,
	    atusb->dev_info.hw_info);

	ret = atusb_rcv_ctrl(atusb->udev, ATUSB_BUILD, 0, 0,
			buildstr, ATUSB_BUILDSTR_SIZE);
	if (ret < 0) {
		goto err;
	}

	dev_info(&atusb->udev->dev, "Firmware: build %s\n", buildstr);

	return 0;
err:
	return ret;
}

static void atusb_bulk_complete_handler(struct urb *urb)
{
	struct atusb *atusb = urb->context;

	if (urb->status == -ENOENT || urb->status == -ECONNRESET
			|| urb->status == -ESHUTDOWN) {
		return;
	}

	if (urb->status != -EINPROGRESS && urb->status != 0)
		goto resubmit;

	tasklet_hi_schedule(&atusb->tasklet);
resubmit:
	usb_submit_urb(urb, GFP_ATOMIC);
}

static int atusb_init_irq_bulk(struct atusb *atusb)
{
	int ret;

	if (atusb->urb) {
		ret = -EINVAL;
		goto err;;
	}

	atusb->urb = usb_alloc_urb(0, GFP_KERNEL);
	if (!atusb->urb) {
		ret = -ENOMEM;
		goto err;
	}

	usb_fill_bulk_urb(atusb->urb, atusb->udev,
			usb_rcvbulkpipe(atusb->udev, 1),
			&atusb->irq_buf, 1,
			atusb_bulk_complete_handler, atusb);

	ret = usb_submit_urb(atusb->urb, GFP_KERNEL);
	if (ret < 0) {
		goto err_submit;
	}

	return 0;
err_submit:
	usb_free_urb(atusb->urb);
err:
	return ret;
}

static void atusb_reset(void *atusb_data)
{
	int ret;
	struct atusb *atusb = atusb_data;

	ret = atusb_snd_ctrl(atusb->udev, ATUSB_RF_RESET, 0, 0, NULL, 0);
	if (ret < 0)
		dev_err(&atusb->udev->dev, "Reset failed, err: %d\n", ret);
}

static int atusb_probe(struct usb_interface *interface,
		const struct usb_device_id *id)
{
	int ret = -EINVAL;
	struct usb_device *udev = interface_to_usbdev(interface);
	struct spi_master *master = NULL;
	struct atusb *atusb = NULL;

	master = spi_alloc_master(&udev->dev, sizeof(struct atusb));
	if (!master) {
		ret = -ENOMEM;
		goto err;
	}

	atusb = spi_master_get_devdata(master);
	atusb->master = spi_master_get(master);

	atusb->udev = usb_get_dev(udev);
	usb_set_intfdata(interface, atusb);

	ret = atusb_show_dev_info(atusb);
	if (ret < 0) {
		goto err;
	}

	master->mode_bits = SPI_CPOL | SPI_CPHA | SPI_CS_HIGH;
	master->bus_num	= -1;
	master->num_chipselect = 1;
	master->setup = atusb_setup;
	master->transfer_one_message = atusb_transfer_one_message;

	ret = spi_register_master(master);
	if (ret < 0) {
		goto err_free_master;
	}

	atusb_init_irq_bulk(atusb);

	at86rf230_platform_data.atusb_reset = atusb_reset;
	at86rf230_platform_data.atusb_data = atusb;
	at86rf230_platform_data.atusb_tasklet = &atusb->tasklet;

	atusb->spi = spi_new_device(master, &spi_board_info);
	if (!atusb->spi) {
		goto err_unregister_master;
	}

	return 0;
err_unregister_master:
	spi_unregister_master(master);
err_free_master:
	spi_master_put(master);
err:
	return ret;
}

static void atusb_disconnect(struct usb_interface *interface)
{
	struct atusb *atusb = usb_get_intfdata(interface);

	usb_kill_urb(atusb->urb);
	usb_free_urb(atusb->urb);

	usb_set_intfdata(interface, NULL);
	usb_put_dev(atusb->udev);

	spi_dev_put(atusb->spi);
	spi_unregister_master(atusb->master);
	spi_master_put(atusb->master);

	kfree(atusb);
}

/*  The devices we work with */
static const struct usb_device_id atusb_device_table[] = {
	{ .match_flags			= USB_DEVICE_ID_MATCH_DEVICE
		| USB_DEVICE_ID_MATCH_INT_INFO,
		.idVendor			= ATUSB_VENDOR_ID,
		.idProduct			= ATUSB_PRODUCT_ID,
		.bInterfaceClass	= USB_CLASS_VENDOR_SPEC },
	/* end with null element */
	{},
};
MODULE_DEVICE_TABLE(usb, atusb_device_table);

struct usb_driver tis_usb_driver = {
	.name = ATUSB_DRIVER_NAME,
	.probe = atusb_probe,
	.disconnect = atusb_disconnect,
	.id_table = atusb_device_table,
};
module_usb_driver(tis_usb_driver);

MODULE_LICENSE("GPL");
