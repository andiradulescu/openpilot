#include <cstring>

#include "common/tests/native_test.h"
#include "selfdrive/pandad/panda_comms.h"

static int fake_context_storage;
static int fake_device_storage;
static int fake_handle_storage;
static libusb_device *fake_devices[] = {
  reinterpret_cast<libusb_device *>(&fake_device_storage),
  nullptr,
};

extern "C" {
int LIBUSB_CALL libusb_init(libusb_context **ctx) {
  *ctx = reinterpret_cast<libusb_context *>(&fake_context_storage);
  return 0;
}

void LIBUSB_CALL libusb_exit(libusb_context *) {}

int LIBUSB_CALLV libusb_set_option(libusb_context *, enum libusb_option, ...) {
  return 0;
}

ssize_t LIBUSB_CALL libusb_get_device_list(libusb_context *, libusb_device ***list) {
  *list = fake_devices;
  return 1;
}

void LIBUSB_CALL libusb_free_device_list(libusb_device **, int) {}

int LIBUSB_CALL libusb_get_device_descriptor(libusb_device *, libusb_device_descriptor *desc) {
  *desc = {};
  desc->idVendor = 0x3801;
  desc->idProduct = 0xddcc;
  desc->iSerialNumber = 1;
  return 0;
}

int LIBUSB_CALL libusb_open(libusb_device *, libusb_device_handle **handle) {
  *handle = reinterpret_cast<libusb_device_handle *>(&fake_handle_storage);
  return 0;
}

void LIBUSB_CALL libusb_close(libusb_device_handle *) {}

int LIBUSB_CALL libusb_get_string_descriptor_ascii(libusb_device_handle *, uint8_t, unsigned char *data, int) {
  std::memcpy(data, "stub", 4);
  return 4;
}

int LIBUSB_CALL libusb_kernel_driver_active(libusb_device_handle *, int) {
  return 0;
}

int LIBUSB_CALL libusb_detach_kernel_driver(libusb_device_handle *, int) {
  return 0;
}

int LIBUSB_CALL libusb_set_configuration(libusb_device_handle *, int) {
  return 0;
}

int LIBUSB_CALL libusb_claim_interface(libusb_device_handle *, int) {
  return 0;
}

int LIBUSB_CALL libusb_release_interface(libusb_device_handle *, int) {
  return 0;
}

const char *LIBUSB_CALL libusb_strerror(int) {
  return "stub";
}

int LIBUSB_CALL libusb_control_transfer(libusb_device_handle *, uint8_t, uint8_t, uint16_t, uint16_t,
                                        unsigned char *, uint16_t, unsigned int) {
  return 0;
}

int LIBUSB_CALL libusb_bulk_transfer(libusb_device_handle *, unsigned char, unsigned char *, int length,
                                     int *transferred, unsigned int) {
  *transferred = length - 1;
  return 0;
}
}

void test_short_successful_write_disconnects() {
  PandaUsbHandle handle("");
  unsigned char data[] = {0, 1};

  CHECK(handle.bulk_write(3, data, sizeof(data), 5) == 1);
  CHECK(!handle.connected.load());
  CHECK(!handle.comms_healthy.load());
}

int main() {
  return run_native_test(test_short_successful_write_disconnects);
}
