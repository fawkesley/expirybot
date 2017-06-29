#!/bin/sh -eux

THIS_SCRIPT=$0
THIS_DIR=$(dirname ${THIS_SCRIPT})

SHORT_IDS_FILE="${THIS_DIR}/data/$(date +%F)/short_key_ids.txt"


copy_short_ids_dump_file() {
  mkdir -p $(dirname $SHORT_IDS_FILE)

  if [ ! -f "${SHORT_IDS_FILE}" ]; then
    mv ${HOME}/short_key_ids_dump.txt "${SHORT_IDS_FILE}"
  fi
}

make_expiring_keys_csv() {
  ./expirybot/make_csv.py "${SHORT_IDS_FILE}"
}

send_emails() {
  echo
}

clean_dev_shm() {
  rm -rf /dev/shm/tmp.expirybot.*
}

copy_short_ids_dump_file
make_expiring_keys_csv
send_emails
clean_dev_shm
