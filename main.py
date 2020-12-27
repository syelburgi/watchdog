# !/usr/bin/env python3
import argparse
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import os
import pyzipper
import datetime
from os.path import basename
import threading
from commonregex import CommonRegex, phone, email
import re
import signal
import sys


class InputProcessing(FileSystemEventHandler):
    def __init__(self, opath):
        self.output_path = opath
        if os.path.isdir(self.output_path + '/todecode') is False:
            os.mkdir('{}/todecode'.format(self.output_path))

    def on_modified(self, event):
        try:
            print(f'event type: {event.event_type}  path : {event.src_path}')
            if not event.src_path.endswith('.txt'):
                return

            ts = int(time.time())
            secret_password = ts
            file_name_format = datetime.datetime.fromtimestamp(ts).strftime('%Y_%m_%d_%I_%M_%S_%p')
            if os.path.isdir(self.output_path + '/todecode') is False:
                os.mkdir('{}/todecode'.format(self.output_path))

            zipfile = self.output_path + '/todecode/' + file_name_format + '.zip'
            filepath = event.src_path

            if os.path.isfile(filepath) is False:
                return

            with pyzipper.AESZipFile(zipfile, 'w', compression=pyzipper.ZIP_LZMA, encryption=pyzipper.WZ_AES) as zf:
                zf.setpassword(bytes(secret_password))
                zf.write(filepath, basename(filepath))

            os.remove(event.src_path)
        except Exception as e:
            os.remove(event.src_path)
            print(str(e))


class OutputProcessing(FileSystemEventHandler):
    def __init__(self, opath):
        self.output_path = opath

    def on_modified(self, event):
        try:
            print(f'event type: {event.event_type}  path : {event.src_path}')
            if not event.src_path.endswith('.zip'):
                return

            zipfilepath = event.src_path
            zipfile = basename(event.src_path)
            name = zipfile.split('.')
            dt = datetime.datetime.strptime(name[0], '%Y_%m_%d_%I_%M_%S_%p')
            secret_password = int(dt.replace().timestamp())
            with pyzipper.AESZipFile(zipfilepath) as zf:
                zf.setpassword(bytes(secret_password))
                file_name = zf.namelist()[0]
                file_content = zf.read(file_name)

            file_content = str(file_content, 'utf-8')
            os.remove(zipfilepath)
            parsed_text = CommonRegex(file_content)
            pii_present = False
            pii_dict = {"dates": "date-", "times": "time-", "links": "link-",
                        "ips": "ip-", "ipv6s": "ip-", "prices": "price-", "hex_colors": "colour-",
                        "credit_cards": "card-", "btc_addresses": "address-", "street_addresses": "address-"}

            if parsed_text.phones:
                pii_present = True
                file_content = re.sub(phone, "Number-xyz", file_content)

            if parsed_text.emails:
                pii_present = True
                file_content = re.sub(email, "Email-xyz", file_content)

            for key, value in parsed_text.__dict__.items():
                if key in pii_dict:
                    rstring = pii_dict[key]
                else:
                    continue

                for c, s in enumerate(value):
                    pii_present = True
                    file_content = re.sub(s, rstring + "{}".format(c), file_content)

            if pii_present:
                file_name = self.output_path + "/PII_filtered_" + file_name
            else:
                file_name = self.output_path + '/' + file_name

            with open(file_name, "w+") as f:
                f.write(file_content)
        except Exception as e:
            os.remove(zipfilepath)
            print(str(e))


def run_watcher(path, event_handler):

    observer = Observer()
    observer.schedule(event_handler, path, recursive=False)
    observer.daemon = True
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


def signal_handler(sig, frame):
    print("Signal handler exit")
    sys.exit(0)


if __name__ == '__main__':
    try:
        parser = argparse.ArgumentParser(description='PII Filtering')
        parser.add_argument('-I', '--input', type=str, help="Input Folder path to monitor.")
        parser.add_argument('-O', '--output', type=str, help="Output Folder path after PII Filtering")
        args = parser.parse_args()

        if args.input is None or args.output is None:
            print("Input and output directory should be specified")
            exit(1)

        input_path = r'{}'.format(args.input)
        if os.path.isdir(input_path) is False:
            print("Input folder path is invalid or doesn't exists")
            exit(1)

        output_path = r'{}'.format(args.output)
        if os.path.isdir(output_path) is False:
            print("Output folder path is invalid or doesn't exists")
            exit(1)

        if input_path == output_path:
            print("Input path and output path cannot be same")
            exit(1)

        signal.signal(signal.SIGINT, signal_handler)
        input_event_handler = InputProcessing(output_path)
        output_event_handler = OutputProcessing(output_path)
        input_watcher_thread = threading.Thread(target=run_watcher, args=(input_path, input_event_handler,))
        input_watcher_thread.daemon = True
        input_watcher_thread.start()

        output_watcher_thread = threading.Thread(target=run_watcher, args=(output_path + '/todecode',
                                                                           output_event_handler,))
        output_watcher_thread.daemon = True
        output_watcher_thread.start()

        input_watcher_thread.join()
        output_watcher_thread.join()

    except Exception as e:
        print(str(e))



