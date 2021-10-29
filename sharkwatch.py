'''J Whiteside | NT | 20211029
A script to take arguments for TSHARK (See also Wireshark) and execute it with passed arguments
then monitor the output directory for new files and move them to a new, specified, location."""

#Import any Modules used in the script.
import os
import subprocess
import sys
import time
import queue

# Check if Watchdog module is present, if not import the required functions from Watchdog. 
try:
    from watchdog.observers import Observer
    from watchdog.events import PatternMatchingEventHandler
except ImportError:
    subprocess.call([sys.executable, "-m", "pip", "install", "watchdog"])
    from watchdog.observers import Observer
    from watchdog.events import PatternMatchingEventHandler


# Using Observer, watch for files and define what happens when a file is detected.
def on_created(event):
    print(f"{event.src_path} has been created", flush=True)
    Q.put(event.src_path)

    # Test if results directory exists. If not, create it, if it does simply print it out, then run TShark
    if not os.path.isdir(RESDIR):
        try:
            os.makedirs(RESDIR)
            print(f"Results directory {RESDIR} created", flush=True)
        except():
            print(f"Making {RESDIR} caused an unknown failure", flush=True)
    else:
        print(f"Results directory {RESDIR} already exists", flush=True)
#Check the OS is Windows, then set up a queue to use for storing filenames, ready to move the files when ready, and if not Windows then error. It also shows progress to the user.
    if 'nt' == os.name and Q.qsize() > 1: #Only starts working when the queue has one or more items in it
        try:
            qitem = Q.get()
            path, file = os.path.split(qitem)
            print(f"Queue size = ", Q.qsize(), flush=True)
            print("Windows processing starting", flush=True)
            infile = " -r " + qitem
            outfile = RESDIR + file + ".csv"
            print("File to be processed: ", qitem, flush=True)
            print("Results file: ", outfile, flush=True)
            run = "\"c:\\program files\\wireshark\\tshark.exe\"" + infile + TSHARK + outfile
            print("TShark parameters:", run, flush=True)
            p = subprocess.Popen(
                run,
                shell=True)

        except():
            print(f"There was an unknown error", flush=True)
    else:
        print(f"Waiting for files to be closed before processing starts.", flush=True) #This is reported if the queue is <1 to prevent files being moved before they are closed.

#Set up of the main() function that does all the work.
def main(tshark: str, resdir: str, watcheddir: str): 
    # Global variables required for the queue and arguments.
    global Q
    global TSHARK
    global RESDIR
    TSHARK = tshark
    RESDIR = resdir
    Q = queue.Queue()
    # Tells the directory watcher to look only for *.pcap files. Ignores any directories that may get created as we don't care about them.
    patterns = "*.pcap"
    ignore_patterns = ""
    ignore_directories = False
    case_sensitive = False
    event_handler = PatternMatchingEventHandler(patterns, ignore_patterns, ignore_directories, case_sensitive)
    event_handler.on_created = on_created
    # Starts watcher process until interrupted by the keyboard.
    go_recursively = True
    dir_watcher = Observer()
    dir_watcher.schedule(event_handler, watcheddir, recursive=go_recursively)
    dir_watcher.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        dir_watcher.stop()
        dir_watcher.join()
