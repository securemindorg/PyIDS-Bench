import psutil
import time
import datetime

procname = "firefox"

while True:
	output_sys = open("/tmp/sysstats_counter.log", 'a')

	for proc in psutil.process_iter():
		if proc.name == procname:
			p = proc

        p.cmdline

        proc_rss, proc_vms =  p.get_memory_info()
        proc_cpu =  p.get_cpu_percent(1)

        scol1 = str(proc_rss / 1024)
        scol2 = str(proc_cpu)

	print scol1
	print scol2

	now = str(datetime.datetime.now())

        output_sys.write(scol1)
        output_sys.write(", ")
        output_sys.write(scol2)
        output_sys.write(", ")
        output_sys.write(now)
        output_sys.write("\n")

        output_sys.close( )

        time.sleep(1)
