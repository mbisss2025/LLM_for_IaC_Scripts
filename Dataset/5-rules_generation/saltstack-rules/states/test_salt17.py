    outfile, pid, filename, attempts_remaining, max_wait_time
):
    report_name = find_report_in_cur_dir(pid, filename)
    if report_name:
        with open(report_name, "r") as f: