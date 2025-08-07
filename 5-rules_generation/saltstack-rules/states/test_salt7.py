
    for i in range(len(opts.file_names)):
        matrix_of_code_regions[i] = run_llvm_mca_tool(opts, opts.file_names[i])
    if not opts.plot and not opts.plot_resource_pressure:
        console_print_results(matrix_of_code_regions, opts)