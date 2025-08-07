        re.MULTILINE,
    )
    module_utils += re.findall(r"from\s+ansible_collections\.ibm\." + collection_to_use
