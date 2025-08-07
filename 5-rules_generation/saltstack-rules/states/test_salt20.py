regexp_list = []
for name in node_name_set:
    regexp_list.append(re.compile(name))

# used to see what kind of line we are on