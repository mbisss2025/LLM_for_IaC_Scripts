        else:
            include_stmt = "'#include <%s>' % os.path.join(r'" + public_api_dir + "', header)"
        list = [eval(include_stmt) for header in public_headers if (
            header.startswith("SB") and header.endswith(".h"))]
        includes = '\n'.join(list)