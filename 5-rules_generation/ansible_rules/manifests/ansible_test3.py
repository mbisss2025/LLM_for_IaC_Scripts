            update_query = ("UPDATE i_host set sw_version = %s WHERE "
                            "hostname = '%s'" % (to_release, hostname[0]))
            db_update(conn, update_query)
            LOG.info("Updated sw_version to %s on %s" %
                     (to_release, hostname[0]))