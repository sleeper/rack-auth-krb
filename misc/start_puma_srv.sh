#!/bin/bash
LD_LIBRARY_PATH=/usr/lib bundle exec puma -Ilib misc/rack_dump_headers.ru
