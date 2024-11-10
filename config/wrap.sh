#!/bin/bash

echo "nameserver $(dig +short dns)" > /etc/resolv.conf

/bin/sh
