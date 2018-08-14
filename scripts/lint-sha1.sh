#!/bin/bash

if [[ $(grep sha1 package-lock.json | wc -l --) > 0 ]] ; then
    exit 1;
else
    exit 0;
fi
