#!/usr/bin/env sh

set -e;

if [ -z $HOST ]; then
    echo "Base URL is required"
    exit 1
fi

if [ -z $ACCESS_KEY ]; then
    echo "Access key is required"
    exit 1
fi

if [ -n $TWITTER_ACCOUNT ]; then
    echo "https://$HOST/twitter/media/${TWITTER_ACCOUNT}?code=$(echo -n /twitter/media/${TWITTER_ACCOUNT}${ACCESS_KEY} | md5sum | tr -d ' -')&readable=1&authorNameBold=1&showAuthorInTitle=1&showAuthorInDesc=1&addLinkForPics=1&showTimestampInDescription=1&includeRts=0"
fi
