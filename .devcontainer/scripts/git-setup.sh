#!/bin/bash

GIT_TOKEN=$(echo "protocol=https
host=github.com" | git credential fill 2>/dev/null | grep "^password=" | cut -d= -f2)

if [ -n "$GIT_TOKEN" ]; then
    USER_DATA=$(curl -s -H "Authorization: token $GIT_TOKEN" https://api.github.com/user)
    GIT_USER_NAME=$(echo "$USER_DATA" | grep '"name"' | head -1 | sed 's/.*"name": "\(.*\)",/\1/')
    GIT_USER_LOGIN=$(echo "$USER_DATA" | grep '"login"' | head -1 | sed 's/.*"login": "\(.*\)",/\1/')
    GIT_USER_EMAIL=$(echo "$USER_DATA" | grep '"email"' | head -1 | sed 's/.*"email": \(.*\),/\1/' | tr -d '"')
    
    [ -z "$GIT_USER_NAME" ] || [ "$GIT_USER_NAME" = "null" ] && GIT_USER_NAME="$GIT_USER_LOGIN"
    
    if [ -z "$GIT_USER_EMAIL" ] || [ "$GIT_USER_EMAIL" = "null" ]; then
        GIT_USER_EMAIL="${GIT_USER_LOGIN}@users.noreply.github.com"
    fi
    
    git config --global user.name "$GIT_USER_NAME"
    git config --global user.email "$GIT_USER_EMAIL"
fi
