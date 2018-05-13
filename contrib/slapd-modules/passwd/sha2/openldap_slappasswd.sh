#!/bin/sh
#
#  openssl_slappasswd -- OpenLDAP slappasswd(with pw-sha2)-compatible
#                        hash generator only with openssl, sed, tail, sh
#  ==========================================================
   Copyright='(C) 2018 henoheno@users.osdn.me'
   Homepage='https://ja.osdn.net/users/henoheno/'
   License='The OpenLDAP Public License, and revised BSD License'
#
#  ( Test environment: CentOS Linux 7 with openssl )

# Software versioning
VERS_major='0'         # User Interface (file-name etc.) are holded
VERS_minor='9.1'       # Release / build number
VERSION="$VERS_major.$VERS_minor"

# Name and Usage --------------------------------------------
ckname="` basename -- "$0" `"

usage(){
  trace 'usage()' || return  # (DEBUG)
   warn "$ckname -- OpenLDAP slappasswd(with pw-sha2)-compatible"
   warn '                  hash generator only with openssl, sed, tail, sh'
  qwarn
  qwarn "Usage: $ckname [-h scheme] [-s secret]"
  qwarn '       [--salt salt] [-n]'
  qwarn
  qwarn '  -h scheme, --scheme scheme'
  qwarn '        password hash scheme:'
  qwarn '           md5,  sha1,  sha256,  sha384,  sha512,'
  qwarn '           smd5, ssha1, ssha256, ssha384, ssha512,'
  qwarn '           {MD5},  {SHA1},  {SHA256},  {SHA384},  {SHA512},'
  qwarn '           {SMD5}, {SSHA1}, {SSHA256}, {SSHA384}, {SSHA512}'
  qwarn "           (default: '{SSHA256}')"
  qwarn "           You can put '{SCHEME}base64-encoded-hash-and-salt' to verify"
  qwarn
  qwarn '  -s secret, --secret secret'
  qwarn '        passphrase or secret'
  qwarn
  qwarn '  -T filepath, --file filepath'
  qwarn '        use entire file contents for secret'
  qwarn
  qwarn '  --salt salt'
  qwarn '        specify salt for smd5, ssha1, ssha256, ssha384, ssha512'
  qwarn '        (default: random 8 bytes)'
  qwarn
  qwarn '  -n    omit trailing newline'
  qwarn
  qwarn 'Examples:'
  qwarn "  $ $ckname --secret pass --scheme ssha256"
  qwarn '  {SSHA256}10/w7o2juYBrGMh32/KbveULW9jk2tejpyUAD+uC6PE= # random salt'
  qwarn "  $ $ckname --secret pass --scheme ssha256 --salt 'foobar' # specify salt from --salt"
  qwarn '  {SSHA256}Yuz0lZnd9xxLQhxgOSuV8b4GlTzeOWKriq9ay51aoLxmb29iYXI='
  qwarn "  $ $ckname --secret pass --scheme '{SSHA256}Yuz0lZnd9xxLQhxgOSuV8b4GlTzeOWKriq9ay51aoLxmb29iYXI='"
  qwarn '  {SSHA256}Yuz0lZnd9xxLQhxgOSuV8b4GlTzeOWKriq9ay51aoLxmb29iYXI= # specify salt from data, verify OK'
  qwarn ; return 1
}

# Common functions ------------------------------------------
warn(){  echo "$*" 1>&2 ; }
qwarn(){ test "$__quiet"   || warn "$*" ; }
qecho(){ test "$__quiet"   || echo "$*" ; }
vwarn(){ test "$__verbose" && warn "$*" ; }
vecho(){ test "$__verbose" && echo "$*" ; }
dwarn(){ test "$__debug"   && warn "$*" ; }
decho(){ test "$__debug"   && echo "$*" ; }
err() {  warn "Error: $*" ; exit 1 ; }

quote(){
  test    $# -gt 0  && {  echo -n  "\"$1\"" ; shift ; }
  while [ $# -gt 0 ] ; do echo -n " \"$1\"" ; shift ; done ; echo
}

trace(){
  test "$__debug" || return 0  # (DEBUG)
  _msg="$1" ; test $# -gt 0 && shift ; warn "  $_msg    : ` quote "$@" `"
}

version(){
  trace 'version()' || return  # (DEBUG)
  warn ; warn "$ckname $VERSION" ; warn "Copyright $Copyright"
  warn "$Homepage" ; warn "License: $License" ; warn ; return 1
}

# Prerequisites ---------------------------------------------

# openssl commnad

# Default variables -----------------------------------------

# Function verifying arguments ------------------------------

# _NOP = Do nothing (No operation)
getopt(){ _arg=noarg
  trace 'getopt()' "$@"  # (DEBUG)

  case "$1" in
  ''  )  echo 1 ;;

  # Grobal and Local options for slappasswd
  -h|--sc|--sch|--sche|--schem|--scheme        ) echo _scheme 2 ; _arg="ALLOWEMPTY" ;;
  -s|--se|--sec|--secr|--secr|--secre|--secret ) echo _secret 2 ; _arg="$2" ;;
  -T|--fi|--fil|--file ) echo _file 2 ; _arg="$2" ;;
  -n|--omit-the-trailing-newline ) echo _nonewline ;;

   # Do nothing, compatibility only
  -u|--userPassword      ) echo _NOP ;;
  -o|--option            ) echo _NOP 2 ; _arg="$2" ;;

  # Not supported
  #-c|--crypt-salt-format ) echo _NOP 2 ; _arg="$2" ;;
  # slappasswd seems not work for SHA-2
  #-g|--gen|--gene|--gener|--generate ) echo _NOP ;;

  # Original options
  # Salt not from with scheme
  --sa|--sal|--salt ) echo _salt 2 ; _arg="$2" ;;

  # Common options
  -[hH]|--he|--help ) echo _usage exit1 ;;
     --vers|--versi|--versio|--version ) echo _version exit1 ;;
  -v|--verb|--verbo|--verbos|--verbose ) echo _verbose ;;
  -q|--qu|--qui|--quiet        ) echo _quiet ;;
  -f|--fo|--for|--forc|--force ) echo _force ;;
     --de|--deb|--debu|--debug ) echo _debug ;;

  -*  ) warn "Error: Unknown option \"$1\"" ; return 1 ;;

  # No commands
   *  ) echo _usage exit1 ;;
  esac

  test 'x' != "x$_arg"
}

preparse_single_options(){
  while [ $# -gt 0 ] ; do
    chs="` getopt "$@" 2> /dev/null `"
    for ch in $chs ; do
      case "$ch" in
        _* ) echo "_$ch" ;;
      esac
    done
    shift
  done
}

# Working start ---------------------------------------------

# Show arguments in one line (DEBUG)
case '--debug' in "$1"|"$3") false ;; * ) true ;; esac || {
  test 'x--debug' = "x$1" && shift ; __debug=on ; trace 'Args  ' "$@"
}

# No argument (slappasswd compatible way)
if [ $# -eq 0 ] ; then
  _scheme= ; _secret= ; _salt= ; _file=
fi

# Preparse
for i in ` preparse_single_options "$@" ` ; do
  eval "$i=on"
done

# Parse
while [ $# -gt 0 ] ; do
  chs="` getopt "$@" `" || { warn "Syntax error with '$1'" ; usage; exit 1 ; }
  trace '$chs  ' "$chs"  # (DEBUG)

  for ch in $chs ; do
  case "$ch" in
   ## Single options
    _usage   ) usage     ;;
    _version ) version   ;;

   ## Double Options
   _secret ) _secret="$2" ; _file=   ;;
   _file   ) _file="$2"   ; _secret= ;;
   _scheme ) _scheme="$2" ;;
   _salt   ) _salt="$2"   ;;

   _*      ) shift ;; ## Preparsed or NOP

   ## Commands
   [1-3]     ) shift $ch ;;
   exit      ) exit      ;;
   exit1     ) exit 1    ;;
   * )
      if [ -z "$__help" ]
      then err "Unknown command \"$1\""
      else err "Unknown command \"$2\""
      fi
  esac
  done
done

# No secret
if [ 'x' = "x$_secret$_file" ] ; then
  echo -n 'New password: '          1>&2 ; read    _secret
  echo -n 'Re-enter new password: ' 1>&2 ; read -s _secret2
  echo
  if [ 'x' = "x$_secret" ] ; then
    warn 'Password verification failed.'
    usage
    exit 1
  fi
  if [ "x$_secret" != "x$_secret2" ] ; then
    warn 'Password values do not match'
    usage
    exit 1
  fi
fi


# Working start ---------------------------------------------

_openssl_slappasswd()
{
  if [ 'x' != "$__debug" ]
  then base='_openssl_slappasswd(): '
  else base=
  fi
  warn(){  echo "$base$*" 1>&2 ; }
  dwarn(){ test 'x' != "x$__debug"   && warn "$*" ; }

  # Prerequisites: openssl command
  for target in openssl sed tail ; do
    if ! which "$target" 1>/dev/null 2>&1 ; then
      warn "Command not found: $target" ; exit 1
    fi
  done

  scheme="$1"
  secret="$2"
  salt="$3"
  file="$4"
  hash=
  case "$scheme" in
    '{'[a-zA-Z0-9./_-][a-zA-Z0-9./_-]*'}'* )
      scheme="` echo "$1" | sed 's#^\({[a-zA-Z0-9./_-][a-zA-Z0-9./_-]*}\).*#\1#' | tr A-Z a-z | tr -d '{}' `"
      hash="`   echo "$1" | sed  's#^{[a-zA-Z0-9./_-][a-zA-Z0-9./_-]*}##' `"
    ;;
  esac
  if [ 'x' != "x$__debug" ] ; then
    warn "scheme=$scheme"
    warn "hash=$hash"
    warn "secret=$secret"
    warn "file=$_file"
    warn "salt=$salt"
  fi

  algo= ; l= ; prefix=
  case "$scheme" in
    ''      ) algo='-sha256'; l=33; prefix='{SSHA256}'; scheme=ssha256 ;;
    ssha256 ) algo='-sha256'; l=33; prefix='{SSHA256}';;
     sha256 ) algo='-sha256'; l=  ; prefix='{SHA256}' ;;
    ssha384 ) algo='-sha384'; l=49; prefix='{SSHA384}';;
     sha384 ) algo='-sha384'; l=  ; prefix='{SHA384}' ;;
    ssha512 ) algo='-sha512'; l=65; prefix='{SSHA512}';;
     sha512 ) algo='-sha512'; l=  ; prefix='{SHA512}' ;;
       ssha ) algo='-sha1'  ; l=21; prefix='{SSHA}'   ;; # Not -sha
       sha1 ) algo='-sha1'  ; l=  ; prefix='{SHA}'    ;; # Not -sha
       smd5 ) algo='-md5'   ; l=17; prefix='{SMD5}'   ;;
        md5 ) algo='-md5'   ; l=  ; prefix='{MD5}'    ;;
    * ) warn "Non-supported scheme: $scheme" ; return 1 ;;
  esac

  # <- Binary-friendry way but maybe slow:
  #    You know if your /tmp is on the memory or not
  tmp_header="/tmp/tmp_$$_` openssl rand -hex 8 `"
  tmp_payload="${tmp_header}_payload.bin"
     tmp_salt="${tmp_header}_salt.bin"
  trap 'rm -f "$tmp_payload" "$tmp_salt"' 1 3 4 6 10 15

  case "$scheme" in
    ssha* | smd5* )
      if [ 'xx' != "x${salt}x" ]
      then
        dwarn "Salt: --salt '$salt'"
        echo -n "$salt"  > "$tmp_salt"
      else
        if [ 'xx' != "x${hash}x" ]
        then
          dwarn "Salt: from hash"
           echo -n "$hash" | openssl enc -d -base64 -A | tail -c "+$l" >  "$tmp_salt" # [O]
          #echo -n "$hash" | openssl enc -d -base64 -A | cut  -b "$l-" >  "$tmp_salt" # [X]
        else
          dwarn "Salt: random"
          openssl rand 8 > "$tmp_salt"
        fi
      fi
    ;;
  esac

  if [ 'x' = "x$_file" -o ! -f "$_file" ] ; then
    echo -n "$secret" > "$tmp_payload"
    _file="$tmp_payload"
  fi

  echo -n "$prefix"

  openssl_file2hash(){
    algo="$1" ; shift
    _sfile="$2" # salt.bin
    if [ 'x' = "x$_sfile" -o ! -f "$_sfile" ]
    then cat "$@" | openssl dgst "$algo" -binary | openssl enc -base64 -A
    else cat "$@" | openssl dgst "$algo" -binary |
                               cat - "$tmp_salt" | openssl enc -base64 -A
    fi
  }
  case "$scheme" in
    ssha* | smd5* ) openssl_file2hash "$algo" "$_file" "$tmp_salt" ;;
    *             ) openssl_file2hash "$algo" "$_file"             ;;
  esac

  rm -f "$tmp_payload" "$tmp_salt"
  # -> Binary-friendry way
}

_openssl_slappasswd "$_scheme" "$_secret" "$_salt" "$_file" && {
  if [ ! "$__nonewline" ] ; then
     echo
  fi
}
