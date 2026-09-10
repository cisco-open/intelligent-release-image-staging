#!/usr/bin/env perl
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# Internal transport for xr-run.sh. Its enclosing watchdog bounds every read,
# including the wait for SSH EOF after logout. Keep command text off argv.
use strict;
use warnings;
use Errno qw(EINTR);
use IPC::Open3;
use IO::Handle;

my @commands = <STDIN>;
my ($input, $output);
my $pid = eval { open3($input, $output, '>&STDERR', @ARGV) };
if (!$pid) {
    print STDERR "xr-run.sh: cannot launch SSH dialogue\n";
    exit 1;
}
$input->autoflush(1);
STDOUT->autoflush(1);
$SIG{PIPE} = 'IGNORE';

my ($tail, $prefix) = ('', undef);
my $sent = 0;
my $write_failed = 0;
my $read_failed = 0;
while (1) {
    my $count = sysread($output, my $chunk, 8192);
    if (!defined $count) {
        next if $! == EINTR;
        print STDERR "xr-run.sh: cannot read SSH dialogue\n";
        $read_failed = 1;
        last;
    }
    last if !$count;
    print STDOUT $chunk;

    # Preserve output bytes for the caller's sanitizer. Inspect only the last
    # line, with CR removed just as xr-run.sh's output filter removes it.
    $chunk =~ s/\r//g;
    $tail .= $chunk;
    $tail =~ s/.*\n//s;
    # A truncated long line must never become a prompt after trimming.
    $tail = substr($tail, 0, 513);
    next if length($tail) > 512;
    if (!defined $prefix) {
        if ($tail =~ m{\A(RP/[A-Za-z0-9_./-]+:[A-Za-z0-9_.-]+)\#[ \t]*\z}) {
            $prefix = $1;
        } else {
            next;
        }
    }
    # Command echoes, another router's prompt, and incomplete config prompts
    # cannot release input. Config submodes retain the authenticated prefix.
    next unless $tail =~ /\A\Q$prefix\E(?:\((?:admin-)?config(?:-[A-Za-z0-9_-]+)*\)|\(admin\))?\#[ \t]*\z/;
    next if $sent == @commands || $write_failed;
    $tail = '';
    if (!print {$input} $commands[$sent]) {
        $write_failed = 1;
        close $input;
        next;
    }
    $sent++;
    # The final command is xr-run.sh's exit. Do not offer EOF to a run child
    # while its output/prompt is still pending; that child may consume input.
    close $input if $sent == @commands;
}
close $output;
close $input if $sent < @commands && !$write_failed;
my $waited;
do { $waited = waitpid($pid, 0) } while $waited == -1 && $! == EINTR;
my $status = $?;
my $rc;
if ($waited == -1) {
    print STDERR "xr-run.sh: cannot reap SSH dialogue\n";
    $rc = 1;
} else {
    $rc = ($status & 127) ? 128 + ($status & 127) : $status >> 8;
}
if ($sent < @commands || $write_failed) {
    print STDERR "xr-run.sh: SSH closed before all commands were delivered\n";
    $rc ||= 1;
}
$rc ||= 1 if $read_failed;
exit $rc;
