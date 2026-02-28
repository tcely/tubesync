#!/usr/bin/perl
use strict;
use warnings;
use Getopt::Long;
use File::Basename;

# 0. Zero-dependency helpers
sub native_copy {
    my ($src, $dst) = @_;
    open(my $in,  '<', $src) or die "Read $src: $!";
    open(my $out, '>', $dst) or die "Write $dst: $!";
    binmode($in); binmode($out);
    print $out $_ while <$in>;
    close($in); close($out);
}

sub ensure_dir {
    my $path = shift;
    my $dir = dirname($path);
    if (!-d $dir) {
        my @parts = split(/\//, $dir);
        my $current = "";
        foreach my $part (@parts) {
            next if $part eq "";
            $current .= "/$part";
            if (!-d $current) { mkdir($current, 0755) or die "mkdir $current: $!\n"; }
        }
    }
}

my ($dry_run, $fuzz_range, $revert, $clean) = (0, 25, 0, 0);
GetOptions("dry-run"=>\$dry_run, "fuzz=i"=>\$fuzz_range, "revert"=>\$revert, "clean"=>\$clean);
my $patch_file = $ARGV or die "Usage: $0 [--dry-run|--revert|--clean] <patch_file>\n";

# 1. SHA1 Identification
my $ck_out = `/usr/bin/cksum -a sha1 "$patch_file"`;
chomp($ck_out);
my ($hash) = $ck_out =~ /=\s+([a-f0-9]+)/i;
die "No SHA1 hash found in cksum output\n" unless $hash;

my $state_dir = -w "/cache" ? "/cache" : ($ENV{TMPDIR} && -d $ENV{TMPDIR} && -w _ ? $ENV{TMPDIR} : ".");
my $state_file = "$state_dir/.patch_state_$hash";

# 2. Parse Patch (Strict Path Extraction)
open(my $ph, '<', $patch_file) or die "No patch: $!\n";
my %patches; my ($cur_f, $git_state) = (undef, 0);
while (<$ph>) {
    if (/^diff --git\s+a\/(.+?)\s+b\/(.+)$/) { $git_state = 1; next; }
    elsif ($git_state == 1 && /^deleted file mode/) { $patches{$cur_f}{deleted} = 1 if $cur_f; next; }
    elsif (/^\-\-\- (a\/)?(.+)$/) {
        my $f = $2; $f =~ s/\s+$//;
        $cur_f = $f unless $f eq '/dev/null';
    }
    elsif (/^\+\+\+ (b\/)?(.+)$/) {
        my $f = $2; $f =~ s/\s+$//;
        if ($f eq '/dev/null') { $patches{$cur_f}{deleted} = 1; }
        else { $cur_f = $f; $patches{$cur_f}{deleted} = 0; }
    }
    elsif ($cur_f && /^@@ -(\d+),?\d*? \+(\d+),?\d*? @@/) {
        push @{$patches{$cur_f}{hunks}}, { old_start => $1, lines => [] };
    }
    elsif ($cur_f && @{$patches{$cur_f}{hunks}}) {
        push @{$patches{$cur_f}{hunks}[-1]{lines}}, $_ if /^[ \+\-\\]/;
    }
}
close($ph);

# 3. Clean / Revert Logic
if ($clean || $revert) {
    print(($clean ? "Cleaning backups...\n" : "Reverting files...\n"));
    foreach my $f (keys %patches) {
        my $orig = "$f.orig";
        if ($clean && -e $orig) { unlink($orig); print "  Deleted: $orig\n"; }
        elsif ($revert && -e $orig) {
            my @st = stat($orig); rename($orig, $f);
            chown($st[4], $st[5], $f); chmod($st[2] & 07777, $f); utime($st[8], $st[9], $f);
            print "  Restored: $f\n";
        }
    }
    unlink($state_file) if -e $state_file;
    exit 0;
}

# 4. Matching Helpers
sub find_hunk {
    my ($content, $hunk_lines, $target_idx) = @_;
    my @search = grep { /^[ -]/ } @$hunk_lines;
    return $target_idx if _check_match($content, \@search, $target_idx);
    for (my $o = 1; $o <= $fuzz_range; $o++) {
        return $target_idx - $o if _check_match($content, \@search, $target_idx - $o);
        return $target_idx + $o if _check_match($content, \@search, $target_idx + $o);
    }
    return undef;
}
sub _check_match {
    my ($c, $s, $idx) = @_;
    return 0 if $idx < 0 || ($idx + scalar @$s) > scalar @$c;
    for (my $i = 0; $i < scalar @$s; $i++) { return 0 if $c->[$idx + $i] ne substr($s->[$i], 1); }
    return 1;
}

# 5. Dry Run
if ($dry_run) {
    open(my $sf, '>', $state_file) or die "No state file: $!\n";
    print $sf "CKSUM:$ck_out\n";
    foreach my $f (sort keys %patches) {
        if ($patches{$f}{deleted}) { print "DELETE: $f\n"; next; }
        if (-f $f) {
            my @st = stat($f); open(my $fh, '<', $f); my @content = <$fh>; close($fh);
            my (@offsets, $fail) = ((), 0);
            foreach my $h (@{$patches{$f}{hunks}}) {
                my $idx = find_hunk(\@content, $h->{lines}, $h->{old_start} - 1);
                if (defined $idx) { push @offsets, $idx - ($h->{old_start} - 1); } else { $fail = 1; }
            }
            # stat indices: 9=mtime, 7=size
            print $sf "$f|$st[9]|$st[7]|" . join(",", @offsets) . "\n" unless $fail;
            print(($fail ? "FAIL: " : "OK: ") . "$f\n");
        } elsif (!-e $f) { print "NEW: $f\n"; }
    }
    close($sf); exit 0;
}

# 6. Execution
my %stabilized_offsets;
if (-e $state_file) {
    open(my $sf, '<', $state_file); my $header = <$sf>;
    while (<$sf>) { chomp; my ($f, $m, $s, $o) = split(/\|/); @{$stabilized_offsets{$f}} = split(",", $o); }
    close($sf);
}

my @backups;
eval {
    foreach my $file (keys %patches) {
        if ($patches{$file}{deleted}) { unlink($file) if -e $file; next; }
        ensure_dir($file);
        my $orig = "$file.orig";
        if (-e $file && !-e $orig) {
            my @st = stat($file); rename($file, $orig); native_copy($orig, $file);
            chown($st[4], $st[5], $file); chmod($st[2] & 07777, $file); utime($st[8], $st[9], $file);
            push @backups, $file;
        }
        my @content = (-e $file) ? do { open(my $fh, '<', $file); <$fh> } : ();
        my @hunks = @{$patches{$file}{hunks} // []};
        my @offsets = @{$stabilized_offsets{$file} // []};
        for (my $i = $#hunks; $i >= 0; $i--) {
            my $h = $hunks[$i];
            my $idx = (@content) ? ((defined $offsets[$i]) ? ($h->{old_start}-1+$offsets[$i]) : find_hunk(\@content, $h->{lines}, $h->{old_start}-1)) : 0;
            die "Hunk match failed for $file\n" unless defined $idx;
            my (@new, $rem) = ((), 0);
            foreach my $l (@{$h->{lines}}) {
                my ($ind, $t) = (substr($l, 0, 1), substr($l, 1));
                if ($ind eq ' ' || $ind eq '-') { $rem++ if $ind eq '-'; push @new, $t if $ind eq ' '; }
                elsif ($ind eq '+') { push @new, $t; }
            }
            splice(@content, $idx, $rem, @new);
        }
        open(my $out, '>', $file); print $out join('', @content); close($out);
    }
};

if ($@) {
    warn "Error: $@. Rolling back...\n";
    foreach my $f (@backups) { rename("$f.orig", $f) if -e "$f.orig"; }
    exit 1;
}
unlink($state_file) if -e $state_file;
print "Successfully applied patches.\n";

