#!/usr/bin/perl
use strict;
use warnings;
use Getopt::Long;
use File::Basename;

# --- Configuration & Globals ---
my $dry_run    = 0;
my $revert     = 0;
my $clean      = 0;
my $fuzz_range = 25;

GetOptions(
    "dry-run" => \$dry_run,
    "fuzz=i"  => \$fuzz_range,
    "revert"  => \$revert,
    "clean"   => \$clean
);

my $patch_file = $ARGV or die "Usage: $0 [--dry-run|--revert|--clean] <patch_file>\n";

# --- 1. SHA1 Identification ---
my $ck_out = `/usr/bin/cksum -a sha1 "$patch_file"`;
chomp($ck_out);
my ($patch_hash) = $ck_out =~ /=\s+([a-f0-9]+)/i;
die "Could not determine SHA1 hash of patch file.\n" unless $patch_hash;

my $state_dir = -w "/cache" ? "/cache" : ($ENV{TMPDIR} && -d $ENV{TMPDIR} && -w _ ? $ENV{TMPDIR} : ".");
my $state_file = "$state_dir/.patch_state_$patch_hash";

# --- 2. Patch Parsing ---
open(my $ph, '<', $patch_file) or die "Cannot open patch file: $!\n";

my %patches;
my $cur_file;
my $is_git_patch = 0;

while (my $line = <$ph>) {
    if ($line =~ /^diff --git\s+a\/.+?\s+b\/.+$/) {
        $is_git_patch = 1;
        next;
    }
    elsif ($is_git_patch && $line =~ /^deleted file mode/) {
        $patches{$cur_file}{deleted} = 1 if $cur_file;
        next;
    }
    elsif ($line =~ /^--- (?:a\/)?(.+)$/) {
        my $path = $1; $path =~ s/\s+$//;
        $cur_file = $path unless $path eq '/dev/null';
    }
    elsif ($line =~ /^\+\+\+ (?:b\/)?(.+)$/) {
        my $path = $1; $path =~ s/\s+$//;
        if ($path eq '/dev/null') {
            $patches{$cur_file}{deleted} = 1;
        } else {
            $cur_file = $path;
            $patches{$cur_file}{deleted} = 0;
        }
    }
    elsif ($cur_file && $line =~ /^@@ -(\d+),?\d*? \+(\d+),?\d*? @@/) {
        push @{$patches{$cur_file}{hunks}}, { old_start => $1, lines => [] };
    }
    elsif ($cur_file && @{$patches{$cur_file}{hunks}}) {
        push @{$patches{$cur_file}{hunks}[-1]{lines}}, $line if $line =~ /^[ \+\-\\]/;
    }
}
close($ph);

# --- 3. Clean and Revert Modes ---
if ($clean || $revert) {
    print(($clean ? "Removing backups for $patch_hash...\n" : "Reverting files for $patch_hash...\n"));
    foreach my $file (keys %patches) {
        my $backup = "$file.orig";
        if ($clean && -e $backup) {
            unlink($backup);
            print "  Deleted: $backup\n";
        }
        elsif ($revert && -e $backup) {
            my (undef, undef, $mode, undef, $uid, $gid, undef, undef, $atime, $mtime) = stat($backup);
            rename($backup, $file);
            chown($uid, $gid, $file); chmod($mode & 07777, $file); utime($atime, $mtime, $file);
            print "  Restored: $file\n";
        }
    }
    unlink($state_file) if -e $state_file;
    exit 0;
}

# --- 4. Hunk Matching Engine ---
sub find_hunk_index {
    my ($file_content, $hunk_lines, $original_line_idx) = @_;
    my @search_lines = grep { /^[ -]/ } @$hunk_lines;

    return $original_line_idx if check_match($file_content, \@search_lines, $original_line_idx);

    for (my $offset = 1; $offset <= $fuzz_range; $offset++) {
        my $before = $original_line_idx - $offset;
        my $after  = $original_line_idx + $offset;
        return $before if check_match($file_content, \@search_lines, $before);
        return $after  if check_match($file_content, \@search_lines, $after);
    }
    return undef;
}

sub check_match {
    my ($content, $search, $idx) = @_;
    return 0 if $idx < 0 || ($idx + scalar @$search) > scalar @$content;

    for (my $i = 0; $i < scalar @$search; $i++) {
        # Normalized comparison: strip all CR/LF
        my $file_line = $content->[$idx + $i]; $file_line =~ s/[\r\n]+$//;
        my $hunk_line = substr($search->[$i], 1); $hunk_line =~ s/[\r\n]+$//;

        return 0 if $file_line ne $hunk_line;
    }
    return 1;
}

# --- 5. Dry Run Phase ---
if ($dry_run) {
    open(my $sf, '>', $state_file) or die "Cannot create state file: $!\n";
    print $sf "CKSUM:$ck_out\n";
    foreach my $file (sort keys %patches) {
        if ($patches{$file}{deleted}) { print "DELETE: $file\n"; next; }
        if (-f $file) {
            my (undef, undef, undef, undef, undef, undef, undef, $size, undef, $mtime) = stat($file);
            open(my $fh, '<', $file); my @content = <$fh>; close($fh);
            my (@offsets, $failed_hunk) = ((), 0);
            foreach my $hunk (@{$patches{$file}{hunks}}) {
                my $idx = find_hunk_index(\@content, $hunk->{lines}, $hunk->{old_start} - 1);
                if (defined $idx) { push @offsets, ($idx - ($hunk->{old_start} - 1)); }
                else { $failed_hunk = 1; }
            }
            print $sf "$file|$mtime|$size|" . join(",", @offsets) . "\n" unless $failed_hunk;
            print(($failed_hunk ? "FAIL:   " : "READY:  ") . "$file\n");
        } elsif (!-e $file) { print "CREATE: $file\n"; }
    }
    close($sf); exit 0;
}

# --- 6. Patch Execution Phase ---
my %stabilized_offsets;
if (-e $state_file) {
    open(my $sf, '<', $state_file); <$sf>;
    while (my $line = <$sf>) {
        chomp($line); my ($file, $mtime, $size, $offs) = split(/\|/, $line);
        @{$stabilized_offsets{$file}} = split(",", $offs);
    }
    close($sf);
}

my @backup_list;
eval {
    foreach my $file (keys %patches) {
        if ($patches{$file}{deleted}) { unlink($file) if -e $file; next; }

        my $dir = dirname($file);
        if (!-d $dir) {
            my $acc = "";
            foreach my $part (split(/\//, $dir)) {
                next if $part eq ""; $acc .= "/$part";
                mkdir($acc, 0755) if !-d $acc;
            }
        }

        my $backup = "$file.orig";
        if (-e $file && !-e $backup) {
            my (undef, undef, $mode, undef, $uid, $gid, undef, undef, $atime, $mtime) = stat($file);
            rename($file, $backup);

            # Binary copy to preserve original state in backup
            open(my $in, '<', $backup); open(my $out, '>', $file); binmode($in); binmode($out);
            print $out $_ while <$in>; close($in); close($out);

            chown($uid, $gid, $file); chmod($mode & 07777, $file); utime($atime, $mtime, $file);
            push @backup_list, $file;
        }

        my @content = (-e $file) ? do { open(my $fh, '<', $file); <$fh> } : ();
        my @hunks = @{$patches{$file}{hunks} // []};
        my @offsets = @{$stabilized_offsets{$file} // []};

        for (my $i = $#hunks; $i >= 0; $i--) {
            my $hunk = $hunks[$i];
            my $target_idx = (@content)
                ? ((defined $offsets[$i] ? ($hunk->{old_start}-1+$offsets[$i]) : find_hunk_index(\@content, $hunk->{lines}, $hunk->{old_start}-1)))
                : 0;

            die "Hunk matching failed for $file\n" unless defined $target_idx;

            my (@new_lines, $lines_to_remove) = ((), 0);
            foreach my $line (@{$hunk->{lines}}) {
                my $indicator = substr($line, 0, 1);
                my $text      = substr($line, 1);

                # Strip all incoming line endings from patch
                $text =~ s/[\r\n]+$//;

                if ($indicator eq ' ' || $indicator eq '-') {
                    $lines_to_remove++ if $indicator eq '-';
                    # Force normalization to \n
                    push @new_lines, $text . "\n" if $indicator eq ' ';
                } elsif ($indicator eq '+') {
                    push @new_lines, $text . "\n";
                }
            }
            splice(@content, $target_idx, $lines_to_remove, @new_lines);
        }

        # Ensure all existing lines in @content also use \n before writing
        open(my $out, '>', $file);
        foreach my $line (@content) {
            $line =~ s/[\r\n]+$//;
            print $out $line . "\n";
        }
        close($out);
    }
};

if ($@) {
    warn "Error: $@. Rolling back changes...\n";
    foreach my $f (@backup_list) { rename("$f.orig", $f) if -e "$f.orig"; }
    exit 1;
}

unlink($state_file) if -e $state_file;
print "Patching completed successfully (Normalized to LF).\n";

