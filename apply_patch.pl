#!/usr/bin/perl
use strict;
use warnings;
use Getopt::Long;
use File::Basename;

# --- 0. Minimal Native Copy ---
sub native_copy {
    my ($source_path, $destination_path) = @_;
    open(my $in,  '<', $source_path)      or die "Could not read $source_path: $!";
    open(my $out, '>', $destination_path) or die "Could not write $destination_path: $!";
    binmode($in);
    binmode($out);
    print $out $_ while <$in>;
    close($in);
    close($out);
}

# --- 1. Consolidated Hashing Helpers (Purpose-Oriented) ---
sub _get_digest {
    my ($file_path, $algo) = @_;
    return "" unless -f $file_path;
    my $cksum_output = `/usr/bin/cksum -a $algo "$file_path"`;
    chomp($cksum_output);
    my ($fingerprint) = $cksum_output =~ /=\s+([a-f0-9]+)/i;
    return $fingerprint || "";
}

sub get_patch_id { return _get_digest(shift, "sha1"); }
sub get_file_fingerprint { return _get_digest(shift, "sha512"); }

# --- 2. Configuration & Globals ---
my ($dry_run, $revert, $clean, $fuzz_range) = (0, 0, 0, 25);
GetOptions(
    "dry-run" => \$dry_run,
    "fuzz=i"  => \$fuzz_range,
    "revert"  => \$revert,
    "clean"   => \$clean
);

my $patch_file = $ARGV or die "Usage: $0 [--dry-run|--revert|--clean] <patch_file>\n";
my $patch_hash = get_patch_id($patch_file);
die "Could not generate ID for patch file.\n" unless $patch_hash;

my $state_directory;
if (open(my $mount_fh, '<', '/proc/mounts')) {
    while (my $mount_line = <$mount_fh>) {
        if ($mount_line =~ /^\S+\s+\/cache\s+tmpfs\s+/) {
            $state_directory = "/cache" if -w "/cache";
            last;
        }
    }
    close($mount_fh);
}
$state_directory ||= ($ENV{TMPDIR} && -d $ENV{TMPDIR} && -w _) ? $ENV{TMPDIR} : ".";

my $state_file = "$state_directory/.patch_state_$patch_hash";
my $temp_suffix = substr($patch_hash, 0, 11);

# --- 3. Patch Parsing (The Snapshot) ---
open(my $patch_fh, '<', $patch_file) or die "Cannot open patch: $!\n";
my %patches;
my $current_file;
my $is_git_format = 0;

while (my $line = <$patch_fh>) {
    if ($line =~ /^diff --git\s+a\/.+?\s+b\/.+$/) { $is_git_format = 1; next; }
    elsif ($is_git_format && $line =~ /^deleted file mode/) { $patches{$current_file}{deleted} = 1 if $current_file; next; }
    elsif ($line =~ /^--- (?:a\/)?(.+)$/) {
        my $path = $1; $path =~ s/\s+$//;
        $current_file = $path unless $path eq '/dev/null';
    }
    elsif ($line =~ /^\+\+\+ (?:b\/)?(.+)$/) {
        my $path = $1; $path =~ s/\s+$//;
        if ($path eq '/dev/null') { $patches{$current_file}{deleted} = 1; }
        else { $current_file = $path; $patches{$current_file}{deleted} = 0; }
    }
    elsif ($current_file && $line =~ /^@@ -(\d+),?\d*? \+(\d+),?\d*? @@/) {
        push @{$patches{$current_file}{hunks}}, { old_start => $1, lines => [], no_eof_newline => 0 };
    }
    elsif ($current_file && @{$patches{$current_file}{hunks}}) {
        if ($line =~ /^\\ No newline at end of file/) { $patches{$current_file}{hunks}[-1]{no_eof_newline} = 1; }
        else { push @{$patches{$current_file}{hunks}[-1]{lines}}, $line if $line =~ /^[ \+\-\\]/; }
    }
}
close($patch_fh);

# --- 4. Clean and Revert ---
my %state_metadata;
if (-e $state_file) {
    open(my $sf_fh, '<', $state_file); <$sf_fh>;
    while (<$sf_fh>) {
        chomp;
        my ($filename, $mtime, $size, $offsets, $status, $source_hash) = split(/\|/);
        $state_metadata{$filename} = { status => $status, hash => $source_hash };
    }
    close($sf_fh);
}

if ($clean || $revert) {
    print(($clean ? "Cleaning backups...\n" : "Reverting to original state...\n"));
    foreach my $target (keys %patches) {
        my $backup = "$target.orig";
        if ($clean && -e $backup) { unlink($backup); }
        elsif ($revert && -e $backup) {
            if ($state_metadata{$target} && $state_metadata{$target}{status} eq "NEW") {
                unlink($target) if -e $target; unlink($backup);
                print "  Removed created file: $target\n";
            } else {
                rename($backup, $target); # Preserves original metadata
                print "  Restored: $target\n";
            }
        }
    }
    unlink($state_file) if -e $state_file; exit 0;
}

# --- 5. Hunk Matching Engine ---
sub find_hunk_index {
    my ($file_content, $hunk_lines, $start_pos) = @_;
    my @match_search = grep { /^[ -]/ } @$hunk_lines;
    return $start_pos if verify_context($file_content, \@match_search, $start_pos);
    for (my $offset = 1; $offset <= $fuzz_range; $offset++) {
        return ($start_pos - $offset) if verify_context($file_content, \@match_search, $start_pos - $offset);
        return ($start_pos + $offset) if verify_context($file_content, \@match_search, $start_pos + $offset);
    }
    return undef;
}

sub verify_context {
    my ($lines, $search, $idx) = @_;
    return 0 if $idx < 0 || ($idx + scalar @$search) > scalar @$lines;
    for (my $i = 0; $i < scalar @$search; $i++) {
        my $f_text = $lines->[$idx + $i]; $f_text =~ s/[\r\n]+$//;
        my $h_text = substr($search->[$i], 1); $h_text =~ s/[\r\n]+$//;
        return 0 if $f_text ne $h_text;
    }
    return 1;
}

# --- 6. Dry Run ---
if ($dry_run) {
    open(my $sf_out, '>', $state_file) or die "Cannot create state file: $!\n";
    print $sf_out "CKSUM:$patch_hash\n";
    foreach my $f (sort keys %patches) {
        if ($patches{$f}{deleted}) { print "DELETE: $f\n"; next; }
        if (-f $f) {
            my @stats = stat($f);
            my $file_hash = get_file_fingerprint($f);
            open(my $fh, '<', $f); my @content = <$fh>; close($fh);
            my (@offsets, $failed) = ((), 0);
            foreach my $h (@{$patches{$f}{hunks}}) {
                my $idx = find_hunk_index(\@content, $h->{lines}, $h->{old_start} - 1);
                if (defined $idx) { push @offsets, ($idx - ($h->{old_start} - 1)); } else { $failed = 1; }
            }
            print $sf_out "$f|$stats|$stats|" . join(",", @offsets) . "|EXISTING|$file_hash\n" unless $failed;
            print(($failed ? "FAIL:   " : "READY:  ") . "$f\n");
        } elsif (!-e $f) {
            print $sf_out "$f|0|0||NEW|\n"; print "CREATE: $f\n";
        }
    }
    close($sf_out); exit 0;
}

# --- 7. Execution ---
my %stabilized_data;
if (-e $state_file) {
    open(my $sf_in, '<', $state_file); <$sf_in>;
    while (<$sf_in>) {
        chomp; my ($f, $m, $s, $o, $st, $shash) = split(/\|/);
        @{$stabilized_data{$f}} = (split(",", $o), $st, $shash);
    }
    close($sf_in);
}

my @processed_files;
my @deferred_unlinks;

eval {
    foreach my $target (keys %patches) {
        my $temp_work_file = "${target}.tmp_${temp_suffix}"; unlink($temp_work_file) if -e $temp_work_file;
        my $backup_file = "$target.orig";
        my $expected_hash = defined $stabilized_data{$target} ? $stabilized_data{$target}[-1] : "";

        # Step A: Backup Sequence (Copy -> Rename Original -> Rename Copy)
        if (-e $target && !-e $backup_file) {
            my $current_disk_hash = get_file_fingerprint($target);
            die "State Conflict: $target drift detected!\n" if $expected_hash ne $current_disk_hash;

            native_copy($target, $temp_work_file);
            rename($target, $backup_file) or die "Renaming backup failed: $target\n";
            rename($temp_work_file, $target) or die "Activating working copy failed: $target\n";

            # Verify integrity of working copy
            my $work_hash = get_file_fingerprint($target);
            die "Integrity Check Failed: $target corruption!\n" if $expected_hash ne $work_hash;

            push @processed_files, $target;
            push @deferred_unlinks, $target if $patches{$target}{deleted};
        }
        elsif (!-e $target && !-e $backup_file) {
            open(my $marker_fh, '>', $backup_file); close($marker_fh);
            push @processed_files, $target;
        }

        next if $patches{$target}{deleted};

        # Step B: Application
        my $target_dir = dirname($target);
        if (!-d $target_dir) {
            my $path_acc = "";
            foreach my $seg (split(/\//, $target_dir)) { next if $seg eq ""; $path_acc .= "/$seg"; mkdir($path_acc, 0755) if !-d $path_acc; }
        }

        my @file_lines = (-e $target) ? do { open(my $fh, '<', $target); <$fh> } : ();
        my @hunks   = @{$patches{$target}{hunks} // []};
        my @offsets = defined $stabilized_data{$target} ? @{$stabilized_data{$target}}[0..$#{$stabilized_data{$target}}-2] : ();
        my $suppress_final_newline = 0;

        for (my $i = $#hunks; $i >= 0; $i--) {
            my $h = $hunks[$i];
            my $match_idx = (@file_lines) ? (defined $offsets[$i] ? ($h->{old_start}-1+$offsets[$i]) : find_hunk_index(\@file_lines, $h->{lines}, $h->{old_start}-1)) : 0;
            die "Match failed during apply: $target\n" unless defined $match_idx;
            $suppress_final_newline = 1 if $i == $#hunks && $h->{no_eof_newline};

            my (@transformed, $removed_count) = ((), 0);
            foreach my $line (@{$h->{lines}}) {
                my ($ind, $text) = (substr($line, 0, 1), substr($line, 1));
                $text =~ s/[\r\n]+$//;
                if ($ind eq ' ' || $ind eq '-') { $removed_count++ if $ind eq '-'; push @transformed, $text . "\n" if $ind eq ' '; }
                elsif ($ind eq '+') { push @transformed, $text . "\n"; }
            }
            splice(@file_lines, $match_idx, $removed_count, @transformed);
        }

        # Step C: Final Atomic Commit
        open(my $out_fh, '>', $temp_work_file) or die "Write temp failed: $target\n";
        for (my $i = 0; $i <= $#file_lines; $i++) {
            my $l = $file_lines[$i]; $l =~ s/[\r\n]+$//;
            print $out_fh ($i == $#file_lines && $suppress_final_newline) ? $l : $l . "\n";
        }
        close($out_fh); rename($temp_work_file, $target) or die "Commit failed: $target\n";
    }
    foreach my $f_to_del (@deferred_unlinks) { unlink($f_to_del) or warn "Unlink failed: $f_to_del: $!\n"; }
};

if ($@) {
    warn "Application Error: $@. Rolling back changes...\n";
    foreach my $f (@processed_files) {
        my $orig = "$f.orig";
        if (-e $orig) {
            my $status = defined $stabilized_data{$f} ? $stabilized_data{$f}[-2] : "EXISTING";
            if ($status eq "NEW") { unlink($f) if -e $f; unlink($orig); }
            else { rename($orig, $f); }
        }
    }
    exit 1;
}

unlink($state_file) if -e $state_file;
print "Success.\n";

