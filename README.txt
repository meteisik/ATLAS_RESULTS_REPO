ATLAS WEBSITE DATA

Contents

corpus/                 Java baseline, training and held-out source files.
rego/                   Recorded policy and driver files, grouped by policy class and campaign.
results/campaigns/      Original per-file evaluation JSON for each campaign.
results/archived_results.csv  The website's recorded per-pipeline held-out metrics.
results/time_logs.csv   The website's recorded invocation timings and exit codes.
catalog.json and pipelines.csv  The website's pipeline inventory.
campaigns.csv           Campaign settings and result-file locations.
corpus_index.csv        Source-file split and Safe/Violating labels.
campaign_inputs.csv     Archived baseline/training membership for each campaign.
rego_index.csv          Website pipeline IDs mapped to policy and driver files.

Coverage

107 campaigns, 791 selected pipelines, six policy classes.
10896 Java files: six baseline files, 90 training files and 10,800 held-out files.
The held-out set contains 900 Safe and 900 Violating files per policy class.
The training directory is the available common source pool; campaign_inputs.csv
records which baseline and training files each archived campaign actually used.
The main and server-campaign source snapshots contain identical Java files.

The CWE321 baseline is corpus/CWE321/baseline/MixedP1P2P3.java.
Select a pipeline for the matching policy class when uploading a corpus file.

Measurements

Results and timings are saved measurements, not new executions. Source Java,
Rego, raw result JSON and website measurement CSV files are copied byte-for-byte.
Original labels, errors, weak-release flags, failed invocations and timing values
are retained. Generator names identify the recorded experimental configuration.
Rego driver files preserve their recorded analyzer interface; corpus, checkers
and measurements are provided here as data for the existing hosted runner.

Some raw campaign result archives contain pipeline names beyond the website's
selected roster. The existing archived_names_match flags are preserved. Use
pipelines.csv and rego_index.csv to identify the selected website pipelines.
The archived skipped-campaign note is retained in catalog.json.

All index paths are relative to this directory. No deployment or login is needed
to read these files.
