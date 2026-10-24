ATLAS RESULTS

Corpus, Rego policies and recorded results for 107 campaigns and 791 selected
pipelines across six policy classes.

Contents
  corpus/       10,896 Java files: baseline, training and held-out samples.
  rego/         Policies and matching drivers, grouped by campaign.
  results/      Campaign result JSON, archived_results.csv and time_logs.csv.

Indexes
  catalog.json, pipelines.csv:   Available pipelines.
  campaigns.csv                Campaign settings and result locations.
  corpus_index.csv             Sample splits and Safe/Violating labels.
  campaign_inputs.csv          Baseline/training files used by each campaign.
  rego_index.csv               Pipeline-to-policy and driver mappings.

To analyze a sample, open the Windows sample runner,
select a pipeline for the matching policy class, and upload the Java file.
CWE321 baseline example: corpus/CWE321/baseline/MixedP1P2P3.java.

The sample runner is only available for Windows systems.

