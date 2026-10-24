ATLAS RESULTS

Corpus, Rego policies and recorded results for 107 campaigns and 791 selected
pipelines across six policy classes.

Policies: CWE22, CWE321, CWE284, CWE643, CWE89, CWE117

Sample repos referenced in paper: https://samate.nist.gov/SARD/test-suites/109 & https://github.com/UnitTestBot/juliet-java-test-suite/tree/master

Contents
  corpus/       10,896 Java files: 10,800 evaluation samples (Safe/Violating) and 96 baseline/training files.
  rego/         Policies and matching drivers, grouped by campaign.
  results/      Campaign result JSON, archived_results.csv and time_logs.csv.

Indexes
  pipelines.csv:                Available pipelines.
  campaigns.csv:                Campaign settings and result locations.
  corpus_index.csv:             Sample splits and Safe/Violating labels.
  campaign_inputs.csv:          Baseline/training files used by each campaign.
  rego_index.csv:               Pipeline-to-policy and driver mappings.

To analyze a Java code sample, open the Windows sample runner,
select a pipeline for the matching policy class, and upload the Java file.
CWE321 baseline example: corpus/CWE321/baseline/MixedP1P2P3.java.

The sample runner is only available for Windows systems.

