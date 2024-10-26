## Running the Analysis

This `run.js` script is designed to analyze specified JavaScript vulnerabilities across multiple levels of dependencies. To run the script, you can use the following command in your terminal:

```bash
node run.js --levels <number_of_levels> -s <start_analysis_id> -e <end_analysis_id> --vulns <vuln_id_1> <vuln_id_2> ...
```

- `--levels` or `-l`:  
  Specifies the number of levels to analyze (e.g., 5).

- `--start` or `-s`:  
  The analysis ID to start with (default is 1).

- `--end` or `-e`:  
  The analysis ID to end with (by default it will analyze until the last analysis ID).

- `--vulns` or `-v`:  
  A list of vulnerabilities to analyze (use Snyk IDs)

 - `--threads` or `-t`:  
  Number of concurrent threads to run (default = number of CPU cores)


For example:

```bash
node run.js --levels 5 -s 300 -e 400 --vulns SNYK-JS-LODASH-73638 SNYK-JS-MINIMIST-559764 SNYK-JS-KINDOF-537849 SNYK-JS-MINIMATCH-10105 SNYK-JS-QS-10407 SNYK-JS-HOEK-12061 SNYK-JS-DEBUG-10762 SNYK-JS-YARGSPARSER-560381
```