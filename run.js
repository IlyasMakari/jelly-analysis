require('log-timestamp');
const fs = require('fs');
const execSync = require('child_process').execSync;
const spawnSync = require('child_process').spawnSync;
const spawn = require('child_process').spawn;
var ls = require('npm-remote-ls').ls;
const _ = require("lodash");
const yargs = require('yargs');
const os = require('os');
const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');
const semver = require('semver');

const JELLY_TIMEOUT_SECONDS = 5 * 60; // 5 minutes
const INSTALL_TIMEOUT_SECONDS = 5 * 60; // 5 minutes

function executeCommand(command, args, options = {}) {
    return new Promise((resolve, reject) => {
        const process = spawn(command, args, options);

        let output = '';
        process.stdout.on('data', (data) => (output += data.toString()));
        process.stderr.on('data', (data) => (output += data.toString()));

        let timeout = null;
        if (options.timeout) {
            timeout = setTimeout(() => {
                process.kill('SIGKILL');
                reject(new Error(`${command} ${args} TIMEOUT`));
            }, options.timeout);
        }

        process.on('exit', (code) => {
            if (timeout) clearTimeout(timeout);
            if (code === 0) resolve(output);
            else reject(new Error(`${command} ${args} exited with code ${code} \n \n ${output}`));
        });
    });
}

async function runJelly(analysisId, vulnId, packageName, includePackages, outputFolder) {
    // console.log(`(${analysisId}) Running Jelly on the packages: ${includePackages.join(" ")}`)
    const jellyArgs = [
        '-c',
        `export NODE_OPTIONS="--max-old-space-size=65536" && npm run start --max-old-space-size=65536 -- \
            -j ../${outputFolder}/${analysisId}.json \
            -m ../${outputFolder}/${analysisId}.html \
            -b ../code/${analysisId} -v ../vulnerability_definitions/${vulnId}.json \
            --api-exported ../code/${analysisId}/node_modules/${packageName} \
            --timeout 300 --external-matches --proto ${includePackages.length > 0 ? "--include-packages " + includePackages.join(" ") : ""}`,
    ];
    return await executeCommand('sh', jellyArgs, { cwd: "jelly-master", timeout: JELLY_TIMEOUT_SECONDS * 1000 });
}

async function installPackage(packageName, version, analysisId) {
    // console.log(`(${analysisId}) Installing ${packageName}@${version}`);
    return await executeCommand('npm', ['i', `${packageName}@${version}`], {
        cwd: `code/${analysisId}`,
        timeout: INSTALL_TIMEOUT_SECONDS * 1000,
    });
}

function getDependencyTree(packageName, version) {
    return new Promise((resolve, reject) => {
        ls(packageName, version, (tree) => {
            resolve(tree);
        });
    });
}

function findPaths(tree, targetKey, currentPath = []) {
    let paths = [];
    for (let key in tree) {
        let keyVersion = key.split('@')[1];
        if ((targetKey.version_range && key.startsWith(targetKey.package + "@") && semver.satisfies(keyVersion, targetKey.version_range))
            || (!targetKey.version_range && key.startsWith(targetKey.package + "@"))) {
            paths.push([...currentPath, key]);
        } else if (typeof tree[key] === 'object' && Object.keys(tree[key]).length > 0) {
            let subPaths = findPaths(tree[key], targetKey, [...currentPath, key]);
            paths = paths.concat(subPaths);
        }
    }
    return paths;
}

function rangeEventsToSemverRange(events) {
    let ranges = [];

    for (const event of events) {
        if (event.introduced && event.introduced !== "0") {
            ranges.push(`>=${event.introduced}`);
        }
        if (event.fixed) {
            ranges.push(`<${event.fixed}`);
        }
    }

    return ranges.join(" "); // Combine ranges into a valid semver range string
}

function getVulnerableRange(osvData) {

    if (!osvData.affected || !Array.isArray(osvData.affected)) {
        throw new Error('Invalid OSV JSON format: Missing "affected" field.');
    }

    let vulnerableRanges = [];

    for (const affected of osvData.affected) {
        if (affected.ranges) {
            for (const range of affected.ranges) {
                if (range.type === "SEMVER") {
                    // Convert range events to semver-compatible range
                    const semverRange = rangeEventsToSemverRange(range.events);
                    if (semverRange) {
                        vulnerableRanges.push(semverRange);
                    }
                } else if (range.type === "ECOSYSTEM") {
                    const ecosystemRange = rangeEventsToSemverRange(range.events);
                    if (ecosystemRange) {
                        vulnerableRanges.push(ecosystemRange);
                    }
                } else if (range.type === "GIT") {
                    console.warn("Skipping GIT range; not supported for semver ranges.");
                } else {
                    console.warn(`Unsupported range type: ${range.type}`);
                }
            }
        }
    }

    // Combine all semver ranges into one
    if (vulnerableRanges.length > 0) {
        return vulnerableRanges.join(" || "); // Use OR (||) to combine ranges
    }

    return null; // No vulnerable range found
}

async function runAnalysis(analysis) {

    console.log(`(${analysis.analysis_id}) Starting the level ${analysis.level} analysis of ${analysis.vuln_id}: ${analysis.package} -> ${analysis.dependency}`);

    let install_output = "";
    let jelly_output = "";

    // Track start time in ms
    const startTime = Date.now();

    // Track the project size in kilobytes
    analysis.project_size = -1;

    try {
        // Create new NPM environment to run the tests on
        fs.rmSync(`code/${analysis.analysis_id}`, { recursive: true, force: true });
        fs.mkdirSync(`code/${analysis.analysis_id}`, { recursive: true });
        const packageJsonString = `{"name": "code", "version": "1.0.0", "description": "", "main": "index.js", "scripts": {"test": "echo \\"Error: no test specified\\" && exit 1"}, "author": "", "license": "ISC"}`;
        fs.writeFileSync(`code/${analysis.analysis_id}/package.json`, packageJsonString);

        // Install the dependency to test
        install_output = await installPackage(analysis.package, analysis.version, analysis.analysis_id);

        // Find the directory size of /code/${analysisId} in kilobytes
        analysis.project_size = parseInt(execSync(`du -sk code/${analysis.analysis_id} | cut -f1`, { encoding: 'utf8' }).trim());

        // Get the dependency tree and save as json
        const tree = await getDependencyTree(analysis.package, analysis.version);
        fs.writeFileSync(`${analysis.outputFolder}/${analysis.analysis_id}-deptree.json`, JSON.stringify(tree));

        // Get the vulnerable range from the OSV data
        const osvData = JSON.parse(fs.readFileSync(`vulnerability_definitions/${analysis.vuln_id}.json`, "utf-8"))[0]['osv'];
        const range = getVulnerableRange(osvData);

        // Find the packages between the dependency and the vulnerability
        const targetKeyRange = { "package": analysis.dependency, "version_range": range };
        const targetKeySpecific = { "package": analysis.dependency, "version_range": analysis.dep_version };
        const targetKeyName = { "package": analysis.dependency };
        let rangePaths = findPaths(tree, targetKeyRange);
        let rangePathsFiltered = rangePaths.filter(path => path.length == analysis.level + 1);
        let specificPaths = findPaths(tree, targetKeySpecific);
        let specificPathsFiltered = specificPaths.filter(path => path.length == analysis.level + 1);
        let namePaths = findPaths(tree, targetKeyName);
        let namePathsFiltered = namePaths.filter(path => path.length == analysis.level + 1);

        console.log(`(${analysis.analysis_id}) Vulnerable range: ${range} | Vulnerable range paths: ${rangePaths.length} (${rangePathsFiltered.length} filtered) | Specific paths: ${specificPaths.length} (${specificPathsFiltered.length} filtered) | Name paths: ${namePaths.length} (${namePathsFiltered.length} filtered)`);

        // Only analyze the paths that are of the correct level
        const include_packages = [...new Set(namePathsFiltered.flat().map(e => e.substr(e, e.lastIndexOf('@'))))];

        // Make a file to store the 3 types of paths
        fs.writeFileSync(`${analysis.outputFolder}/${analysis.analysis_id}-paths.json`, JSON.stringify({
            rangePaths: rangePaths,
            specificPaths: specificPaths,
            namePaths: namePaths,
            rangePathsFiltered: rangePathsFiltered,
            specificPathsFiltered: specificPathsFiltered,
            namePathsFiltered: namePathsFiltered,
        }));

        // If namePathsFiltered is empty, throw an error
        if (namePathsFiltered.length === 0) {
            console.error(`(${analysis.analysis_id}) No paths of level ${analysis.level} found from ${analysis.package} to ${analysis.dependency}`);
            throw new Error(`(${analysis.analysis_id}) No paths of level ${analysis.level} found from ${analysis.package} to ${analysis.dependency}`);
        }

        // Run Jelly
        jelly_output = await runJelly(analysis.analysis_id, analysis.vuln_id, analysis.package, include_packages, analysis.outputFolder);
        fs.writeFileSync(`${analysis.outputFolder}/${analysis.analysis_id}.txt`, install_output + "\n" + jelly_output);

        // Track end time in ms
        const endTime = Date.now();
        analysis.execitionTime = endTime - startTime;

        // Return the analysis with success
        return { task: analysis, success: true };

    }
    catch(error) {
        // Save error to file
        fs.writeFileSync(`${analysis.outputFolder}/${analysis.analysis_id}`, `${error.name}: ${error.message}`);

        // Track end time in ms
        const endTime = Date.now();
        analysis.execitionTime = endTime - startTime;

        return { task: analysis, success: false, error: error };
    }
    finally {
        // Delete the NPM environment when finished
        fs.rmSync(`code/${analysis.analysis_id}`, { recursive: true, force: true });
    }   

}

function createSchedule(levels, vulnerabilities, sampleSizes) {
    let tasks = []
    let remainingItems = {};
    let analysis_id = 1;
    levels.forEach(i => {
        vulnerabilities.forEach(vuln => {

            // Read the full dataset for this vulnerability and level combination
            const dataset = JSON.parse(fs.readFileSync(`selections_new/dependencies/${vuln}-level-${i}.json`, "utf8"));

            // Get the sample size for this combination
            const sampleKey = `('${vuln}', ${i - 1})`;
            const sampleSize = sampleSizes[sampleKey]?.sample_size || 100; // Default to 100 if not specified

            // Select the sample and the remaining items
            const sample = dataset.slice(0, sampleSize);
            const remaining = dataset.slice(sampleSize); // Spare items

            // Add tasks for the sample (no analysis_id yet)
            sample.forEach((selection) => {
                tasks.push({
                    vuln_id: selection.id,
                    dependency: selection.dependency,
                    package: selection.package,
                    version: selection.version,
                    dep_version: selection.dep_version,
                    level: i,
                    sampleKey: sampleKey,
                });
            });

            // Store the remaining items for this sampleKey
            remainingItems[sampleKey] = remaining;
        });
    });

    return { tasks, remainingItems };
}


async function main() {

    // CLI args
    const argv = yargs
        .option("levels", {
            alias: "l",
            type: "array",
            description: "List of levels to analyze (e.g., --levels 1 2 3)",
            coerce: (levels) => levels.map(Number),
            demandOption: true,
        })
        .option("vulns", { alias: "v", type: "array", description: "List of vulnerabilities", demandOption: true })
        .option("threads", { alias: "t", type: "number", description: "Number of concurrent threads", default: os.cpus().length })
        .help()
        .argv;

    // Logging
    console.log(`Starting analysis of levels: ${argv.levels}`);
    console.log(`Concurrent threads: ${argv.threads}`);
    console.log(`Analyzing vulnerabilities: ${argv.vulns}`);

    // Delete code from previous run
    execSync(`find . -maxdepth 1 -type d ! -name "." -exec rm -rf {} + || true`, { cwd: "code"}).toString();
    
    // Create output folder
    const now = new Date();
    const year = now.getFullYear();
    const month = String(now.getMonth() + 1).padStart(2, '0'); // Months are zero-based
    const day = String(now.getDate()).padStart(2, '0');
    const hours = String(now.getHours()).padStart(2, '0');
    const minutes = String(now.getMinutes()).padStart(2, '0');
    const outputFolder = `output/output-${year}-${month}-${day}-${hours}${minutes}`;
    fs.mkdirSync(`./${outputFolder}`, { recursive: true })

    // Load sample sizes
    const sampleSizes = JSON.parse(fs.readFileSync('selections_new/sample_sizes.json', 'utf8'));

    // Initialize analysis dict
    let analysisDict = [];
    fs.writeFileSync(`${outputFolder}/$dict.json`, JSON.stringify(analysisDict, null, 2));

    // Create schedule
    const { tasks, remainingItems } = createSchedule(argv.levels, argv.vulns, sampleSizes);

    // Initialize progress tracking
    let currentAnalysisId = 1; // Tracks the next analysis ID to assign
    
    // Start workers and manage tasks
    let runningThreads = 0;

    // Function to start a worker
    function startWorker(task) {
        runningThreads++;
        task.analysis_id = currentAnalysisId++;
        task.outputFolder = outputFolder;
        const worker = new Worker(__filename, { workerData: task });

        worker.on('message', (msg) => {
            console.log(`Analysis ${msg.task.analysis_id} finished - ${msg.success ? "SUCCESS" : "FAILED"}`);

            // Save the analysis to the dict
            let analysis = msg.task;
            analysis.success = msg.success;
            analysisDict.push(analysis);
            fs.writeFileSync(`${outputFolder}/$dict.json`, JSON.stringify(analysisDict, null, 2));

            // Log success progress
            let sampleKey = msg.task.sampleKey;
            let sampleSuccesses = analysisDict.filter(a => a.sampleKey === sampleKey && a.success).length;
            let sampleSize = sampleSizes[sampleKey]?.sample_size || 100; // Default to 100 if not specified
            console.log(`${sampleKey} - ${sampleSuccesses} results out of ${sampleSize} required samples (${(sampleSuccesses / sampleSize * 100).toFixed(2)}%)`);

            worker.terminate();
            runningThreads--;
            
            if (!msg.success && remainingItems[msg.task.sampleKey].length > 0) {
                // If failed, try another analysis if there are remaining items for this sampleKey
                let nextTask = remainingItems[msg.task.sampleKey].shift();

                let nextAnalysis = {
                    vuln_id: nextTask.id,
                    dependency: nextTask.dependency,
                    package: nextTask.package,
                    version: nextTask.version,
                    dep_version: nextTask.dep_version,
                    level: nextTask.order + 1,
                    sampleKey: msg.task.sampleKey,
                };

                startWorker(nextAnalysis);
            } else if (tasks.length > 0) {
                startWorker(tasks.shift());
            }

        });

    }

    // Start initial workers up to the number of threads
    while (runningThreads < argv.threads && tasks.length > 0) {
        startWorker(tasks.shift());
    }

}



// Multithreading
if (isMainThread) main();
else runAnalysis(workerData)
    .then((output) => {
        parentPort.postMessage({task: output.task, success: output.success});
    })
    .catch((err) => console.log(err));

