require('log-timestamp');
const fs = require('fs');
const execSync = require('child_process').execSync;
const spawnSync = require('child_process').spawnSync;
const spawn = require('child_process').spawn;
var ls = require('npm-remote-ls').ls;
const _ = require("lodash");
const yargs = require('yargs');

// Output folder name
const now = new Date();
const year = now.getFullYear();
const month = String(now.getMonth() + 1).padStart(2, '0'); // Months are zero-based
const day = String(now.getDate()).padStart(2, '0');
const hours = String(now.getHours()).padStart(2, '0');
const minutes = String(now.getMinutes()).padStart(2, '0');
const outputString = `output/output-${year}-${month}-${day}-${hours}${minutes}`;

function runJelly(analysis_id, vuln_id, package, include_packages) {
    return new Promise((resolve, reject) => {
        // Define the maximum time (in milliseconds) for the Jelly process to run
        let jelly_timeout_seconds = 5 * 60; // Example: 5 minutes

        // Use spawn instead of execSync for more control over the process
        const jellyProcess = spawn('sh', ['-c', `
            export NODE_OPTIONS="--max-old-space-size=65536"
            npm run start --max-old-space-size=65536 -- \
            --approx \
            -j ../${outputString}/${analysis_id}.json \
            -m ../${outputString}/${analysis_id}.html \
            -b ../code \
            -v ../vulnerability_definitions/${vuln_id}.json \
            --api-exported \
            ../code/node_modules/${package} \
            --timeout 300 \
            --external-matches --proto \
            ${(include_packages.length > 0) ? "--include-packages " + include_packages.join(" ") : ""}
        `], { cwd: "jelly-0.10.0", maxBuffer: (10 * 1024 * 1024) });

        // Set the timeout to kill the Jelly process if it runs too long
        const timeout = setTimeout(() => {
            try {
                process.kill(jellyProcess.pid, 'SIGKILL');
                reject(new Error("JELLY TIMEOUT"));
            } catch (e) {
                console.log('Jelly process terminated before the timeout cutoff');
            }
        }, jelly_timeout_seconds * 1000);

        // Capture stdout and stderr for logging purposes
        let output = '';
        jellyProcess.stdout.on('data', (data) => {
            output += data.toString();
        });

        jellyProcess.stderr.on('data', (data) => {
            output += data.toString();
        });

        // Handle process exit
        jellyProcess.on('exit', (code) => {
            clearTimeout(timeout); // Clear the timeout if the process exits on its own
            if (code === 0) {
                // Write output to file
                fs.writeFileSync(`${outputString}/${analysis_id}.txt`, output);
                resolve();
            } else {
                reject(new Error(`Jelly process exited with code ${code}`));
            }
        });
    });
}


function findPaths(tree, targetKey, currentPath = []) {
    let paths = [];
    for (let key in tree) {
        if (key === targetKey) {
            paths.push([...currentPath, key]);
        } else if (typeof tree[key] === 'object' && Object.keys(tree[key]).length > 0) {
            let subPaths = findPaths(tree[key], targetKey, [...currentPath, key]);
            paths = paths.concat(subPaths);
        }
    }
    return paths;
}

function runAnalysis(analysis) {
	execSync("rm -rf ./* || true", { cwd: "code"}).toString();
    let packageJsonString = `{"name": "code", "version": "1.0.0", "description": "", "main": "index.js", "scripts": {"test": "echo \\"Error: no test specified\\" && exit 1"}, "author": "", "license": "ISC"}`;
    fs.writeFileSync('code/package.json', packageJsonString);
    console.log(`(${analysis.analysis_id}) Starting the level ${analysis.level} analysis of ${analysis.vuln_id}: ${analysis.package} -> ${analysis.dependency}`);
    
    
    // console.log(npm_i.stderr.toString('utf8'));

    // npm_i.stdout.on('data', (data) => {
    //     console.log("received data");
    //     console.log(data.toString())
    // })

    // npm_i.on('close', (code) => {
    //   console.log(`Process exited with code ${code}`)
    // })

    
    
    return new Promise(function(resolve, reject) {

        let install_timeout_seconds = 5 * 60; // 5 min install timeout
        // let install_timeout_seconds = 30;

        console.log(`Installing ${analysis.package}@${analysis.version}`)
        npm_i = spawn(`npm`, ["i", `${analysis.package}@${analysis.version}`], { cwd: "code", timeout: install_timeout_seconds * 1000});
    
        var timeout = setTimeout(() => {
          try {
            process.kill(npm_i.pid, 'SIGKILL');
            reject(new Error("NPM INSTALL TIMEOUT"));
          } catch (e) {
            console.log('Install terminated before the timeout cutoff');
          }
        }, install_timeout_seconds*1000);

        npm_i.on('exit', (code) => {
            console.log(`"npm i ${analysis.package}@${analysis.version}" command has finished: Process exited with code ${code}`);

            console.log(`Retrieving the npm tree for ${analysis.package}@${analysis.version}`);
            ls(analysis.package, analysis.version, function(tree) {
                try {
                    console.log(`Tree retrieved for ${analysis.package}@${analysis.version}`)
                    fs.writeFileSync(`${outputString}/${analysis.analysis_id}-deptree.json`, JSON.stringify(tree));
                    const targetKey = `${analysis.dependency}@${analysis.dep_version}`;
                    const paths = findPaths(tree, targetKey).filter(path => path.length == analysis.level + 1);
                    const include_packages = [...new Set(paths.flat().map(e => e.substr(e, e.lastIndexOf('@'))))];
                    console.log(`Running Jelly on the packages: ${include_packages.join(" ")}`)
                    runJelly(analysis.analysis_id, analysis.vuln_id, analysis.package, include_packages).then(function() {
                        console.log("success!");
                        resolve();
                    }, function(err) {
                        console.log("error");
                        console.log(err);
                        reject(err);
                    });
                } catch (error) {
                    reject(error);
                }
            });
        });

        
    });
}

function createSchedule(levels, vulnerabilities) {
    let tasks = []
    let analysis_id = 1;
    levels.forEach(i => {
        vulnerabilities.forEach(vuln => {
            JSON.parse(fs.readFileSync(`selections/${vuln}-level-${i}.json`, 'utf8')).forEach(selection => {
                tasks.push({
                    "analysis_id": analysis_id,
                    "vuln_id": selection.id,
                    "dependency": selection.dependency,
                    "package": selection.package,
                    "version": selection.version,
                    "dep_version": selection.dep_version,
                    "level": i
                });
                analysis_id++;
            });
        });
    });
    return tasks
}


(async () => {

    // CLI args
    const argv = yargs
        .option('start', {
            alias: "s",
            type: 'number',
            description: 'The analysis ID to start with',
            default: 1
        })
        .option('end', {
            alias: "e",
            type: 'number',
            description: 'The analysis ID to end with',
            default: false
        })
        .option('levels', {
            alias: "l",
            type: 'number',
            description: 'Number of levels to analyze',
            default: 1
        })
        .option('vulns', {
            alias: "v",
            type: 'array',
            description: 'List of vulnerabilities to analyze',
            demandOption: true
        })
        .help()
        .argv;

    console.log(`Analyzing vulnerabilities: ${argv.vulns}`)

    // Create output folder
    fs.mkdirSync(`./${outputString}`, { recursive: true })

    planned_analyses = await createSchedule(Array.from({ length: argv.levels }, (_, i) => i + 1), argv.vulns);
    fs.writeFileSync(`${outputString}/$dict.json`,  JSON.stringify(planned_analyses.map(a => _.omit(a, 'run')), null, 2));
    console.log(`Starting ${argv.levels}-level analysis from ${argv.start} to ${(argv.end || planned_analyses.length)}`)

    for(analysis of planned_analyses.slice(argv.start - 1, (argv.end || planned_analyses.length))) {
    
        try {
            await runAnalysis(analysis)
        } catch (e) {
            fs.writeFileSync(`${outputString}/${analysis.analysis_id}`, `${e.name}: ${e.message}`);
        }
        
    }

})()

