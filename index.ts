import { Command } from 'commander';
import fs from 'fs';
import figlet from 'figlet';
import axios from 'axios';
import { AdvisoryPayload, severityLevels } from './types';
import { simulateProgress } from './progress-bar';

type CommandOptions = {
    verbose?: boolean;
    severity?: keyof typeof severityLevels;
}

function bold(text: string | number){
    return `\x1b[1m${text}\x1b[0m`;
}

function colorizeSeverity(severity: string) {
    switch (severity.toLowerCase()) {
      case 'low':
        return `\x1b[33m${severity}\x1b[0m`; // Yellow
      case 'medium':
        return `\x1b[91m${severity}\x1b[0m`; // Orange/Red
      case 'high':
        return `\x1b[31m${severity}\x1b[0m`; // Red
      case 'critical':
        return `\x1b[35m${severity}\x1b[0m`; // Purple
      default:
        return severity; // No color for unknown severity
    }
  }

(async () => {
    const program = new Command();

    program
        .version('1.0.0')
        .description('A simple CLI tool')
        .option('-f, --file <filename>', 'Specify a file')
        .option('-v, --verbose', 'Enable verbose mode')
        .option('-s, --severity <severity>', 'Specify the severity. Possible values: low, medium, high, critical')
        .parse(process.argv);

    const options = program.opts<CommandOptions>();

    if (process.argv.includes('-h') || process.argv.includes('--help')) {
        program.outputHelp();
        process.exit(0);
      }else{
        let verbose = options.verbose ? true : false;
        let severity;
        if(options.severity){
            if(!Object.keys(severityLevels).includes(options.severity)){
                throw Error('Invalid severity value - Allowed values: low, medium, high, critical');
            }
            severity = options.severity;
        }
        await vulnerabilityCheck({
            verbose,
            severity
        });
      }
})();

async function vulnerabilityCheck(options:{
    severity?: keyof typeof severityLevels;
    verbose?: boolean;}) {

    console.log(figlet.textSync("Scanning..."));

    const currentDirectory = process.cwd();

    try{
        const packageJSONExists = fs.existsSync(`${currentDirectory}/package.json`);

        if(!packageJSONExists){
            throw Error('Package json is not found in the current directory');
        }

        const packageJSONData = fs.readFileSync(`${currentDirectory}/package.json`, 'utf8');

        let packageJSONParsedData;

        try{
            packageJSONParsedData = JSON.parse(packageJSONData);
        }catch(error){
            throw Error('Package json is not valid');
        }

        let dependencies = packageJSONParsedData.dependencies;

        if(!dependencies){
            throw Error('Missing dependencies in package json');
        }
        
        //array where each element is a string in the format of "dependency@version"
        const urlQueryParams = [];
        for(const packageName in dependencies){
            let packageVersion = dependencies[packageName];
            packageVersion = packageVersion.replace('^', '');
            packageVersion = packageVersion.replace('~', '');

            urlQueryParams.push(`${packageName}@${packageVersion}`);
        }

        const params:any = {
            ecosystem: 'npm',
            affects: urlQueryParams.join(',')
        }

        const response = await axios.get('https://api.github.com/advisories', { method: 'POST', 
            headers: {
                'Content-Type': 'application/vnd.github+json'
            },
            params
        });
        const data: AdvisoryPayload[] = await response.data;

        const groupedVulnerabilities: {
            [package_name: string]: {
                summaries: string[];
                vulnerable_versions_range: string[];
                severity: keyof typeof severityLevels;
                score: number;
                descriptions?: string[];
            }
        } = {};

        for (const item of data) {
            for (const vulnerability of item.vulnerabilities) {
                if (groupedVulnerabilities[vulnerability.package.name]) {
                    groupedVulnerabilities[vulnerability.package.name].summaries.push(`${item.summary} Ref. URL: ${item.html_url}`)

                    const versionAlreadyExists = groupedVulnerabilities[vulnerability.package.name].vulnerable_versions_range.find((version: string) => version === vulnerability.vulnerable_version_range);
                    if(!versionAlreadyExists){
                        groupedVulnerabilities[vulnerability.package.name].vulnerable_versions_range.push(vulnerability.vulnerable_version_range)
                    }

                    if(severityLevels[item.severity] > severityLevels[groupedVulnerabilities[vulnerability.package.name].severity]){
                        groupedVulnerabilities[vulnerability.package.name].severity = item.severity;
                        groupedVulnerabilities[vulnerability.package.name].score = item.cvss.score;
                    }

                    if(options.verbose){
                        groupedVulnerabilities[vulnerability.package.name].descriptions?.push(item.description);
                    }

                } else {
                    if(options.severity){
                        if(severityLevels[item.severity] < severityLevels[options.severity]){
                            continue;
                        }
                    }
                    groupedVulnerabilities[vulnerability.package.name] = {
                        summaries: [
                            `${item.summary} -> Ref. URL: ${item.html_url}`
                        ],
                        vulnerable_versions_range: [vulnerability.vulnerable_version_range],
                        severity: item.severity,
                        score: item.cvss.score
                    }

                    if(options.verbose){
                        groupedVulnerabilities[vulnerability.package.name].descriptions = [item.description];
                    }
                }
            }
        }


        await simulateProgress(3);

        console.log('Vulnerability scan done')

        console.log('Generating report...')

        let index = 0;
        const length = Object.keys(groupedVulnerabilities).length;

        console.log(bold("REPORT"))
        console.log("___________________________________________________\n")

        for(const package_name in groupedVulnerabilities){
            const vulnerability = groupedVulnerabilities[package_name];
            console.log(`Vulnerable package: ${bold(package_name)} - Severity: ${bold(colorizeSeverity(vulnerability.severity))} - Score: ${bold(vulnerability.score)}`);
            console.log(`Affected versions: ${bold(vulnerability.vulnerable_versions_range.join(', '))}`)
            
            console.log(`${bold('Summary')}`)
            console.log(vulnerability.summaries.join('\n'));

            if(options.verbose){
                console.log(`${bold('Description')}`)
                console.log(vulnerability.descriptions?.join('\n'));
            }

            index++;
            if(index < length){
                console.log('----------------------------------')
            }
        }

        console.log("___________________________________________________")
        console.log("REPORT DONE")

    } catch (error){
        if(error instanceof Error){
            console.log(error.message);
        }
        return;
    }
}