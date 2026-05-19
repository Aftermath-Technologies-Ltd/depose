// Quick debug script
import { parse } from '../packages/core/src/reconstruct/yaml-parser.ts';

const yaml = `version: 1
rules:
  - id: terraform-destroy
    matcher:
      argvHead: ["terraform", "destroy"]
    severity: critical
`;

const result = parse(yaml);
console.log('Result:', JSON.stringify(result, null, 2));