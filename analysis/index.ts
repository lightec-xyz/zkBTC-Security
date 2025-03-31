import { execSync } from "node:child_process";
import { inherits } from "node:util";

export default function main() {
    execSync("mkdir output")
    execSync("node dist/analysis/src/cp_compute.js 256480 > output/cp_compute_difficulty_change.out")
    execSync("node dist/analysis/src/cp_compute.js 100000 > output/cp_compute_1.out")
    execSync("node dist/analysis/src/cp_compute.js 200000 > output/cp_compute_2.out")
    execSync("node dist/analysis/src/cp_compute.js 300000 > output/cp_compute_3.out")
    execSync("node dist/analysis/src/cp_compute.js 400000 > output/cp_compute_4.out")
    execSync("node dist/analysis/src/cp_compute.js 500000 > output/cp_compute_5.out")
}

main()