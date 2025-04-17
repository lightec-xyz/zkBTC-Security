import { execSync } from "node:child_process";
import { inherits } from "node:util";

export default function main() {
    execSync("node dist/src/timestamp_compute.js > output/ts_compute.out")
    execSync(`node dist/src/cp_compute_all "" 2016 "" > output/cp_compute_all.out`)
    execSync(`node dist/src/net_time_compute.js "" 11 "" > output/net_compute_11.out`)
    execSync(`node dist/src/net_time_compute.js "" 48 "" > output/net_compute_48.out`)
}

main()