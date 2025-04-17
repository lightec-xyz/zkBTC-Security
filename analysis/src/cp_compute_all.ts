import { open } from "node:fs/promises";
import path from "node:path";
import { plot, Plot } from "nodeplotlib";
import { evaluate_timestamp_statistics } from "./timestamp_compute";

const range = (start:number,stop:number)=>{
    let r = Array(stop-start+1)
    for (let i = start; i <= stop; i++){
        r[i-start]=i
    }
    return r
}

export function parse_timestamp_from_blockhead(line: string): number{
    let timeHex = line.substring(136,144);
    //Reverse Endianess
    let timeHexRev = ""+timeHex.substring(6,8)+timeHex.substring(4,6)+timeHex.substring(2,4)+timeHex.substring(0,2);
    let timeStamp = parseInt(timeHexRev,16);
    return timeStamp;
}

const default_path = "data/headers.txt";

async function main(dataPath:string=default_path, blocknum=2016, do_plot=false){
    if(dataPath==""||dataPath=="default"||dataPath=="undefined")dataPath=default_path
    if(!blocknum){blocknum=2016}
    let timestamps:number[] = []
    const file = await open(dataPath);
    let i=0
    for await (const line of file.readLines()){
        timestamps[i]=parse_timestamp_from_blockhead(line);
        i++;
    }
    let successes:number[] = Array(2017).fill(0);
    let allowance = 0;
    let minimum_accept_depth;
    let minimum_accept_depths:number[] = Array(2017).fill(0);
    let consecutive_accept:boolean;
    let deltas:number[] = Array(i).fill(0)
    let not_accepted_txns = Array(i).fill(0);
    for (let index = 0; index < i-blocknum; index++) {
        minimum_accept_depth = 0
        consecutive_accept = false
        for (let checkpoint_depth = 72; checkpoint_depth<=blocknum; checkpoint_depth++) {
            let estimated_depth = (1200+timestamps[index+checkpoint_depth]-timestamps[index])/600
            allowance = 7 + Math.ceil(checkpoint_depth/6.0)
            if (checkpoint_depth>=estimated_depth-allowance) {
                successes[checkpoint_depth]++
                if (!consecutive_accept){
                    minimum_accept_depth = checkpoint_depth
                    consecutive_accept = true
                }
            }
            else {
                consecutive_accept=false
                minimum_accept_depth=0
            }
        }
        if (minimum_accept_depth == 0){console.log(index),not_accepted_txns[index]=1}
        minimum_accept_depths[minimum_accept_depth]++
        deltas[index]=timestamps[index+blocknum]-timestamps[index]
    }
    for (let index = 0; index < i-blocknum; index++) {
        for (let checkpoint_depth = 72; checkpoint_depth<=2016; checkpoint_depth++) {
        }
    }
    /*let block_pass_height_plot : Plot = {
        x: range(72,2017),
        y: minimum_accept_depths.slice(72,2017),
        type: "scatter"
    }*/
    let not_accepted_txns_plot : Plot = {
        x: range(0,i),
        y: not_accepted_txns,
        type: "scatter",
        name: "rejection"
    }
    let timestamp_ratio_plot : Plot = {
        x: range(30,i),
        y: deltas.map((v)=>v/600/blocknum),
        name: "average timestamp delta"
    }
    //plot([block_pass_height_plot])
    if (do_plot) plot([not_accepted_txns_plot,timestamp_ratio_plot])
    console.log(`Failed blocks = ${minimum_accept_depths[0]}`)

    let success = 0;
    let checkpoint_depth = 0;
    successes.forEach((val)=>{
        if (checkpoint_depth>=72&&checkpoint_depth<=2016) {
            console.log(`One in ${Math.ceil(1/(1-val/(i-2016)))} transactions of checkpoint depth ${checkpoint_depth} will be rejected`);
            success+=val
        }
        checkpoint_depth++
    })
    console.log(`${success/i/1945} of total transactions passed`)
    await evaluate_timestamp_statistics(timestamps,1000,2016)
    return 0;
}

if (require.main === module) {
    main(process.argv[2],Number(process.argv[3]),Boolean(process.argv[4]))
}
