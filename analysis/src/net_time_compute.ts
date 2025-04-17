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

function compute_median(data: number[]){
    let ord: number[] = Array.from(data).sort();
    return ord[(ord.length+1)/2];
}

const default_path = "data/headers.txt";

async function main(dataPath:string=default_path, blocknum=11, do_plot=false){
    if(dataPath==""||dataPath=="default"||dataPath=="undefined")dataPath=default_path;
    if(!blocknum)blocknum=11
    let timestamps:number[] = []
    const file = await open(dataPath);
    let i=0
    for await (const line of file.readLines()){
        timestamps[i]=parse_timestamp_from_blockhead(line);
        i++;
    }
    let successes:number[] = Array(2017).fill(0);
    let medians:number[] = [];
    for (i=blocknum;i<timestamps.length;i++){
        // This is hardcoded
        medians[i]=compute_median(timestamps.slice(i-12,i-1));
    }
    let deltas = Array(i);
    let diff = Array(i);
    let not_accepted_txns = Array(i).fill(0);
    for (let index = 1+blocknum; index < i; index++) {
        deltas[index]=timestamps[index-1]-timestamps[index-1-blocknum]
        let estimated_blocktime = (deltas[index])/(blocknum)
        let estimated_network_time = medians[index]+6*estimated_blocktime

        //diff[index]= timestamps[index]-(medians[index]+deltas[index]/11*6+120*60);
        diff[index]=timestamps[index]-estimated_network_time;
        if (diff[index]-120*60<=0) {
            successes[index]++
        }
        else {
            not_accepted_txns[index]++
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
    let mean_blocktime_delta_plot : Plot = {
        x: range(0,i),
        y: deltas.map((v)=>(v/blocknum)),
        name: "mean blocktime"
    }
    //timestamps[i]<=median[i]+6*mean+120*60
    //mean>=(timestamps[i]-120*60-median[i])/6
    let actual_network_time_plot : Plot = {
        x: range(0,i),
        y: medians.map((v,i)=>(timestamps[i]-120*60-v)/6),
        name: "minumum required blocktime"
    }
    let difference_plot : Plot = {
        x: range(0,i),
        y: range(0,i).map((i)=>diff[i]+120*60)
    }
    not_accepted_txns.forEach((v,i)=>{
        if (v) {
            console.log(`block ${i} failed to pass, median = ${medians[i]}, estimated = ${medians[i]+deltas[i]/11*6+120*60}, actual network time = ${timestamps[i]}, deltas = ${deltas[i]/blocknum}, diff = ${timestamps[i]-(medians[i]+deltas[i]/11*6+120*60)}`)
        }
    })
    if (do_plot){
        plot([not_accepted_txns_plot,mean_blocktime_delta_plot])
        plot([not_accepted_txns_plot,actual_network_time_plot])
        plot([mean_blocktime_delta_plot,actual_network_time_plot])
        plot([not_accepted_txns_plot])
        plot([difference_plot])
    }
    evaluate_timestamp_statistics(diff,10000,1+blocknum,(v)=>true)
    let success = 0;
    return 0;
}

if (require.main === module) {
    main(process.argv[2],Number(process.argv[3]),Boolean(process.argv[4]))
}
