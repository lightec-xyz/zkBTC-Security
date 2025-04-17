import { open } from "node:fs/promises";
import { parse_timestamp_from_blockhead } from "./cp_compute_all";

async function get_timestamps_from_file(dataPath:string="data/headers.txt"){
    let timestamps:number[] = []
    const file = await open(dataPath);
    let i=0
    for await (const line of file.readLines()){
        timestamps[i]=parse_timestamp_from_blockhead(line);
        i++;
    }
    return timestamps
}

export async function evaluate_timestamp_statistics(timestamps:number[], granularity:number=2016, start=1, filter:(v:number)=>boolean=(v)=>(v>=700)){
    if (!granularity) granularity=2016;
    if (!start) start=1;
    let i=start;let s=0;
    let sum = 0;
    let sums:number[] = [];
    let means:number[] = [];
    let sigmas:number[] = [];
    let delta;
    while (i+granularity<timestamps.length){
        [sums[s],means[s],sigmas[s]]=[0,0,0];
        for (let j=0;j<granularity;j++){
            delta = timestamps[i+j]-timestamps[i+j-1];
            sum+=delta
            sums[s]+=delta;
        }
        means[s]=sums[s]/granularity
        for (let j=0;j<granularity;j++){
            delta = timestamps[i+j]-timestamps[i+j-1];
            sigmas[s]+=Math.pow((delta-means[s]),2)
        }
        sigmas[s]=Math.sqrt(sigmas[s]/granularity);
        if (filter(s)){
        console.log(`Section ${s}, blocks ${i} to ${i+granularity-1} : mean=${means[s]}, σ=${sigmas[s]}`)}
        i+=granularity;
        s++
    }

    let size = i
    let mean = sum/(size-start)
    let sigma = 0
    i=start
    while (i<size){
        sigma+=Math.pow(((timestamps[i]-timestamps[i-1])-mean),2)
        i++
    }
    sigma = Math.sqrt(sigma/(size-start))
    console.log(`All blocks from ${start} to ${size} : mean=${mean}, σ=${sigma}`)
}

async function main(data:string|number[]="data/headers.txt", granularity=2016, start=1) {
    if (typeof data === "string") { evaluate_timestamp_statistics(await get_timestamps_from_file(data),granularity,start)}
    else evaluate_timestamp_statistics(data,granularity,start);
}

if (require.main===module){
    main(process.argv[2],Number(process.argv[3]),Number(process.argv[4]))
}