import { open } from "node:fs/promises";
import path from "node:path";

function parse_timestamp_from_blockhead(line: string): number{
    let timeHex = line.substring(136,144);
    //Reverse Endianess
    let timeHexRev = ""+timeHex.substring(6,8)+timeHex.substring(4,6)+timeHex.substring(2,4)+timeHex.substring(0,2);
    let timeStamp = parseInt(timeHexRev,16);
    return timeStamp;
}

async function main(displacement:number=0, dataPath:string="analysis/data/headers.txt"){
    if (Number.isNaN(displacement))displacement=0;
    console.log("Start")
    console.log("Current working directory:"+path.resolve("./"))
    let timestamps:number[] = []
    const file = await open(dataPath);
    let i=0
    for await (const line of file.readLines()){
        //console.log(i+" "+line)
        timestamps[i]=parse_timestamp_from_blockhead(line);
        //console.log(timestamps[i])
        i++;
    }
    let okaydiff = 0;
    let gooddiff = 0;
    let successes:number[] = new Array(2017).fill(0);
    let blocknum_base = i - 3017 - displacement;
    let allowance = 0;
    for (let index = 0; index < 1000; index++) {
        let blocknum = blocknum_base + index 
        let delta_t = timestamps[blocknum]-timestamps[blocknum-1]
        if (timestamps[blocknum]) {okaydiff++}
        if (540<=delta_t&&delta_t<=660) {gooddiff++}
        for (let chekpoint_depth = 70; chekpoint_depth<=2016; chekpoint_depth++) {
            let estimated_depth = (1200+timestamps[blocknum]-timestamps[blocknum-chekpoint_depth])/600
            let i = 0
            allowance = 7 + Math.ceil(chekpoint_depth/6.0)
            if (chekpoint_depth>=estimated_depth-allowance) {
                successes[chekpoint_depth]++
            }
            i++
        }
    }
    i = 0;
    let success = 0;
    let dec:number[] = Array(10).fill(0);
    successes.forEach((val)=>{
        if (i>=70&&i<=2010) {console.log(`${val} out of ${1000} of checkpoint depth ${i} passed`);}
        if (i>=70&&i<=2016) {dec[Math.floor((i-70)/194)]+=val
        success+=val}
        i++
    })
    console.log(`${success/1947000} of total checkpoints passed`)
    for (let i = 1; i <= 10; i++) {
        console.log(`${dec[i-1]/(194*1000)} of checkpoints of approximate depth ${i-1}0% to ${i}0% passed`)
        
    }
    console.log(`${okaydiff/1000} of blockheads are well defined `)
    console.log(`${gooddiff/1000} of block timestamps are within 10% of 600s`)
    return 0;
}

if (require.main === module) {
    main(Number(process.argv[2]),process.argv[3])
}
