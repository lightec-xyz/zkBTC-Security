# Data analysis examples

Setup and run default tasks
```
$ npm i
$ npm run main
```

## Note
It is recommended to pipe data to a file, otherwise the terminal output may be become truncated.

## Computing Checkpoint liveness 
Evaluates whether a checkpoint will accept a transaction downstream eventually, up to a set amount of blocks (defaults to 2016 blocks, or approximately 14 days). 
```
npx tsc
node analysis/dist/src/cp_compute_all.js [maximum blocks]
```