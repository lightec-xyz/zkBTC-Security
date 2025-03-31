# Data analysis examples

Setup and run default tasks
```
$ npm i
$ npm run main
```

## Note
It is recommended to pipe data to a file. The terminal output may be become truncated.

## Task 1 : Compute Transaction pass probability depending on checkpoint depth
```
$ npm tsc && npx tsx analysis/src/cp_compute.ts [data_dispacement] [alternate_data_file_path]
```