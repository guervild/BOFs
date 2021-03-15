# Silent Lsass Dump

Dump the LSASS process via the silent process exit mechanism into the C:\\Temp directory.
This implementation use direct syscall genreated with @Outflanknl's [InlineWhispers](https://github.com/outflanknl/InlineWhispers).

Only the first method describe in the article [Lsass Memory Dumps are Stealthier than Ever Before – Part 2](https://www.deepinstinct.com/2021/02/16/lsass-memory-dumps-are-stealthier-than-ever-before-part-2/) has been implemented.

All credit to @deepinstinct and their [LsassSilentProcessExit](https://github.com/deepinstinct/LsassSilentProcessExit) project.

## Compile

```
make
```

## Usage

Load the provided aggressor script. After you found the LSASS PID, run the command:

```
silentLsassDump <LSASS PID>
```