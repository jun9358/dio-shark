# dio-shark

dio-shark is an analyzing disk input/output tool. It has two program. One is dioshark and other is dioparse. dioshark capture raw event from disk. dioparse analyze raw data got from dioshark and print or show analyzing results.

## System requirements
dio-shark is known to compile and pass its test suite on:

* Ubuntu with 12.04 LTS version.

## Facilities
* Capturing disk input/output.
* Showing analyzing results with some options such as time, sector, pid and so on.

## Goals
* Finding bottleneck in disk input/output.

## Usages
### dioshark
dioshark [ -d \<device\> ] [ -o \<outfile\> ]
* -d : device which is traced
* -o : output file name

### dioparse

dioparse [ -i \<input\> ] [ -o \<output\> ] [-p \<print\> ] [ -T \<time filter\> ] [ -S \<sector filter\> ] [ -P \<pid filter\> ] [ * -s \<statistic\> ] [ -g ]
* -i : The input file name which has the raw tracing data.
* -o : The output file name of dioparse.
* -p : Print option. It can have two suboptions 'sector' , 'time'
* -T : Time filter option
* -S : Sector filter option
* -P : Pid filter option
* -s : Statistic option. It can have three suboptions 'path', 'pid' and 'cpu'
* -g : Show statistic results graphically.


## Build and quick start for using the program

```bash
$ make
$ sudo ./dioshark -d sda -o output_shark
```

Perform some input/output action and terminate dioshark(Ctrl+C)

```bash
$ sudo ./dioparse -i output_shark -o output_parse.txt
$ vi output_parse.txt
```
