# Collecting Statistics Via slapd-tester

If started with the option 

**-%** *filename*
	
slapd-tester writes statistics (as text) to *filename*. 

To do that, it starts the test programs (e.g. slapd-addel) with the option

**-%** /tmp/statsfifo

This name is hard-coded in slapd-common.h.  It is the name of a FIFO
that slapd-tester creates.  

The test programs test the argument to the **-%** option.  If it is a
FIFO, they write binary information to it.  If not, they write
text. That way, individual test programs can be run outside the
framework, and the framework's binary data feed can be adapted to
other uses later.

To read the FIFO, slapd-tester forks yet one more child.  The reader
normally exits on EOF, which happens when all writers close the
FIFO. slapd-tester normally removes the FIFO via an exit handler.

## Script Machinery

**slapd-tester** is normally invoked by the **run** script, currently
verging on 1000 lines of shell script.  

The course of least resistance seemed to be an environment
variable. If you define

**TESTER_STATS=***filename*

in your environment, then **run** will invoke 

**slapd-tester -%** *filename*


