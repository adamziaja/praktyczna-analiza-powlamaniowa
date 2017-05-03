#!/usr/bin/env python
"""Apache Log Time Converter (Py 2.6)

Submit bugs to msmith --at-- blackfortressindustries.com

Converts timestamp to/from Apache Combined Format/Epoch time
in place, or output in body file 3.x format. 

NOTE: Currently only Apache combined (distro default) log format is supported
  LogFormat "%h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" combined
  Where:
    %h = Client IP
    %l = identd response from client (generally "-")
    %u = HTTP Auth Username
    %t = server time request was received
      [day/month/year:hour:minute:second zone]
        day = 2*digit
        month = 3*letter
        year = 4*digit
        hour = 2*digit
        minute = 2*digit
        second = 2*digit
        zone = (`+' | `-') 4*digit
    \"%r\" = client request line
    %>s = status code server sent to client
    %O = bytes sent, including size of headers
    \"%{Referer}i\" = contents of the referer req header
    \"%{User-Agent}i\" = contents of the UA req header

Body file formats:
2.x:
  MD5 | path/name | device | inode | mode_as_value | mode_as_string | num_of_links
 | UID | GID | rdev | size | atime | mtime | ctime | block_size | num_of_blocks

3.x:
  MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime

For purposes of our output, 
MD5 shall always be zero
name shall be the (client IP)+"request" according to log line
inode shall be 999999
mode shall be '-/rrwxrwxrwx'
UID shall be zero
GID shall be zero
size shall be size of data sent by server according to log line
atime/mtime/ctime/crtime shall all be set according to the timestamp (seconds since epoch TZ adjusted) in the log line

example fls output in body file 3.x format
md5|file|st_ino|st_ls|st_uid|st_gid|st_size|st_atime|st_mtime|st_ctime|st_crtime
0|<schardt.dd-OBJECTS.MAP-dead-12302>|12302|-/rrwxrwxrwx|0|0|2692|1093621589|1093621589|1093621590|1092954465
0|<schardt.dd-INDEX.MAP-dead-12303>|12303|-/rrwxrwxrwx|0|0|572|1093621589|1093621589|1093621590|1092954465
0|<schardt.dd-ROLL_FORWARD-dead-12304>|12304|-/rrwxrwxrwx|0|0|0|1093621590|1093621590|1093621590|1093621590

"""


import optparse
import re
import datetime
import calendar


def outputApacheLine(data, epoch):
  """Writes data to stdout in Apache Combined Format with
    timestamp converted to epoch value."""
  print("%s %s %s %s \"%s\" %s %s \"%s\" \"%s\"" %
        (data.get('ClientIP'),
         data.get('ident'),
         data.get('Username'),
         epoch,
         data.get('ClientRequest'),
         data.get('ServerStatus'),
         data.get('BytesSent'),
         data.get('Referer'),
         data.get('UserAgent')
         )
        )

def outputBodyLine(data, epoch):
  """Writes data to stdout in bodyfile format for use with timeline data
    from forensic investigations.  Easy to add extra data to name section."""
  print("0|(%s)\"%s\"|99999999|-/rrwxrwxrwx|0|0|%s|%s|%s|%s|%s" %
        (data.get('ClientIP'),
         data.get('ClientRequest'),
         data.get('BytesSent'),
         epoch,
         epoch,
         epoch,
         epoch
         )
        )


def parseApacheFile(file):
  """Deals with the file specified on the command line.  Assuming
    parsing one file at a time, REs are compiled here for efficiency reasons
    and passed to line function.  Is easy to extend to other formats"""
  combinedFormat = re.compile('\A(?P<ClientIP>\d+\.\d+\.\d+\.\d+)\s'
                              '(?P<ident>-|\w*)\s'
                              '(?P<Username>-|\w*)\s'
                              '\[(?P<fullDate>(?P<Day>\d+)/'
                              '(?P<Month>\w+)/'
                              '(?P<Year>\d\d\d\d):'
                              '(?P<Hours>\d\d):'
                              '(?P<Mins>\d\d):'
                              '(?P<Secs>\d\d)\s'
                              '(?P<TZone>[+-]\d\d\d\d))\]\s\"'
                              '(?P<ClientRequest>.*)\"\s'
                              '(?P<ServerStatus>-|\d+)\s'
                              '(?P<BytesSent>-|\d+)\s\"'
                              '(?P<Referer>.*)\"\s\"'
                              '(?P<UserAgent>.*)\"\n?\Z')
  tzPattern = re.compile('\A(?P<EoW>[+-])'
                         '(?P<Hrs>\d\d)'
                         '(?P<Mins>\d\d)\Z')
  # TODO: Check mime-type of file and handle .gz too
  with open(file) as fh:
      for line in fh:
          parseApacheLine(line, combinedFormat, tzPattern)

def parseApacheLine(line, lineRe, tzRe):
  """Handle each line by capturing the data in RE object."""
  lineMatch = lineRe.match(line)
  
  if lineMatch:
    # Do math on ts to account for timezone indicated in logfile
    ts = datetime.datetime.strptime(
        lineMatch.group('fullDate').split()[0],
        '%d/%b/%Y:%H:%M:%S')
    tzMatch = tzRe.match(lineMatch.group('TZone'))
    # create appropriate timedelta object td = timedelta(days=[+|-]\d\d, seconds=[+|-]\d\d)
    tzDelta = datetime.timedelta(
        hours= -(int(tzMatch.group('EoW')+tzMatch.group('Hrs'))),
        minutes= -(int(tzMatch.group('EoW')+tzMatch.group('Mins')))
    )
    # adjust timestamp accordingly with delta object
    newTs = ts + tzDelta
    if (options.mactime):
        outputBodyLine(lineMatch.groupdict(), calendar.timegm(newTs.timetuple()))
    else:
        outputApacheLine(lineMatch.groupdict(), calendar.timegm(newTs.timetuple()))
  else:
    ##TODO: do something more creative with the lines that failed to parse  
    print(line)



  
# Deal with args first

usage = "usage: %prog -f target [-m]"
parser = optparse.OptionParser(usage=usage)
parser.add_option("-f", "--file", action="store", type="string",
                  dest="targetFile", help="Apache Log to parse",
                  metavar="FILE", default="test.log")
parser.add_option("-m", "--mactime", action="store_true", default=False,
                  dest="mactime", help="Enable mactime output format")
(options, args) = parser.parse_args()
if len(options.targetFile) == 0:
    parser.error("Please specify a file to parse")

parseApacheFile(options.targetFile)
