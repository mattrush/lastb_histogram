#!/usr/bin/ruby

# lastb_histogram.rb, ruby 2.2.8
#
# analyze a file containing the output of the lastb command.
# sort and generate a sparkline for each ip address.
# requires a UTF8-enabled locale or terminal emulator such as uxterm.
#
# by mrush
# m@root.dance
# https://github.com/mattrush

require 'time'
require 'date'
require 'sparkr'

file_name = "lastb.txt"
events = []
event_count = 0
event_keys = ['ipv4','time','duration','username']
relations = []
freq_ip = Hash.new(0)

ip_re = /(([0-9]{1,3}[.]){3})([0-9]{1,3}){1}/
date_re = /([a-zA-Z]{3}[ ]+){1}([0-9]{1,2}[ ][0-9]{2}[:][0-9]{2}[ ])/
duration_re = /\([0-9]{2}[:][0-9]{2}\)/
dur_re = /([0-9]{2}[:][0-9]{2})/
user_re = /\A\w+/
valid_re = /[s]{2}[h][:]/

puts "[<][parsing events]"
print "["

File.open(file_name, 'r').each do |line|
  valid = valid_re.match(line)
  next unless valid

  ip = ip_re.match(line).to_s
  date = date_re.match(line).to_s
  time = Time.parse(date).to_time if date
  duration = duration_re.match(line).to_s
  dur = dur_re.match(duration).to_s
  user = user_re.match(line).to_s

  values = [ip, time, dur, user]
  event = event_keys.zip(values).to_h
  events<< event
  event_count += 1
  print '.' if (event_count % 1000 == 0)
end

print "]\n"
puts "[+][parsed #{event_count} events]"

# tally number of hits per unique ipv4, into freq_ip hash
events.each { |e| ip = e['ipv4']; freq_ip[ip] += 1 }
freq_ip = freq_ip.sort_by { |a, b| b }
freq_ip.reverse!

# collect hit times for each unique ipv4 into each relation's 'hits' array
c = 1
freq_ip.each do |f_ip, f_count|
  puts "[*][corelating hits from #{f_ip}][#{c}/#{freq_ip.length}]"
  c += 1

  hits = Array.new
  days = Hash.new(0)
  relation = {'ipv4' => f_ip, 'count' => f_count, 'hits' => hits, 'days' => days }

  events.each do |e|
    event_ip = e['ipv4'].to_s
    event_time = e['time'].to_time

    if f_ip == event_ip
      relation['hits']<< event_time
    end
  end
  relations<< relation
end

# for each ip, find the number of hits per day, storing in a hash as @day => count. push the hash into the 'days' array
relations.each do |r|
  r['hits'].each do |h|
    period = h.to_date
    r['days'][period] += 1
  end
end

# find the first and last days seen in the log file
firsts = Array.new
lasts = Array.new
relations.each do |r|
  firsts<< r['days'].keys.min
  lasts<< r['days'].keys.max
end
first = firsts.min
last = lasts.max

# setup the spark_days hash to contain every day from first observed to the last observed, with all counts (values) zeroed
spark_days = Hash.new(0)
step = first
until step > last
  spark_days[step] = 0
  step += 1
end

# display findings
puts "[+][found #{events.length} events]"
puts "[+][found #{freq_ip.length} unique ipv4 addresses]"

# get the string of hits/day for sparkr, and print our findings
relations.each do |r|
  spark_hash = spark_days.clone
  r['days'].each do |day, count|
    spark_hash[day] = count
  end
  spark_array = spark_hash.values
  puts "[+][hits: #{r['count']}][origin: #{r['ipv4']}][#{Sparkr.sparkline(spark_array)}]"
end
