#!/usr/bin/env python
import dns.resolver
import threading
import argparse
import sys

import task_pool

def execute(args):
    '''
    Performs dns probes on the specified domain. 
    Returns a JSON of the results
    
    Excepts an args dict with the following contents:
    args["<param>"] = <value>                              
    Param       Value   Description                         Default (Or required)
    domains     []      Domains to probe                    required
    wordlist    path    Wordlist to use when probing        ""
    types       []      The type of DNS records to lookup   ["A"]
    namservers  []      Nameservers to use                  system default
    store_miss  Bool    Store misses as well                False
    verbose     Bool    Log verbose status message to outp  False
    debug       Bool    Log debug messages                  False
    rate        int     Maximum requests per second         1000
    threads     int     Number of threads to utilize        1
    '''
    if args["domains"] == []:
        raise Exception("Domains required.")
    if "wordlist" not in args:
        args["wordlist"] = ""
    if "types" not in args or args["types"] == []:
        args["types"] = ["A"]
    if "nameservers" not in args:
        args["nameservers"] = []
    if "store_miss" not in args:
        args["store_miss"] = False
    if "verbose" not in args:
        args["verbose"] = False
    if "debug" not in args:
        args["debug"] = False

    debug = args["debug"]
    verbose = debug or args["verbose"]

    resolver = dns.resolver.get_default_resolver()
    if args["nameservers"] != []:
        resolver.nameservers = args["nameservers"]
    log(debug, "[+] Using nameservers: %s" % resolver.nameservers)

    wordlist = []
    if args["wordlist"] != "":
        log(debug, "[+] Using wordlist: %s" % args["wordlist"])
        with open(args["wordlist"], "r") as f:
            wordlist = map(lambda x: x.strip(), f.readlines())

    log(debug, "[+] Running with %d threads." % args["threads"])

    # Check the specified domains
    # Prepare threadpool with tasks
    domains = args["domains"]
    recordtypes = args["types"]
    threadcount = args["threads"]
    rate = args["rate"]

    pool = task_pool.TaskPool(rate, threadcount)
    for domain in domains:
        for record_type in recordtypes:
            pool.add_task(dns_request, resolver, domain, record_type, log, verbose, debug)

    if len(wordlist) > 0:
        for domain in domains:
            for word in wordlist:
                for recordtype in recordtypes:
                    pool.add_task(dns_request, resolver, word + "." + domain, recordtype, log, verbose, debug)

    # Perform all dns requests (wait until everything is done)
    # RAM issues?
    try:
        pool.perform_tasks()
    except KeyboardInterrupt:
        pool.cleanup()
        return []
    
    # Extract the results
    results = []
    store_miss = args["store_miss"]
    for dns_response in list(pool.result_reporter.queue.queue):
        if dns_response:
            name = dns_response[0]
            recordtype = dns_response[1]
            answers = dns_response[2]
            result = {}
            result["domain"] = name
            result["result"] = map(str, answers)
            result["type"] = recordtype
            results.append(result)
            # Add "." to end of domain as this is expected format 
            if answers.canonical_name.to_text() != name + ".": 
                # A CNAME Was returned as well, store it.
                cname_record = {}
                cname_record["domain"] = name
                cname_record["result"] = [ answers.canonical_name.to_text() ]
                cname_record["type"] = "CNAME"
                results.append(cname_record)
        elif store_miss:
            result = {}
            result["domain"] = name
            result["result"] = []
            result["type"] = "NXDOMAIN"
            results.append(result)
            
    return results

def dns_request(resolver, name, recordtype, logger, verbose, debug):
    answers = None
    try:
        answers = resolver.query(name, recordtype)
        logger(verbose, "[+] Hit %s (%s)" % (name, recordtype))
    except Exception as e:
        logger(debug, "[-] Miss %s (%s)" % (name, recordtype))
        return None
    return (name, recordtype, answers)


log_lock = threading.Lock()
def log(should_log, msg):
    global log_lock
    log_lock.acquire()
    if should_log:
        print(msg)
    log_lock.release()

def parse_cmdline():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--domains", help="The domains to probe.", nargs="*", default=[])
    parser.add_argument("-n", "--nameservers", help="The domain servers to use", nargs="*", default=[])
    parser.add_argument("-l", "--wordlist", help="Wordlist of possible subdomains.", default="")
    parser.add_argument("-t", "--types", help="The type of dns record to look up.", default=["A"], choices=["A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME"], nargs="*")
    parser.add_argument("-v", "--verbose", help="Verbose status messages.", default=False, action="store_true")
    parser.add_argument("-f", "--format", help="Format of the output.", default="grep", choices={"grep", "json"})
    parser.add_argument("-V", "--debug", help="Log debug messages.", default=False, action="store_true")
    parser.add_argument("-r", "--read", help="Read domains from file.")
    parser.add_argument("-w", "--write", help="Write results to files using the given base path.", default="")
    parser.add_argument("-s", "--store-miss", help="Store the result even tho there was a NXDOMAIN (miss) when performing the lookup.", default=False, action="store_true")
    parser.add_argument("-T", "--threads", help="Number of threads to use when bruting with a wordlist.", default=1, type=int)
    parser.add_argument("-R", "--rate", help="Maximum number of requests per second allowed", default=1000, type=int)
    
    args = parser.parse_args() 

    if args.read:
        with open(args.read, "r") as f:
            lines = map(lambda x: x.strip(), f.readlines())
            args.domains.extend(lines)
    if args.domains == []:
        lines = sys.stdin.readlines()
        args.domains.extend(map(lambda x: x.strip(), lines))

    return vars(args)

def json_output(result):
    return str(result)

def grep_output(result):
    domain = result["domain"]
    result_str = reduce(lambda x,y: x + y + ",", result["result"], "")[:-1]
    recordtype = result["type"]
    return ("%s\t%s\t%s" % (domain, result_str, recordtype))

if __name__ == "__main__":
    args = parse_cmdline()
    results = execute(args)

    formatter = grep_output
    if args["format"] == "json":
        formatter = json_output

    fd_out = sys.stdout
    if args["write"] != "":
        fd_out = open(args["write"], "w")

    for result in results:
        output = formatter(result)
        fd_out.write(output + "\n")
    
    if args["write"] != "":
        fd_out.close()
