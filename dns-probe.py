#!/usr/bin/env python
import dns.resolver
import threading
import argparse
import sys

def execute(args):
    '''
    Performs dns probes on the specified domain. 
    Returns a JSON of the results
    
    Excepts an args dict with the following contents:
    args["<param>"] = <value>                              
    Param       Value   Description                         Default (Or required)
    domains     []      Domains to probe                    required
    wordlist    path    Wordlist to use when probing        ""
    type        []      The type of DNS records to lookup   ["A"]
    namservers  []      Nameservers to use                  system default
    verbose     Bool    Log verbose status message to outp  False
    debug       Bool    Log debug messages                  False
    '''
    debug = "debug" in args and args["debug"] == True
    verbose = debug or ("verbose" in args and args["verbose"] == True)
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

    results = []
    recordtypes = args["types"]
    for domain in args["domains"]:
        for recordtype in recordtypes:
            subresult = lookup(resolver, domain, recordtype)
            if subresult != []:
                log(verbose, "[+] Hit: %s - %s" % (domain, recordtype))
                dom_results = {}
                dom_results["domain"] = domain
                dom_results["result"] = subresult
                dom_results["type"] = recordtype
                results.append(dom_results)
            else:
                log(debug, "[-] Miss: %s - %s" % (domain, recordtype))

    if wordlist:
        # Divide the wordlist into shards for the different threads.
        shard_count = args["threads"]
        word_count = len(wordlist)
        words_in_shard = word_count/shard_count
        shards = []
        for i in range(0, shard_count):
            offset = i * words_in_shard
            shards.append((offset, offset + words_in_shard))
        # If space is not evenly divided, ensure that the last thread checks the
        # leftovers
        shards[len(shards)-1] = (shards[len(shards)-1][0], word_count)

        log_lock = threading.Lock()

        for domain in args["domains"]:
            threads = []
            for i in range(0, shard_count):
                threads.append(ThreadedLookup(resolver, domain, wordlist, args["types"], verbose, debug, log_lock, shards[i][0], shards[i][1]))
            
            for thread in threads:
                thread.start()
    
            for thread in threads:
                try:
                    thread.join()
                except:
                    continue

            for thread in threads:
                results.extend(thread.results)
            
    return results

class ThreadedLookup(threading.Thread):
    def __init__(self, resolver, domain, wordlist, recordtypes, verbose, debug, log_lock, start_idx, stop_idx):
        threading.Thread.__init__(self)
        self.log_lock = log_lock
        self.resolver = resolver
        self.wordlist = wordlist
        self.recordtypes = recordtypes
        self.domain = domain
        self.verbose = verbose
        self.debug = debug
        self.start_index = start_idx
        self.stop_index = stop_idx
        self.results = []

    def run(self):
        for i in range(self.start_index, self.stop_index):
            subdomain = "%s.%s" % (self.wordlist[i], self.domain)
            for recordtype in self.recordtypes:
                subresult = lookup(self.resolver, subdomain, recordtype)
                if subresult != []:
                    self.log_lock.acquire()             
                    log(self.verbose, "[+] Hit: %s - %s" % (subdomain, recordtype))
                    self.log_lock.release()
        
                    dom_results = {}
                    dom_results["domain"] = subdomain
                    dom_results["result"] = subresult
                    dom_results["type"] = recordtype
                    self.results.append(dom_results)
                else:
                    self.log_lock.acquire()             
                    log(self.debug, "[-] Miss: %s - %s" % (subdomain, recordtype))
                    self.log_lock.release()
            
         

def lookup(resolver, domain, recordtype):
    results = []
    try:
        answers = resolver.query(domain, recordtype)
        for answer in answers:
            results.append(str(answer))
    except Exception as e:
        return []
    return results
        

def log(should_log, msg):
    if should_log:
        print(msg)

def parse_cmdline():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--domains", help="The domains to probe.", nargs="*", default=[])
    parser.add_argument("-n", "--nameservers", help="The domain servers to use", nargs="*", default=[])
    parser.add_argument("-l", "--wordlist", help="Wordlist of possible subdomains.", default="")
    parser.add_argument("-T", "--threads", help="Number of threads to use when bruting with a wordlist.", default=1, type=int)
    parser.add_argument("-t", "--types", help="The type of dns record to look up.", default=["A"], choices=["A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME"], nargs="*")
    parser.add_argument("-v", "--verbose", help="Verbose status messages.", default=False, action="store_true")
    parser.add_argument("-f", "--format", help="Format of the output.", default="grep", choices={"grep", "json"})
    parser.add_argument("-V", "--debug", help="Log debug messages.", default=False, action="store_true")
    parser.add_argument("-r", "--read", help="Read domains from file.")
    parser.add_argument("-w", "--write", help="Write results to files using the given base path.", default="")
    
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

    for recordtype in args["types"]:
        subresults = filter(lambda x: x["type"] == recordtype, results)
        for result in subresults:
            output = formatter(result)
            fd_out.write(output + "\n")
    
    if args["write"] != "":
        fd_out.close()
