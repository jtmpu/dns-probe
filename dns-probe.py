#!/usr/bin/env python
import dns.resolver
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
    namservers  []      Nameservers to use                  system default
    depth       int     Stop after #depth rec. steps        3
    use-cache   Bool    Search the enabled cache modules    False
    save-state  Bool    Enable the saving of state          False
    resume      Bool    Attempt to resume previous probe    False
    verbose     Bool    Log verbose status message to outp  False
    debug       Bool    Log debug messages                  False
    '''
    debug = "debug" in args and args["debug"] == True
    verbose = debug or ("verbose" in args and args["verbose"] == True)
    resolver = dns.resolver.get_default_resolver()
    if args["nameservers"] != []:
        resolver.nameservers = args["nameservers"]
    log(debug, "[+] Using nameservers: %s" % resolver.nameservers)

    results = {}
    for domain in args["domains"]:
        domain_res = {}
        results[domain] = domain_res
        try:
            answers = resolver.query(domain)
            for answer in answers:
                log(verbose, "[+] Hit %s" % domain)
                domain_res[domain] = str(answer)
        except:
            log(debug, "[-] Miss: %s" % domain)
            continue
    return results

def parse_cmdline():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--domains", help="The domains to probe.", nargs="*", default=[])
    parser.add_argument("-n", "--nameservers", help="The domain servers to use", nargs="*", default=[])
    parser.add_argument("-w", "--wordlist", help="Wordlist of possible subdomains.", default="")
    parser.add_argument("-D", "--depth", help="Max depth of recursive search.")
    parser.add_argument("-c", "--use-cache", help="Search known caches.", default=False, action="store_true")
    parser.add_argument("-s", "--save-state", help="Save state during probe.", default=False, action="store_true")
    parser.add_argument("-r", "--resume", help="Attempt to resume", default=False, action="store_true")
    parser.add_argument("-v", "--verbose", help="Verbose status messages.", default=False, action="store_true")
    parser.add_argument("-f", "--format", help="Format of the output.", default="grep", choices={"grep", "json"})
    parser.add_argument("-V", "--debug", help="Log debug messages.", default=False, action="store_true")
    
    args = parser.parse_args() 

    if args.domains == []:
        lines = sys.stdin.readlines()
        args.domains.extend(map(lambda x: x.strip(), lines))

    return vars(args)

def log(should_log, msg):
    if should_log:
        print(msg)

if __name__ == "__main__":
    args = parse_cmdline()
    results = execute(args)
    print(results)
