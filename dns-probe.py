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
    type    str     The type of DNS record to lookup    "A"
    namservers  []      Nameservers to use                  system default
    depth       int     Stop after #depth rec. steps        1
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

    wordlist = []
    if args["wordlist"] != "":
        log(debug, "[+] Using wordlist: %s" % args["wordlist"])
        with open(args["wordlist"], "r") as f:
            wordlist = map(lambda x: x.strip(), f.readlines())

    results = {}
    for domain in args["domains"]:
        subresult = lookup(resolver, domain, args["type"])
        if subresult != []:
            log(verbose, "[+] Hit: %s" % domain)
            results[domain] = {}
            results[domain]["domain"] = domain
            results[domain]["result"] = subresult
            results[domain]["type"] = args["type"]
        else:
            log(debug, "[-] Miss: %s" % domain)

    for domain in args["domains"]:
        for word in wordlist:
            subdomain = "%s.%s" % (word, domain)
            subresult = lookup(resolver, subdomain, args["type"])
            if subresult != []:
                log(verbose, "[+] Hit: %s" % subdomain)
                results[subdomain] = {}
                results[subdomain]["domain"] = subdomain
                results[subdomain]["result"] = subresult
                results[subdomain]["type"] = args["type"]
            else:
                log(debug, "[-] Miss: %s" % subdomain)
    
    return results

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
    parser.add_argument("-t", "--type", help="The type of dns record to look up.", default="A")
    parser.add_argument("-D", "--depth", help="Max depth of recursive search.", default=1)
    parser.add_argument("-c", "--use-cache", help="Search known caches.", default=False, action="store_true")
    parser.add_argument("-s", "--save-state", help="Save state during probe.", default=False, action="store_true")
    parser.add_argument("-p", "--resume", help="Attempt to resume previous probing", default=False, action="store_true")
    parser.add_argument("-v", "--verbose", help="Verbose status messages.", default=False, action="store_true")
    parser.add_argument("-f", "--format", help="Format of the output.", default="grep", choices={"grep", "json"})
    parser.add_argument("-V", "--debug", help="Log debug messages.", default=False, action="store_true")
    parser.add_argument("-r", "--read", help="Read domains from file.")
    parser.add_argument("-w", "--write", help="Write results to file.", default="")
    
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

    for domain, result in results.iteritems():
        output = formatter(result)
        fd_out.write(output + "\n")
    
    if args["write"] != "":
        fd_out.close()
