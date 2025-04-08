@Client.command()
@commands.has_role(ADMIN_ROLE)
async def exec(ctx, *, argument):
    """Execute shell commands (admin only)"""
    await ctx.send("Executing command...")
    results, error = run_command_safely(argument, shell=True, executable="/bin/bash")
    await send_output(ctx, results, error)

@Client.command()
@commands.has_role(ADMIN_ROLE)
async def sudo(ctx, member: discord.Member, role: discord.Role):
    """Add a role to a member (admin only)"""
    try:
        await member.add_roles(role)
        await ctx.send(f"> Successfully added **{role.name}** to **{member.name}**")
    except discord.Forbidden:
        await ctx.send("**Error: I don't have permission to manage roles.**")
    except Exception as e:
        await ctx.send(f"**Error: {e}**")

@Client.command()
@commands.has_role(ADMIN_ROLE)
async def unsudo(ctx, member: discord.Member, role: discord.Role):
    """Remove a role from a member (admin only)"""
    try:
        await member.remove_roles(role)
        await ctx.send(f"> Successfully removed **{role.name}** from **{member.name}**")
    except discord.Forbidden:
        await ctx.send("**Error: I don't have permission to manage roles.**")
    except Exception as e:
        await ctx.send(f"**Error: {e}**")

@Client.command()
@commands.has_role(ADMIN_ROLE)
async def shutdown(ctx):
    """Shutdown the bot (admin only)"""
    await ctx.send("**Shutting down!**\nSomeone requested the shutdown command")
    await ctx.bot.close()

@Client.command()
@commands.has_role(ADMIN_ROLE)
async def restart(ctx):
    """Restart the bot (admin only)"""
    await ctx.send(f"**Restarting ReconServer!**\nIt might take a few minutes to restart the server.")
    try:
        execl(sys.executable, sys.executable, *sys.argv)
    except Exception as e:
        await ctx.send(f"**Error restarting: {e}**")

@Client.command()
@commands.has_role(ADMIN_ROLE)
async def history(ctx):
    """View command history (admin only)"""
    try:
        commands_path = f'{BASE_PATH}/logs/commands.log'
        if not path.exists(commands_path):
            await ctx.send("**Command history log not found.**")
            return
            
        with open(commands_path, 'r') as f:
            commands_content = f.read()
        
        await ctx.send(f"Sending the commands history to your DM :rocket:\nRequested by **{ctx.message.author}**")
        
        if len(commands_content) < 2000:
            await ctx.message.author.send("Users Commands:")
            await ctx.message.author.send(f'```swift\n{commands_content}```')
        else:
            random_str = utilities.generate_random_string()
            with open(f'messages/{random_str}', 'w') as message:
                message.write(commands_content)
                
            await ctx.message.author.send("Users Commands:", file=discord.File(f"messages/{random_str}"))
    except discord.Forbidden:
        await ctx.send("**I don't have permission to send you direct messages.**")
    except Exception as e:
        await ctx.send(f"**Error: {e}**")

@Client.command()
@commands.has_role(ADMIN_ROLE)
async def show(ctx):
    """Show available recon data (admin only)"""
    global logsItems
    
    targetsList = []
    for site, _ in logsItems.items():
        targetsList.append(site)
    
    if not targetsList:
        await ctx.send("**No recon data available.**")
        return
        
    targets_message = '\n'.join(targetsList)
    targets_message = f"""```\n{targets_message}\n```"""
    await ctx.send(f"**Available records: \n\n{targets_message}**")

@Client.command()
@commands.has_role(ADMIN_ROLE)
async def count(ctx, *, argument):
    """Count subdomains for a target (admin only)"""
    global logsItems, resolvedItems
    
    # Error handling for missing data
    if argument not in resolvedItems:
        await ctx.send("**There are no subdomains collected for this target. Please use** `.subdomains [TARGET]` **then try again.**")
        return
        
    if argument not in logsItems:
        await ctx.send("**There are no live subdomains collected for this target. Please use** `.subdomains [TARGET]` **then try again.**")
        return
    
    try:
        resolved_file = resolvedItems[argument]
        resolved_path = f'data/hosts/{resolved_file}'
        if not path.exists(resolved_path):
            await ctx.send(f"**Error: File not found at {resolved_path}**")
            return
            
        with open(resolved_path, 'r') as f:
            resolved_content = f.readlines()
        resolved_length = len(resolved_content)
        
        subdomains_file = logsItems[argument]
        subdomains_path = f'data/subdomains/{subdomains_file}'
        if not path.exists(subdomains_path):
            await ctx.send(f"**Error: File not found at {subdomains_path}**")
            return
            
        with open(subdomains_path, 'r') as f:
            subdomains_content = f.readlines()
        subdomains_length = len(subdomains_content)
        
        await ctx.send(f"**{argument}**:\n\t\tResolved hosts: {resolved_length}\n\t\tLive subdomains: {subdomains_length}")
    except Exception as e:
        await ctx.send(f"**Error counting subdomains: {e}**")

#----- USER COMMANDS -----#

@Client.command()
async def nslookup(ctx, *, argument):
    """Perform DNS lookup"""
    if not argument:
        await ctx.send("**Please provide a domain to look up.**")
        return
        
    # Sanitize input to prevent command injection
    argument = CommandInjection.sanitizeInput(argument)
    
    await ctx.send(f"Looking up DNS information for **{argument}**...")
    results, error = run_command_safely(['nslookup', argument], shell=False)
    await send_output(ctx, results, error, f"DNS lookup for **{argument}**:")

@Client.command()
async def whois(ctx, *, argument):
    """Perform WHOIS lookup"""
    if not argument:
        await ctx.send("**Please provide a domain for WHOIS lookup.**")
        return
        
    # Sanitize input to prevent command injection
    argument = CommandInjection.sanitizeInput(argument)
    
    await ctx.send(f"Performing WHOIS lookup for **{argument}**...")
    results, error = run_command_safely(['whois', argument], shell=False)
    await send_output(ctx, results, error, f"Whois output for **{argument}**:")

@Client.command()
async def dig(ctx, *, argument):
    """Perform DIG lookup"""
    if not argument:
        await ctx.send("**Please provide a domain for DIG lookup.**")
        return
        
    # Sanitize input to prevent command injection
    argument = CommandInjection.sanitizeInput(argument)
    
    await ctx.send(f"Performing DIG lookup for **{argument}**...")
    results, error = run_command_safely(['dig', argument], shell=False)
    await send_output(ctx, results, error, f"Dig output for **{argument}**:")

@Client.command()
async def ip(ctx, *, argument):
    """Get IP address for a domain"""
    if not argument:
        await ctx.send("**Please provide a domain to resolve to an IP.**")
        return
        
    # Sanitize input to prevent command injection
    argument = CommandInjection.sanitizeInput(argument)
    
    try:
        result = utilities.get_ip(argument)
        await ctx.send(result)
    except Exception as e:
        await ctx.send(f"**Error resolving IP: {e}**")

@Client.command()
async def statuscode(ctx, *, argument):
    """Check HTTP status codes for a URL"""
    if not argument:
        await ctx.send("**Please provide a URL to check.**")
        return
        
    # Validate URL
    url_parts = urlparse(argument)
    url_scheme = url_parts.scheme or 'http'
    
    if url_scheme not in ["http", "https"]:
        await ctx.send("**The URL scheme you're using isn't allowed. Please use HTTP or HTTPS.**")
        return
    
    try:
        await ctx.send(f"Checking HTTP methods for <{argument}>")
        await ctx.message.edit(suppress=True)
        status_code_dict = utilities.get_status_codes(argument)
        message = "\n".join(f"{method}: {str(code)}" for method, code in status_code_dict.items())
        
        await ctx.send(message)
        await ctx.send(f"\nRequested by **{ctx.message.author}**")
    except Exception as e:
        await ctx.send(f"**Error checking status codes: {e}**")

@Client.command()
async def prips(ctx, *, argument):
    """Convert CIDR notation to IP range"""
    if not argument:
        await ctx.send("**Please provide a CIDR range.**")
        return
        
    # Sanitize input to prevent command injection
    argument = CommandInjection.sanitizeInput(argument)
    
    await ctx.send(f"Converting CIDR **{argument}** to IP range...")
    results, error = run_command_safely(f"prips {argument}", shell=True)
    await send_output(ctx, results, error, f"Prips output for **{argument}**:")

#----- RECON TOOLS -----#

@Client.command()
async def dirsearch(ctx, *, argument):
    """Directory bruteforce using dirsearch"""
    if not argument:
        await ctx.send("**Please provide a URL to scan.**")
        return
        
    # Sanitize input to prevent command injection
    argument = CommandInjection.sanitizeInput(argument)
    
    try:
        file_name = utilities.generate_random_string()
        dirsearch_path = TOOLS.get('dirsearch')
        
        if not dirsearch_path or not path.exists(dirsearch_path):
            await ctx.send("**Dirsearch tool not found. Please check your settings.**")
            return
            
        current_dir = getcwd()
        try:
            chdir(dirsearch_path)
            
            await ctx.send(f"**Running dirsearch scan on {argument}...**")
            await ctx.send("**Dirsearch has started. Results will be sent when the process is complete.**")
            
            # Run the command asynchronously
            cmd = f'python3 dirsearch.py -u {argument} -e "*" -o {BASE_PATH}/messages/{file_name} && python3 {BASE_PATH}/notify.py --mode 2 -m "Dirsearch results:" -f "- {ctx.message.author}" --file {file_name}'
            subprocess.Popen(cmd, shell=True, stdin=None, stdout=None, stderr=None, close_fds=True)
        finally:
            chdir(current_dir)
    except Exception as e:
        await ctx.send(f"**Error starting dirsearch: {e}**")

@Client.command()
async def arjun(ctx, *, argument):
    """Parameter discovery using Arjun"""
    if not argument:
        await ctx.send("**Please provide a URL to scan.**")
        return
        
    # Sanitize input to prevent command injection
    argument = CommandInjection.sanitizeInput(argument)
    
    await ctx.send(f"**Running Arjun scan on {argument}...**")
    await ctx.send("**Note: The bot won't respond to other commands until this scan completes.**")
    
    try:
        results, error = run_command_safely(f'arjun -u {argument}', shell=True)
        
        if error:
            await ctx.send(f"**Error running Arjun: {error}**")
            return
            
        # Process results
        results = utilities.remove_escape_sequences(results or "")
        results = utilities.remove_string('Processing', results)
        
        target_name = argument.split(' ')[0].replace('http://', '').replace('https://', '')
        await send_output(ctx, results, None, f"Arjun Results For {target_name}:")
    except Exception as e:
        await ctx.send(f"**Error running Arjun: {e}**")

@Client.command()
async def waybackurls(ctx, *, argument):
    """Fetch URLs from Wayback Machine"""
    if not argument:
        await ctx.send("**Please provide a domain to search.**")
        return
        
    # Sanitize input to prevent command injection
    argument = CommandInjection.sanitizeInput(argument)
    
    await ctx.send(f"**Collecting Wayback URLs for {argument}...**")
    
    try:
        results, error = run_command_safely(f"echo {argument} | waybackurls", shell=True)
        
        if error:
            await ctx.send(f"**Error collecting Wayback URLs: {error}**")
            return
            
        await send_output(ctx, results, None, f"Waybackurls output for **{argument}**:")
    except Exception as e:
        await ctx.send(f"**Error collecting Wayback URLs: {e}**")

@Client.command()
async def subfinder(ctx, *, argument):
    """Discover subdomains using subfinder"""
    if not argument:
        await ctx.send("**Please provide a domain to scan.**")
        return
        
    # Sanitize input to prevent command injection
    argument = CommandInjection.sanitizeInput(argument)
    
    await ctx.send(f"**Collecting subdomains for {argument} using Subfinder...**")
    
    try:
        results, error = run_command_safely(f"subfinder -d {argument} -all -silent", shell=True)
        
        if error:
            await ctx.send(f"**Error running Subfinder: {error}**")
            return
            
        await send_output(ctx, results, None, f"Subfinder Results for **{argument}**:")
    except Exception as e:
        await ctx.send(f"**Error running Subfinder: {e}**")

@Client.command()
async def assetfinder(ctx, *, argument):
    """Discover subdomains using assetfinder"""
    if not argument:
        await ctx.send("**Please provide a domain to scan.**")
        return
        
    # Sanitize input to prevent command injection
    argument = CommandInjection.sanitizeInput(argument)
    
    await ctx.send(f"**Collecting subdomains for {argument} using Assetfinder...**")
    
    try:
        results, error = run_command_safely(f"assetfinder --subs-only {argument}", shell=True)
        
        if error:
            await ctx.send(f"**Error running Assetfinder: {error}**")
            return
            
        await send_output(ctx, results, None, f"Assetfinder Results for **{argument}**:")
    except Exception as e:
        await ctx.send(f"**Error running Assetfinder: {e}**")

@Client.command()
async def findomain(ctx, *, argument):
    """Discover subdomains using findomain"""
    if not argument:
        await ctx.send("**Please provide a domain to scan.**")
        return
        
    # Sanitize input to prevent command injection
    argument = CommandInjection.sanitizeInput(argument)
    
    # Check if findomain is properly configured
    findomain_path = TOOLS.get('findomain')
    if not findomain_path or not path.exists(findomain_path):
        await ctx.send("**Findomain tool not found. Please check your settings.**")
        return
        
    await ctx.send(f"**Collecting subdomains for {argument} using Findomain...**")
    
    try:
        results, error = run_command_safely(f"findomain --target {argument} --quiet", shell=True)
        
        if error:
            await ctx.send(f"**Error running Findomain: {error}**")
            return
            
        await send_output(ctx, results, None, f"Findomain Results for **{argument}**:")
    except Exception as e:
        await ctx.send(f"**Error running Findomain: {e}**")

@Client.command()
async def paramspider(ctx, *, argument):
    """Discover parameters using ParamSpider"""
    if not argument:
        await ctx.send("**Please provide a domain to scan.**")
        return
        
    # Sanitize input to prevent command injection
    argument = CommandInjection.sanitizeInput(argument)
    
    # Check if ParamSpider is properly configured
    param_path = TOOLS.get('paramspider')
    if not param_path or not path.exists(param_path):
        await ctx.send("**ParamSpider tool not found. Please check your settings.**")
        return
        
    await ctx.send(f"**Collecting parameters for {argument} using ParamSpider...**")
    
    try:
        results, error = run_command_safely(f"paramspider -d {argument}", shell=True)
        
        if error:
            await ctx.send(f"**Error running ParamSpider: {error}**")
            return
            
        # Process results
        results = utilities.remove_escape_sequences(results or "")
        urls_list = []
        
        for line in results.split('\n'):
            if line.startswith('http'):
                urls_list.append(line)
                
        results = '\n'.join(urls_list)
        
        await send_output(ctx, results, None, f"ParamSpider Results for **{argument}**:")
    except Exception as e:
        await ctx.send(f"**Error running ParamSpider: {e}**")

@Client.command()
async def gitls(ctx, *, argument):
    """List GitHub repositories for a user/organization"""
    if not argument:
        await ctx.send("**Please provide a GitHub username.**")
        return
        
    # Sanitize input to prevent command injection
    argument = CommandInjection.sanitizeInput(argument)
    
    await ctx.send(f"**Collecting GitHub repositories for {argument}...**")
    
    try:
        results, error = run_command_safely(f"echo https://github.com/{argument} | gitls", shell=True)
        
        if error:
            await ctx.send(f"**Error running gitls: {error}**")
            return
            
        if not results:
            await ctx.send(f"**Gitls didn't return any output for {argument}**")
            return
            
        await send_output(ctx, results, None, f"Gitls output for **{argument}**:")
    except Exception as e:
        await ctx.send(f"**Error running gitls: {e}**")

@Client.command()
async def recon(ctx, *, argument):
    """Access pre-saved recon data"""
    if not argument:
        await ctx.send("**Please provide a path to recon data.**")
        return
        
    # Security: Prevent path traversal
    argument = argument.replace('..', '').replace('//', '/')
    
    path_to_check = f'/{USER}/{RECON_PATH}/{argument}'
    
    try:
        if path.exists(path_to_check):
            with open(path_to_check, 'r') as f:
                data = f.read().rstrip()
                data = utilities.remove_escape_sequences(data)
                
            await send_output(ctx, data, None, f"Recon data for **{argument}**:")
        else:
            await ctx.send("**Sorry, the path you specified doesn't exist in our records.**")
    except Exception as e:
        await ctx.send(f"**Error accessing recon data: {e}**")

#----- ADVANCED RECON COMMANDS -----#

@Client.command()
async def subdomains(ctx, *, argument):
    """Collect subdomains from multiple sources and check for live hosts"""
    if not argument:
        await ctx.send("**Please provide a domain to scan.**")
        return
        
    # Create and start the collection task
    asyncio.create_task(collect_subdomains(ctx, argument=argument))

async def collect_subdomains(ctx, *, argument):
    """Async task to collect subdomains"""
    global logsItems, resolvedItems
    
    # Sanitize input to prevent command injection
    argument = CommandInjection.sanitizeInput(argument)
    
    await ctx.send(f"**Collecting subdomains for {argument}...**\nThis might take a few minutes.")
    
    # Verify findomain path
    findomain_path = TOOLS.get('findomain')
    if not findomain_path or not path.exists(findomain_path):
        await ctx.send("**Findomain tool not found. Continuing with other tools.**")
        findomain_path = "echo 'Findomain not available'"
    
    # Define async subprocess runner
    async def run_subprocess(command):
        try:
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT
            )
            results = await process.communicate()
            return results[0].decode('UTF-8')
        except Exception as e:
            return f"Error: {e}"
    
    # Run all subdomain tools asynchronously
    try:
        findomain_results, assetfinder_results, subfinder_results = await asyncio.gather(
            run_subprocess(f"findomain --target {argument} --quiet"),
            run_subprocess(f"assetfinder --subs-only {argument}"),
            run_subprocess(f"subfinder -d {argument} -all -silent")
        )
        
        # Combine and process results
        all_subdomains = findomain_results + assetfinder_results + subfinder_results
        all_subdomains = utilities.remove_duplicates(all_subdomains)
        all_subdomains = utilities.filter_subdomains(all_subdomains, argument)
        
        # Generate unique filenames
        resolved_name = utilities.generate_random_string()
        file_name = utilities.generate_random_string()
        
        # Save all resolved subdomains
        with open(f'data/hosts/{resolved_name}', 'w') as subdomains_file:
            subdomains_file.write('\n'.join(all_subdomains))
        
        # Update global tracking
        resolvedParser.resolvedWriter(Target=argument, fileName=f"{resolved_name}\n")
        resolvedItems[argument] = resolved_name
        
        # Check for live hosts with httpx
        await ctx.send("**Checking for live hosts with httpx...**")
        httpx_results = await run_subprocess(f"cat data/hosts/{resolved_name} | httpx -silent")
        
        # Save live subdomains
        with open(f'data/subdomains/{file_name}', 'w') as subdomains_file:
            subdomains_file.write(httpx_results)
        
        # Update global tracking
        logsParser.logsWriter(Target=argument, fileName=file_name)
        logsItems[argument] = file_name
        
        # Send results to user
        await send_output(ctx, httpx_results, None, f"Active subdomains collected for **{argument}**:")
    except Exception as e:
        await ctx.send(f"**Error collecting subdomains: {e}**")

@Client.command()
async def info(ctx, *, argument):
    """Get detailed information about live subdomains"""
    global logsItems
    
    if not argument:
        await ctx.send("**Please provide a domain to check.**")
        return
        
    try:
        # Check if subdomains have been collected
        if argument not in logsItems:
            await ctx.send("**There are no subdomains collected for this target. Please use** `.subdomains [TARGET]` **first.**")
            return
            
        subdomains_file = logsItems[argument]
        
        # Verify the file exists
        if not path.exists(f'data/subdomains/{subdomains_file}'):
            await ctx.send(f"**Error: Subdomain file not found. Please run** `.subdomains {argument}` **again.**")
            return
            
        await ctx.send(f"**Collecting information about subdomains for {argument}...**")
        
        results, error = run_command_safely(
            f"cat data/subdomains/{subdomains_file} | httpx -title -web-server -status-code -follow-redirects -silent", 
            shell=True
        )
        
        if error:
            await ctx.send(f"**Error getting subdomain info: {error}**")
            return
            
        # Process results
        results = utilities.remove_escape_sequences(results or "")
        
        await send_output(ctx, results, None, f"Subdomains information for **{argument}**:")
    except Exception as e:
        await ctx.send(f"**Error getting subdomain info: {e}**")

@Client.command()
async def nuclei(ctx, *, argument):
    """Scan subdomains with nuclei for vulnerabilities"""
    global logsItems
    
    if not argument:
        await ctx.send("**Please provide a domain to scan.**")
        return
        
    try:
        # Check if subdomains have been collected
        if argument not in logsItems:
            await ctx.send("**There are no subdomains collected for this target. Please use** `.subdomains [TARGET]` **first.**")
            return
            
        subdomains_file = logsItems[argument]
        nuclei_templates = TOOLS.get('nuclei-templates')
        
        if not nuclei_templates or not path.exists(nuclei_templates):
            await ctx.send("**Nuclei templates not found. Please check your settings.**")
            return
            
        await ctx.send(f"**Scanning {argument} for possible issues using Nuclei...**")
        
        # Prepare command based on settings
        if DISABLE_NUCLEI_INFO:
            cmd = f"nuclei -l data/subdomains/{subdomains_file} -t ~/nuclei-templates -silent | grep -v 'info.*\\]' | python3 notify.py --mode 0 --discord-webhook {NUCLEI_WEBHOOK}"
        else:
            cmd = f"nuclei -l data/subdomains/{subdomains_file} -t ~/nuclei-templates -silent | python3 notify.py --mode 0 --discord-webhook {NUCLEI_WEBHOOK}"
        
        # Run asynchronously
        subprocess.Popen(cmd, shell=True, stdin=None, stdout=None, stderr=None, close_fds=True)
        
        await ctx.send("**Results will be sent to the nuclei webhook channel**")
    except Exception as e:
        await ctx.send(f"**Error running Nuclei: {e}**")

@Client.command()
async def subjack(ctx, *, argument):
    """Check for subdomain takeover with Subjack"""
    global resolvedItems
    
    if not argument:
        await ctx.send("**Please provide a domain to scan.**")
        return
        
    # Sanitize input to prevent command injection
    argument = CommandInjection.sanitizeInput(argument)
    
    try:
        # Check if subdomains have been collected
        if argument not in resolvedItems:
            await ctx.send("**There are no subdomains collected for this target. Please use** `.subdomains [TARGET]` **first.**")
            return
            
        resolved_file = resolvedItems[argument]
        file_str = utilities.generate_random_string()
        
        # Verify the file exists
        if not path.exists(f'data/hosts/{resolved_file}'):
            await ctx.send(f"**Error: Resolved hosts file not found. Please run** `.subdomains {argument}` **again.**")
            return
            
        await ctx.send(f"**Scanning {argument} for possible subdomain takeover issues using Subjack...**")
        
        # Run command asynchronously
        cmd = f"subjack -w data/hosts/{resolved_file} -t 100 -timeout 30 -o data/subjack/{argument}-{file_str}.subjack -ssl | python3 notify.py --mode 1 -m 'Subjack results:' -f '- {ctx.message.author}'"
        subprocess.Popen(cmd, shell=True, stdin=None, stdout=None, stderr=None, close_fds=True)
        
        await ctx.send("**Results will be sent to the results channel soon**")
    except Exception as e:
        await ctx.send(f"**Error running Subjack: {e}**")

@Client.command()
async def subjs(ctx, *, argument):
    """Extract JavaScript files from subdomains"""
    global logsItems
    
    if not argument:
        await ctx.send("**Please provide a domain to scan.**")
        return
        
    # Sanitize input to prevent command injection
    argument = CommandInjection.sanitizeInput(argument)
    
    try:
        # Check if subdomains have been collected
        if argument not in logsItems:
            await ctx.send("**There are no subdomains collected for this target. Please use** `.subdomains [TARGET]` **first.**")
            return
            
        subdomains_file = logsItems[argument]
        
        # Verify the file exists
        if not path.exists(f'data/subdomains/{subdomains_file}'):
            await ctx.send(f"**Error: Subdomain file not found. Please run** `.subdomains {argument}` **again.**")
            return
            
        await ctx.send(f"**Extracting JavaScript files from {argument} using Subjs...**")
        
        # Run command asynchronously
        cmd = f"cat data/subdomains/{subdomains_file} | subjs | python3 notify.py --mode 1 -m 'Subjs results:' -f '- {ctx.message.author}'"
        subprocess.Popen(cmd, shell=True, stdin=None, stdout=None, stderr=None, close_fds=True)
        
        await ctx.send("**Results will be sent to the results channel soon**")
    except Exception as e:
        await ctx.send(f"**Error running Subjs: {e}**")

@Client.command()
async def smuggler(ctx, *, argument):
    """Check for HTTP request smuggling vulnerabilities"""
    global logsItems
    
    if not argument:
        await ctx.send("**Please provide a domain or URL to scan.**")
        return
        
    # Sanitize input to prevent command injection
    argument = CommandInjection.sanitizeInput(argument)
    
    try:
        # Get smuggler tool path
        smuggler_path = TOOLS.get('smuggler')
        if not smuggler_path or not path.exists(smuggler_path):
            await ctx.send("**Smuggler tool not found. Please check your settings.**")
            return
            
        await ctx.send(f"**Scanning {argument} for HTTP request smuggling issues using Smuggler...**")
        
        # Determine command based on input format
        if "http:" in argument or "https:" in argument:
            cmd = f"echo {argument} | python3 {smuggler_path}/smuggler.py"
        else:
            # Check if subdomains have been collected
            if argument not in logsItems:
                await ctx.send("**There are no subdomains collected for this target. Please use** `.subdomains [TARGET]` **first.**")
                return
                
            subdomains_file = logsItems[argument]
            cmd = f"cat data/subdomains/{subdomains_file} | python3 ~/discord/discord-recon/tools/smuggler/smuggler.py"
        
        # Run command
        results, error = run_command_safely(cmd, shell=True)
        
        if error:
            await ctx.send(f"**Error running Smuggler: {error}**")
            return
            
        # Process results
        results = utilities.remove_escape_sequences(results or "")
        
        await send_output(ctx, results, None, f"Smuggler Results for **{argument}**:")
    except Exception as e:
        await ctx.send(f"**Error running Smuggler: {e}**")

#----- EVENT HANDLERS -----#

@Client.event
async def on_command_error(ctx, error):
    """Handle command errors"""
    if isinstance(error, commands.CommandNotFound):
        await ctx.send("**Invalid command. Please type** `.help` **to see the list of available commands.**")
    elif isinstance(error, commands.MissingRequiredArgument):
        await ctx.send(f"**Missing required argument: {error.param}. Please check the command syntax.**")
    elif isinstance(error, (commands.MissingRole, commands.MissingAnyRole)):
        await ctx.send("**You don't have permission to use this command. Required role is missing.**")
    elif isinstance(error, commands.BadArgument):
        await ctx.send("**Invalid argument type. Please check the command syntax.**")
    elif isinstance(error, commands.CommandOnCooldown):
        await ctx.send(f"**Command is on cooldown. Try again in {error.retry_after:.2f} seconds.**")
    elif isinstance(error, (commands.DisabledCommand, commands.NoPrivateMessage)):
        await ctx.send("**This command cannot be used in this context.**")
    else:
        await ctx.send(f"**An error occurred: {error}**")
        print(f"Command error: {error}")

@Client.event
async def on_command(ctx):
    """Log all command executions"""
    try:
        current_date = datetime.now()
        formatted_date = current_date.strftime("%Y/%m/%d")
        utilities.log_command(ctx.command, ctx.author, formatted_date, ctx.message.content)
    except Exception as e:
        print(f"Error logging command: {e}")

@Client.event
async def on_member_join(member):
    """Send welcome message to new members"""
    try:
        welcome_message = """```    
Welcome to Discord-Recon, your go-to Discord bot designed to assist bug bounty hunters in streamlining their reconnaissance process through simple commands. Whether you prefer using the bot within your server or privately in this chat, the choice is yours.

If you're interested in hosting your own Discord-Recon server, feel free to explore the source code at https://github.com/DEMON1A/Discord-Recon. Donations are appreciated but not mandatory; they go towards server upgrades and covering the bot's hosting expenses. Contribute if you can, and thank you for being part of our community!
        ```"""
        await member.send(welcome_message)
    except discord.Forbidden:
        # Cannot send DM to the user
        admin_channel = Client.get_channel(ADMIN_CHANNEL)
        if admin_channel:
            await admin_channel.send(f"**Unable to send welcome message to {member.name}#{member.discriminator}**")
    except Exception as e:
        print(f"Error sending welcome message: {e}")

@Client.event
async def on_member_remove(member):
    """Notify admins when a member leaves"""
    try:
        admin_channel = Client.get_channel(ADMIN_CHANNEL)
        if admin_channel:
            await admin_channel.send(f"**{member.name}#{member.discriminator}** either left the server or was removed.")
    except Exception as e:
        print(f"Error handling member remove: {e}")

@Client.event
async def on_ready():
    """Handle bot startup"""
    try:
        admin_channel = Client.get_channel(ADMIN_CHANNEL)
        if not admin_channel:
            print(f"WARNING: Admin channel {ADMIN_CHANNEL} not found!")
            return
            
        current_date = datetime.now()
        formatted_date = current_date.strftime("%Y/%m/%d")

        # Get system information
        memory_usage = psutil.virtual_memory().percent
        cpu_usage = psutil.cpu_percent(interval=1)
        disk_usage = psutil.disk_usage('/').percent

        message = (
            f"**ReconServer Started** :dizzy:\n\n"
            f"Operating on: **{formatted_date}**\n"
            f"Memory Usage: **{memory_usage}%**\n"
            f"CPU Usage: **{cpu_usage}**%\n"
            f"Disk Usage: **{disk_usage}**%\n\n"
            f"Connected to Discord API as: **{Client.user.name}#{Client.user.discriminator}**\n"
            f"Serving **{len(Client.guilds)}** servers with **{len(Client.commands)}** commands"
        )

        await admin_channel.send(message)
        
        # Set bot status
        await Client.change_presence(activity=discord.Activity(type=discord.ActivityType.listening, name=f"{COMMANDS_PREFIX}help"))
        
        print(f"Bot started successfully as {Client.user.name}#{Client.user.discriminator}")
    except Exception as e:
        print(f"Error in on_ready: {e}")

#----- CUSTOM HELP COMMAND -----#

@Client.command(name="commands")
async def show_commands(ctx, command_name=None):
    """Display help information for all commands"""
    if command_name:
        # Show help for a specific command
        command = Client.get_command(command_name)
        if not command:
            await ctx.send(f"**Command '{command_name}' not found. Type** `.commands` **to see all available commands.**")
            return
            
        # Check if user has permission to use this command
        if isinstance(command.checks, list) and any(check.__qualname__.startswith('has_role') for check in command.checks):
            if not ctx.author.guild_permissions.administrator and not any(role.name == ADMIN_ROLE for role in ctx.author.roles):
                await ctx.send(f"**The command** `.{command_name}` **requires the {ADMIN_ROLE} role.**")
                return
                
        embed = discord.Embed(
            title=f"Help: {COMMANDS_PREFIX}{command_name}",
            description=command.help or "No description available.",
            color=discord.Color.blue()
        )
        
        usage = f"{COMMANDS_PREFIX}{command_name}"
        if command.signature:
            usage += f" {command.signature}"
            
        embed.add_field(name="Usage", value=f"`{usage}`", inline=False)
        
        await ctx.send(embed=embed)
    else:
        # Show all commands grouped by category
        embed = discord.Embed(
            title="Discord Recon Bot - Command Help",
            description="Below is a list of available commands. Type `.commands <command>` for more details on a specific command.",
            color=discord.Color.blue()
        )
        
        # Get all command categories
        admin_commands = []
        recon_commands = []
        tool_commands = []
        utility_commands = []
        
        for command in Client.commands:
            # Skip if user can't use the command
            if isinstance(command.checks, list) and any(check.__qualname__.startswith('has_role') for check in command.checks):
                if not ctx.author.guild_permissions.administrator and not any(role.name == ADMIN_ROLE for role in ctx.author.roles):
                    continue
            
            # Categorize commands
            if command.name in ['exec', 'sudo', 'unsudo', 'shutdown', 'restart', 'history', 'show', 'count']:
                admin_commands.append(command.name)
            elif command.name in ['subdomains', 'info', 'nuclei', 'subjack', 'subjs', 'smuggler']:
                recon_commands.append(command.name)
            elif command.name in ['dirsearch', 'arjun', 'waybackurls', 'subfinder', 'assetfinder', 'findomain', 'paramspider', 'gitls']:
                tool_commands.append(command.name)
            else:
                utility_commands.append(command.name)
        
        # Add fields for each category
        if admin_commands and (ctx.author.guild_permissions.administrator or any(role.name == ADMIN_ROLE for role in ctx.author.roles)):
            embed.add_field(
                name="Admin Commands",
                value="`" + "`, `".join(sorted(admin_commands)) + "`",
                inline=False
            )
            
        if recon_commands:
            embed.add_field(
                name="Recon Commands",
                value="`" + "`, `".join(sorted(recon_commands)) + "`",
                inline=False
            )
            
        if tool_commands:
            embed.add_field(
                name="Tool Commands",
                value="`" + "`, `".join(sorted(tool_commands)) + "`",
                inline=False
            )
            
        if utility_commands:
            embed.add_field(
                name="Utility Commands",
                value="`" + "`, `".join(sorted(utility_commands)) + "`",
                inline=False
            )
        
        embed.set_footer(text="Discord-Recon Bot - https://github.com/kdairatchi/Discord-Recon")
        
        await ctx.send(embed=embed)

# Run the bot
if __name__ == "__main__":
    # Start the bot
    try:
        Client.run(DISCORD_TOKEN)
    except discord.LoginFailure:
        print("Error: Invalid Discord token. Please check your settings.")
    except Exception as e:
        print(f"Error starting bot: {e}")
                                                                                       
┌──(root㉿kali)-[~/discord/discord-recon]
└─# 
