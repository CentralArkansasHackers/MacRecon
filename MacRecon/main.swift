import Foundation
import ArgumentParser
import AppKit  // Add this for NSUserName

// MARK: - Main Command
struct MacRecon: ParsableCommand {
    static var configuration = CommandConfiguration(
        commandName: "macrecon",
        abstract: "A stealthy macOS reconnaissance and privilege escalation tool.",
        subcommands: [
            SystemInfo.self,
            SecurityTools.self,
            LaunchItems.self,
            NetworkInfo.self,
            PrivEscCheck.self,
            RunAll.self
        ],
        defaultSubcommand: RunAll.self
    )
    
    // Common options that apply to all subcommands
    struct CommonOptions: ParsableArguments {
        @Flag(name: .long, help: "Run quietly with minimal output")
        var quiet: Bool = false
        
        @Option(name: .long, help: "Path to save the encrypted report")
        var output: String?
        
        @Option(name: .long, help: "Encryption key for the report (if not provided, a random key will be used)")
        var encryptionKey: String?
        
        @Flag(name: .long, help: "Use extra stealth techniques (slower but harder to detect)")
        var extraStealth: Bool = false
    }
}

// MARK: - Subcommands
extension MacRecon {
    // System info command
    struct SystemInfo: ParsableCommand {
        static var configuration = CommandConfiguration(
            commandName: "sysinfo",
            abstract: "Gather comprehensive system information"
        )
        
        @OptionGroup var options: CommonOptions
        
        func run() throws {
            // Apply random delay if extra stealth requested
            if options.extraStealth {
                usleep(UInt32.random(in: 50000...200000)) // 50-200ms
            }
            
            // Run stealth utilities to randomize memory pattern
            StealthUtils.randomizedMemoryAccess()
            
            // Check if being debugged
            if StealthUtils.isBeingDebugged() {
                if !options.quiet {
                    print("[WARNING] Debugging detected. Exiting...")
                }
                return
            }
            
            if !options.quiet {
                print("Gathering system information...")
            }
            
            let sysInfo = SystemInfoGatherer()
            let info = sysInfo.gatherBasicInfo()
            
            // Display results if not in quiet mode
            if !options.quiet {
                printSystemInfo(info)
            }
            
            // Generate report
            if let outputPath = options.output {
                // We'll implement report generation later
                print("Report saved to \(outputPath)")
            }
        }
        
        // Helper to print system info in a readable format
        private func printSystemInfo(_ info: SystemInformation) {
            print("\n=== System Information ===")
            print("Hostname: \(info.hostname)")
            print("macOS Version: \(info.osVersion)")
            print("Build: \(info.buildVersion)")
            print("Kernel: \(info.kernelVersion)")
            print("Uptime: \(formatUptime(info.uptime))")
            print("Boot Time: \(formatDate(info.bootTime))")
            
            print("\n=== User Information ===")
            print("Current User: \(info.currentUser) (UID: \(info.userID))")
            print("Admin Status: \(info.isAdmin ? "Administrator" : "Standard User")")
            print("Admin Users: \(info.adminUsers.joined(separator: ", "))")
            
            print("\n=== Security Status ===")
            print("Full Disk Access: \(info.isFullDiskAccessGranted ? "Granted" : "Not Granted")")
            print("SIP Status: \(info.isSIPEnabled ? "Enabled" : "Disabled")")
            print("Screen Locked: \(info.screenLocked ? "Yes" : "No")")
            print("Virtual Machine: \(info.isVirtualMachine ? "Yes" : "No")")
            
            if !info.securityToolsRunning.isEmpty {
                print("\n=== Security Tools Detected ===")
                for tool in info.securityToolsRunning {
                    print("- \(tool)")
                }
            }
            
            print("\n=== Network Information ===")
            for (interface, ip) in info.ipAddresses {
                let mac = info.macAddresses[interface] ?? "Unknown"
                print("\(interface): \(ip) (\(mac))")
            }
            
            if let ssid = info.wifiSSID {
                print("Wi-Fi SSID: \(ssid)")
            }
            
            print("DNS Servers: \(info.dnsServers.joined(separator: ", "))")
            
            if info.domainInfo.inDomain {
                print("\n=== Domain Status ===")
                print("Domain: \(info.domainInfo.domainName ?? "Unknown")")
            }
            
            if info.isMDMEnrolled {
                print("\n=== MDM Enrollment ===")
                print("MDM Enrolled: Yes")
                for profile in info.mdmProfiles {
                    print("- \(profile)")
                }
            }
        }
        
        // Format uptime in a readable way
        private func formatUptime(_ uptime: TimeInterval) -> String {
            let days = Int(uptime) / 86400
            let hours = (Int(uptime) % 86400) / 3600
            let minutes = (Int(uptime) % 3600) / 60
            
            var result = ""
            if days > 0 { result += "\(days)d " }
            if hours > 0 { result += "\(hours)h " }
            result += "\(minutes)m"
            
            return result
        }
        
        // Format date in a readable way
        private func formatDate(_ date: Date) -> String {
            let formatter = DateFormatter()
            formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
            return formatter.string(from: date)
        }
    }
    
    // Security tools detection command
    struct SecurityTools: ParsableCommand {
        static var configuration = CommandConfiguration(
            commandName: "securitytools",
            abstract: "Detect security and monitoring tools"
        )
        
        @OptionGroup var options: CommonOptions
        
        func run() throws {
            if options.extraStealth {
                usleep(UInt32.random(in: 50000...200000))
            }
            
            if !options.quiet {
                print("Detecting security tools...")
            }
            
            let securityTools = StealthUtils.detectSecurityTools()
            let analysisTools = StealthUtils.checkForAnalysisTools()
            let isVM = StealthUtils.isRunningInVM()
            let isDebugged = StealthUtils.isBeingDebugged()
            let suspiciousEnvVars = StealthUtils.checkForSuspiciousEnvVars()
            
            if !options.quiet {
                printSecurityToolsInfo(
                    securityTools: securityTools,
                    analysisTools: analysisTools,
                    isVM: isVM,
                    isDebugged: isDebugged,
                    suspiciousEnvVars: suspiciousEnvVars
                )
            }
        }
        
        // Helper to print security tools info
        private func printSecurityToolsInfo(securityTools: [String], analysisTools: [String], isVM: Bool, isDebugged: Bool, suspiciousEnvVars: [String]) {
            print("\n=== Security Environment Analysis ===")
            
            if securityTools.isEmpty {
                print("No security tools detected")
            } else {
                print("Security tools detected:")
                for tool in securityTools {
                    print("- \(tool)")
                }
            }
            
            if !analysisTools.isEmpty {
                print("\nAnalysis/debugging tools detected:")
                for tool in analysisTools {
                    print("- \(tool)")
                }
            }
            
            print("\nVirtual Machine: \(isVM ? "Yes" : "No")")
            print("Being Debugged: \(isDebugged ? "Yes" : "No")")
            
            if !suspiciousEnvVars.isEmpty {
                print("\nSuspicious environment variables:")
                for varName in suspiciousEnvVars {
                    print("- \(varName)")
                }
            }
        }
    }
    
    // Launch items command
    struct LaunchItems: ParsableCommand {
        static var configuration = CommandConfiguration(
            commandName: "launchitems",
            abstract: "Enumerate launch agents and daemons"
        )
        
        @OptionGroup var options: CommonOptions
        
        func run() throws {
            if options.extraStealth {
                usleep(UInt32.random(in: 70000...250000))
            }
            
            if !options.quiet {
                print("Enumerating launch items...")
            }
            
            let launchItems = StealthUtils.getLaunchItems()
            
            if !options.quiet {
                printLaunchItems(launchItems)
            }
        }
        
        // Helper to print launch items
        private func printLaunchItems(_ items: [String: [String]]) {
            print("\n=== Launch Agents and Daemons ===")
            
            for (path, files) in items {
                if !files.isEmpty {
                    print("\nIn \(path):")
                    for file in files {
                        print("- \(file)")
                    }
                }
            }
        }
    }
    
    // Network information command
    struct NetworkInfo: ParsableCommand {
        static var configuration = CommandConfiguration(
            commandName: "netinfo",
            abstract: "Gather network information"
        )
        
        @OptionGroup var options: CommonOptions
        
        func run() throws {
            if options.extraStealth {
                usleep(UInt32.random(in: 30000...150000))
            }
            
            if !options.quiet {
                print("Gathering network information...")
            }
            
            // We'll use the network information from SystemInfoGatherer
            let sysInfo = SystemInfoGatherer()
            let info = sysInfo.gatherBasicInfo()
            
            if !options.quiet {
                printNetworkInfo(info)
            }
        }
        
        // Helper to print network info
        private func printNetworkInfo(_ info: SystemInformation) {
            print("\n=== Network Interfaces ===")
            for (interface, ip) in info.ipAddresses {
                let mac = info.macAddresses[interface] ?? "Unknown"
                print("\(interface): \(ip) (\(mac))")
            }
            
            if let ssid = info.wifiSSID {
                print("\nWi-Fi SSID: \(ssid)")
            }
            
            print("\n=== DNS Configuration ===")
            print("DNS Servers: \(info.dnsServers.joined(separator: ", "))")
            
            print("\n=== Remote Access ===")
            print("SSH Enabled: \(info.isRemoteLoginEnabled ? "Yes" : "No")")
            
            if info.domainInfo.inDomain {
                print("\n=== Domain Information ===")
                print("Domain: \(info.domainInfo.domainName ?? "Unknown")")
            }
        }
    }
    
    // Privilege escalation check command
    struct PrivEscCheck: ParsableCommand {
        static var configuration = CommandConfiguration(
            commandName: "privesc",
            abstract: "Check for privilege escalation opportunities"
        )
        
        @OptionGroup var options: CommonOptions
        
        func run() throws {
            if options.extraStealth {
                usleep(UInt32.random(in: 100000...300000))
            }
            
            if !options.quiet {
                print("Checking for privilege escalation opportunities...")
            }
            
            // Check for world-writable files in sensitive directories
            let sensitiveDirs = [
                "/Applications",
                "/Library/LaunchAgents",
                "/Library/LaunchDaemons",
                "/usr/local/bin",
                "/usr/local/sbin"
            ]
            
            let worldWritableFiles = StealthUtils.findWorldWritableFiles(in: sensitiveDirs)
            let pathHijackInfo = StealthUtils.checkPathHijack()
            
            if !options.quiet {
                printPrivEscFindings(
                    worldWritableFiles: worldWritableFiles,
                    pathHijack: pathHijackInfo
                )
            }
        }
        
        // Helper to print privesc findings
        private func printPrivEscFindings(worldWritableFiles: [String], pathHijack: (vulnerable: Bool, writableDirs: [String])) {
            print("\n=== Privilege Escalation Opportunities ===")
            
            if !worldWritableFiles.isEmpty {
                print("\nWorld-writable files in sensitive locations:")
                for file in worldWritableFiles {
                    print("- \(file)")
                }
                print("\nThese files could potentially be modified to execute arbitrary code with elevated privileges.")
            } else {
                print("No world-writable files found in sensitive locations.")
            }
            
            if pathHijack.vulnerable {
                print("\nPATH Hijacking vulnerability detected!")
                print("The following directories in PATH are writable:")
                for dir in pathHijack.writableDirs {
                    print("- \(dir)")
                }
                print("\nYou can potentially hijack commands by placing malicious executables in these directories.")
            } else {
                print("\nNo PATH hijacking opportunities found.")
            }
            
            // Check if current user can sudo
            if StealthUtils.isProcessAdmin() {
                print("\nCurrently running with admin privileges!")
            } else {
                let adminUsers = StealthUtils.getAdminUsers()
                if adminUsers.contains(NSUserName()) {
                    print("\nCurrent user has sudo privileges. Can escalate with password.")
                } else {
                    print("\nCurrent user does not have sudo privileges.")
                }
            }
        }
    }
    
    // Command to run all modules
    struct RunAll: ParsableCommand {
        static var configuration = CommandConfiguration(
            commandName: "all",
            abstract: "Run all reconnaissance and privilege escalation checks"
        )
        
        @OptionGroup var options: CommonOptions
        
        @Flag(name: .long, help: "Skip privilege escalation checks")
        var skipPrivEsc: Bool = false
        
        @Flag(name: .long, help: "Include browser history in report")
        var includeBrowserHistory: Bool = false
        
        @Flag(name: .long, help: "Self-delete after execution")
        var selfDelete: Bool = false
        
        func run() throws {
            // Add random delay if in extra stealth mode
            if options.extraStealth {
                usleep(UInt32.random(in: 100000...500000)) // 100-500ms
            }
            
            // Check for debugging/analysis
            if StealthUtils.isBeingDebugged() {
                if !options.quiet {
                    print("[WARNING] Debugging detected. Proceeding with limited functionality.")
                }
                // We continue anyway but could add evasion here
            }
            
            if !options.quiet {
                print("MacRecon starting full reconnaissance...")
            }
            
            // 1. Run system information gathering
            if !options.quiet {
                print("\nRunning system information gathering...")
            }
            
            let sysInfo = SystemInfoGatherer()
            let systemInfo = sysInfo.gatherBasicInfo()
            
            // 2. Detect security tools
            if !options.quiet {
                print("\nDetecting security tools and environment...")
            }
            
            let securityTools = StealthUtils.detectSecurityTools()
            let analysisTools = StealthUtils.checkForAnalysisTools()
            let isVM = StealthUtils.isRunningInVM()
            
            // 3. Check launch items
            if !options.quiet {
                print("\nEnumerating launch agents and daemons...")
            }
            
            let launchItems = StealthUtils.getLaunchItems()
            
            // 4. Run privilege escalation checks if not skipped
            var privEscResults: (worldWritable: [String], pathHijack: (Bool, [String])) = ([], (false, []))
            if !skipPrivEsc {
                if !options.quiet {
                    print("\nRunning privilege escalation checks...")
                }
                
                // Define sensitive directories
                let sensitiveDirs = [
                    "/Applications",
                    "/Library/LaunchAgents",
                    "/Library/LaunchDaemons",
                    "/usr/local/bin",
                    "/usr/local/sbin"
                ]
                
                // Check for world-writable files
                let worldWritableFiles = StealthUtils.findWorldWritableFiles(in: sensitiveDirs)
                
                // Check for PATH hijacking opportunities
                let pathHijackInfo = StealthUtils.checkPathHijack()
                
                privEscResults = (worldWritableFiles, pathHijackInfo)
            }
            
            // 5. Generate report
            if !options.quiet {
                print("\nGenerating report...")
            }
            
            // We'll implement full reporting later
            // For now, just display results
            if !options.quiet {
                // Print system info
                print("\n=== System Information ===")
                print("Hostname: \(systemInfo.hostname)")
                print("macOS Version: \(systemInfo.osVersion) (Build \(systemInfo.buildVersion))")
                print("Kernel: \(systemInfo.kernelVersion)")
                print("Current User: \(systemInfo.currentUser) (UID: \(systemInfo.userID))")
                print("Admin Status: \(systemInfo.isAdmin ? "Administrator" : "Standard User")")
                
                // Print security status
                print("\n=== Security Status ===")
                print("SIP Status: \(systemInfo.isSIPEnabled ? "Enabled" : "Disabled")")
                print("Full Disk Access: \(systemInfo.isFullDiskAccessGranted ? "Granted" : "Not Granted")")
                
                // Print detected security tools
                if !securityTools.isEmpty {
                    print("\n=== Security Tools Detected ===")
                    for tool in securityTools {
                        print("- \(tool)")
                    }
                }
                
                // Print privilege escalation opportunities
                if !skipPrivEsc {
                    print("\n=== Privilege Escalation Opportunities ===")
                    
                    if !privEscResults.worldWritable.isEmpty {
                        print("\nWorld-writable files in sensitive locations:")
                        for file in privEscResults.worldWritable {
                            print("- \(file)")
                        }
                    } else {
                        print("No world-writable files found in sensitive locations.")
                    }
                    
                    if privEscResults.pathHijack.0 {
                        print("\nPATH Hijacking vulnerability detected!")
                        print("The following directories in PATH are writable:")
                        for dir in privEscResults.pathHijack.1 {
                            print("- \(dir)")
                        }
                    }
                }
            }
            
            // Output to file if specified
            if let outputPath = options.output {
                // We'll implement report generation and encryption later
                print("Report saved to \(outputPath)")
            }
            
            // Self-delete if requested (will need to implement later)
            if selfDelete {
                if !options.quiet {
                    print("\nSelf-deleting...")
                }
                // Implement self-deletion logic
            }
            
            if !options.quiet {
                print("\nMacRecon completed successfully.")
            }
        }
    }
}

// MARK: - Main execution
MacRecon.main()
