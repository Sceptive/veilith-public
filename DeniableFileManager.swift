//
//  DeniableFileManager.swift
//  Veilith
//
//  Created by marcus on 14.07.2025.
//




import Foundation
import Sodium

class DeniableFileManager {
    static let shared = DeniableFileManager()

    private let sodium = Sodium()
    public  let blockSize = 8192
    public  let fileBlockCount = 64
    public  let saltSize = 16
    public  let totalSalts = 64 // Always generate exactly 64 salts
    private let isDebugMode = true
    public  let hmacKeySize = 32
    public  let hmacSize = 32
    public  let deviceIntegrityHMACSize = 32
    
    private let deviceIntegrityManager = DeviceIntegrityManager.shared

    private func debugPrint(_ message: String) {
        if isDebugMode {
            print(message)
        }
    }

    // MARK: - Device Integrity Check
    
    public enum IntegrityStatus {
        case valid
        case invalidDevice  // File was created/modified on different device
        case invalidPassword // Wrong password
        case corrupted      // File tampered or corrupted
    }
    
    public func verifyDeviceIntegrity(file: Data) -> (isValid: Bool, message: String) {
        guard let deviceKey = deviceIntegrityManager.getDeviceIntegrityKey() else {
            return (false, "No device key available")
        }
        
        let expectedMinSize = deviceIntegrityHMACSize + (totalSalts * saltSize) + blockSize
        guard file.count > expectedMinSize else {
            return (false, "File too small")
        }
        
        // Extract device HMAC (first 32 bytes)
        let storedDeviceHMAC = file.prefix(deviceIntegrityHMACSize)
        
        // Get the rest of the file (everything after device HMAC)
        let contentWithoutDeviceHMAC = file.dropFirst(deviceIntegrityHMACSize)
        
        // Compute expected device HMAC
        guard let computedHMAC = computeHMAC(data: contentWithoutDeviceHMAC, key: [UInt8](deviceKey)) else {
            return (false, "Failed to compute device HMAC")
        }
        
        if storedDeviceHMAC == computedHMAC {
            return (true, "Valid")
        } else {
            return (false, "Device HMAC mismatch - file was created/modified on different device")
        }
    }
    
    // MARK: - HMAC Helpers
    
    private func deriveHMACKey(password: String, salt: Data) -> Bytes? {
        var passwordBytes = Array(password.utf8)
        defer { secureZero(&passwordBytes) }

        return sodium.pwHash.hash(outputLength: hmacKeySize,
                                  passwd: passwordBytes,
                                  salt: [UInt8](salt),
                                  opsLimit: sodium.pwHash.OpsLimitInteractive,
                                  memLimit: sodium.pwHash.MemLimitInteractive,
                                  alg: .Argon2ID13)
    }
    
    private func computeHMAC(data: Data, key: Bytes) -> Data? {
        guard let hmac = sodium.auth.tag(message: [UInt8](data), secretKey: key) else { return nil }
        return Data(hmac)
    }
    
    private func verifyHMAC(data: Data, tag: Data, key: Bytes) -> Bool {
        return sodium.auth.verify(message: [UInt8](data), secretKey: key, tag: [UInt8](tag))
    }
    
    private func cryptoSecureRandom(in range: Range<Int>) -> Int {
        let count = range.count
        let randomBytes = sodium.randomBytes.buf(length: 4)!
        let randomValue = randomBytes.withUnsafeBytes { $0.load(as: UInt32.self) }
        return range.lowerBound + Int(randomValue % UInt32(count))
    }

    private func secureZero(_ data: inout Data) {
        let _ = data.withUnsafeMutableBytes { bytes in
            memset_s(bytes.baseAddress, bytes.count, 0, bytes.count)
        }
    }

    private func secureZero(_ array: inout [UInt8]) {
        let _ = array.withUnsafeMutableBytes { bytes in
            memset_s(bytes.baseAddress, bytes.count, 0, bytes.count)
        }
    }
    
    // MARK: - File Creation

    func createFile(entries: [(password: String, message: String)]) -> Data? {
        guard let deviceKey = deviceIntegrityManager.getDeviceIntegrityKey() else {
            debugPrint("Failed to get device integrity key")
            return nil
        }
        
        var salts: [Data] = []
        var blocks: [Data] = []
        var passwords: [String] = []
        
        // Pre-check: Ensure all messages can fit in blocks
        let maxMessageSize = getMaxMessageSize()
        debugPrint("Max msize: \(maxMessageSize)")
        
        for (index, entry) in entries.enumerated() {
            guard entry.message.utf8.count <= maxMessageSize else {
                debugPrint("Message \(index) too large: \(entry.message.utf8.count) bytes, max: \(maxMessageSize)")
                return nil
            }
        }

        // 1. Entries
        for entry in entries {
            guard let salt = randomSalt() else { return nil }
            debugPrint("Salt \(salt as NSData) \(entry.password) \(entry.message)")
            passwords.append(entry.password)
            salts.append(salt)
            if let key = deriveKey(password: entry.password, salt: salt),
               let block = encrypt(message: entry.message, key: key) {
                debugPrint(String(format: "Block size %d", block.count))
                blocks.append(block)
            }
        }

        // 2. Fill remaining salts with random data
        let remainingSalts = totalSalts - salts.count
        for _ in 0..<remainingSalts {
            guard let randomSalt = randomSalt() else { return nil }
            passwords.append("") // Empty password for random salts
            salts.append(randomSalt)
            //debugPrint("Random padding salt \(randomSalt as NSData)")
        }

        // 3. Prepare salt header (all 64 salts)
        var saltsData = Data()
        salts.shuffle()
        for salt in salts {
            saltsData.append(salt)
        }

        debugPrint(String(format: "Total Salts: %d (Real + Fake: %d, Random: %d)",
              salts.count, blocks.count, remainingSalts))

        // 4. Create randomized file blocks
        let totalBlocks = fileBlockCount
        var blocksData = Data(count: totalBlocks * blockSize)
        var usedIndexes = Set<Int>()

        // Place actual encrypted blocks randomly
        for block in blocks {
            var index: Int
            repeat {
                index = cryptoSecureRandom(in: 0..<totalBlocks)
            } while usedIndexes.contains(index)
            usedIndexes.insert(index)

            let offset = index * blockSize
            debugPrint(String(format: "Block Count: %d Size: %d", block.count, blockSize))

            let endOffset = min(offset + block.count, offset + blockSize)
            blocksData.replaceSubrange(offset..<endOffset, with: block.prefix(blockSize))
            
            debugPrint("Written block at index \(index): \(block as NSData)")
        }

        // Fill remaining blocks with random data
        for i in 0..<totalBlocks {
            if !usedIndexes.contains(i) {
                let offset = i * blockSize
                let randomBlock = Data(sodium.randomBytes.buf(length: blockSize)!)
                blocksData.replaceSubrange(offset..<offset + blockSize, with: randomBlock)
            }
        }

        let contentData = saltsData + blocksData
        // 5. Compute device integrity HMAC over everything
        guard let deviceHMAC = computeHMAC(data: contentData, key: [UInt8](deviceKey)) else {
            debugPrint("Failed to compute device HMAC")
            return nil
        }
        
        debugPrint("Device HMAC: \(deviceHMAC as NSData)")
        
        // Final file structure: [Device HMAC][Password HMACs][Salt Header][Encrypted Blocks]
        return deviceHMAC + contentData
    }

    // MARK: - File Decryption

    func decryptFile(file: Data, password: String,
                     ignoreDeviceIntegrity: Bool = false)
        -> (status: IntegrityStatus,
            saltIndex: Int,
            blockIndex: Int,
            message: String)? {
        // Check integrity first
        let (status, _) = verifyDeviceIntegrity(file: file)
        
        if status == false && ignoreDeviceIntegrity == false {
            return (.invalidDevice, 0, 0, "")
        }

        var foundResult: (IntegrityStatus, Int, Int, String) = (.invalidPassword,0,0,"")
        
        // Skip device HMAC for decryption
        let contentData = Data(file.dropFirst(deviceIntegrityHMACSize))
        let expectedHeaderSize = totalSalts * saltSize
        let expectedMinSize = expectedHeaderSize + blockSize
        guard contentData.count > expectedMinSize else { return (.corrupted,0,0,"") }

        // Extract all 64 salts from header
        let salts = (0..<totalSalts).map {
            contentData.subdata(in: ($0 * saltSize)..<(($0 + 1) * saltSize))
        }

        if isDebugMode {
            for (index, salt) in salts.enumerated() {
               // debugPrint("Decrypt Read salt \(index): \(salt as NSData)")
            }
        }

        let body = contentData.subdata(in: expectedHeaderSize..<contentData.count)

        // Always try ALL salts and blocks to prevent timing attacks
        for (saltIndex, salt) in salts.enumerated() {
            guard let key = deriveKey(password: password, salt: salt) else { continue }
            
            for blockIndex in stride(from: 0, to: body.count, by: blockSize).map({ $0 / blockSize }) {
                let offset = blockIndex * blockSize
                let block = body.subdata(in: offset..<min(offset + blockSize, body.count))
                
                if let message = decrypt(block: block, key: key) {
                    foundResult =  (.valid, saltIndex: saltIndex, blockIndex: blockIndex, message: message)
                }
            }
        }

        return foundResult
    }
    
    // MARK: - File Update

    func updateFile(file: Data, password: String, saltIndex: Int, blockIndex: Int, newMessage: String, allowDeviceChange: Bool = false) -> Data? {
        // Check current integrity
        //let (status, _) = checkIntegrity(file: file, password: password)
        let status = verifyDeviceIntegrity(file: file)
        
        if !status.isValid {
            if !allowDeviceChange {
                debugPrint("Cannot update: File was created/modified on different device. Set allowDeviceChange=true to force update.")
                return nil
            }
            debugPrint("Warning: Updating file from different device. Device integrity will be recalculated.")
        }
        
        
        guard let deviceKey = deviceIntegrityManager.getDeviceIntegrityKey() else {
            debugPrint("Failed to get device integrity key")
            return nil
        }
        
        // Skip device HMAC for processing
        var contentData = Data(file.dropFirst(deviceIntegrityHMACSize))
        
        let expectedHeaderSize = totalSalts * saltSize
        let expectedMinSize =  expectedHeaderSize + blockSize
        guard contentData.count > expectedMinSize else {
            debugPrint("Update failed: File size too small")
            return nil
        }

        // Verify message size
        let maxMessageSize = getMaxMessageSize()
        guard newMessage.utf8.count <= maxMessageSize else {
            debugPrint("New message too large: \(newMessage.utf8.count) bytes, max: \(maxMessageSize)")
            return nil
        }


        // Extract salts
        let salts = (0..<totalSalts).map {
            contentData.subdata(in: ($0 * saltSize)..<(($0 + 1) * saltSize))
        }
        
        // Verify salt index
        guard saltIndex >= 0 && saltIndex < totalSalts else {
            debugPrint("Invalid salt index: \(saltIndex)")
            return nil
        }
        
        // Generate new salt and encrypt new message
        guard let newSalt = randomSalt(),
              let newKey = deriveKey(password: password, salt: newSalt),
              let newBlock = encrypt(message: newMessage, key: newKey) else {
            debugPrint("Failed to encrypt new message")
            return nil
        }

        // Update salt in header
        contentData.replaceSubrange((saltIndex * saltSize)..<((saltIndex + 1) * saltSize), with: newSalt)

        // Update block
        let offset = expectedHeaderSize + (blockIndex * blockSize)
        guard offset + blockSize <= contentData.count else {
            debugPrint("Invalid block index: \(blockIndex)")
            return nil
        }
        contentData.replaceSubrange(offset..<offset + blockSize, with: newBlock)
            
        
        // Compute new device HMAC
        guard let newDeviceHMAC = computeHMAC(data: contentData, key: [UInt8](deviceKey)) else {
            debugPrint("Failed to compute new device HMAC")
            return nil
        }
        
        return newDeviceHMAC + contentData
    }
    

    
    
    /// For backward compatibility - calls checkIntegrity internally
 
    
    // MARK: - Size Validation
    
    func getMaxMessageSize() -> Int {
        return blockSize - sodium.aead.xchacha20poly1305ietf.NonceBytes - sodium.aead.xchacha20poly1305ietf.ABytes
    }
    
    func canFitMessage(_ message: String) -> Bool {
        return message.utf8.count <= getMaxMessageSize()
    }
    
    // MARK: - Export/Import Support
    
    /// Recalculates device integrity for imported files
    func recalculateDeviceIntegrity(file: Data, password: String) -> Data? {
        // First verify file has correct structure
        let expectedMinSize = deviceIntegrityHMACSize  + (totalSalts * saltSize) + blockSize
        guard file.count >= expectedMinSize else {
            debugPrint("Cannot recalculate device integrity: File too small")
            return nil
        }
        
        // Extract content after device HMAC (we don't care if device HMAC is valid)
        let fileWithoutDeviceHMAC = file.dropFirst(deviceIntegrityHMACSize)
        
        // Get current device key
        guard let deviceKey = deviceIntegrityManager.getDeviceIntegrityKey() else {
            debugPrint("Failed to get device integrity key")
            return nil
        }
        
        // Compute new device HMAC
        guard let newDeviceHMAC = computeHMAC(data: fileWithoutDeviceHMAC, key: [UInt8](deviceKey)) else {
            debugPrint("Failed to compute new device HMAC")
            return nil
        }
        
        return newDeviceHMAC + fileWithoutDeviceHMAC
    }
    
    // MARK: - Crypto Helpers

    private func randomSalt() -> Data? {
        guard let randomBytes = sodium.randomBytes.buf(length: saltSize) else {
            return nil
        }
        return Data(randomBytes)
    }

    private func deriveKey(password: String, salt: Data) -> Bytes? {
        let passwordBytes = Array(password.utf8)
        
        return sodium.pwHash.hash(outputLength: sodium.aead.xchacha20poly1305ietf.KeyBytes,
                                  passwd: passwordBytes,
                                  salt: [UInt8](salt),
                                  opsLimit: sodium.pwHash.OpsLimitInteractive,
                                  memLimit: sodium.pwHash.MemLimitInteractive,
                                  alg: .Argon2ID13)
    }

    private func encrypt(message: String, key: Bytes) -> Data? {
        var messageBytes = Array(message.utf8)
        defer { secureZero(&messageBytes) }

        guard let (encrypted, nonce) = sodium.aead.xchacha20poly1305ietf.encrypt(message: messageBytes,
                                                                                  secretKey: key) else { return nil }
        
        var block = Data()
        block.append(Data(nonce))
        block.append(Data(encrypted))

        guard block.count <= blockSize else {
            return nil
        }
        
        if block.count < blockSize {
            let padding = Data(count: blockSize - block.count)
            block.append(padding)
        }
        return block
    }
    
    private func decrypt(block: Data, key: Bytes) -> String? {
        let nonceSize = sodium.aead.xchacha20poly1305ietf.NonceBytes
        guard block.count >= nonceSize else { return nil }

        let nonce = [UInt8](block.prefix(nonceSize))
        let remainingData = block.dropFirst(nonceSize)
        
        let ciphertext: [UInt8]
        if let lastNonZero = remainingData.lastIndex(where: { $0 != 0 }) {
            ciphertext = [UInt8](remainingData.prefix(through: lastNonZero))
        } else {
            ciphertext = [UInt8](remainingData)
        }

        if let decrypted = sodium.aead.xchacha20poly1305ietf.decrypt(nonceAndAuthenticatedCipherText: [UInt8](Data(nonce + ciphertext)),
                                                                      secretKey: key) {
            return String(bytes: decrypted, encoding: .utf8)
        }
        return nil
    }
}
