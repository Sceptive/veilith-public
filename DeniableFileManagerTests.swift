//
//  DeniableFileManagerTests.swift
//  Veilith
//
//  Created by marcus on 14.07.2025.
//


import XCTest
import Foundation
import Sodium
@testable import Veilith


class DeniableFileManagerTests: XCTestCase {
    
    var fileManager: DeniableFileManager!
    var deviceIntegrityManager: DeviceIntegrityManager!
    
    override func setUp() {
        super.setUp()
        fileManager = DeniableFileManager.shared
        deviceIntegrityManager = DeviceIntegrityManager.shared
        
        // Ensure we have a device key for testing
        _ = deviceIntegrityManager.getDeviceIntegrityKey()
    }
    
    override func tearDown() {
        fileManager = nil
        deviceIntegrityManager = nil
        super.tearDown()
    }
    
    // MARK: - Device Integrity Tests
    
    func testDeviceIntegrityOnFileCreation() {
        // Given
        let password = "testPassword"
        let message = "Test message"
        
        // When
        let fileData = fileManager.createFile(entries: [(password, message)])
        
        // Then
        XCTAssertNotNil(fileData)
        
        // Verify device integrity
        let result = fileManager.verifyDeviceIntegrity(file: fileData!)
        XCTAssertTrue(result.isValid, "File should have valid device integrity when created")
    }
    
    func testDeviceIntegrityFailsWithTamperedFile() {
        // Given
        let password = "testPassword"
        let message = "Test message"
        
        guard let fileData = fileManager.createFile(entries: [(password, message)]) else {
            XCTFail("Failed to create file")
            return
        }
        
        // When - Tamper with device HMAC
        var tamperedFile = fileData
        tamperedFile[0] ^= 0xFF // Flip first byte of device HMAC
        
        // Then
        let status = fileManager.verifyDeviceIntegrity(file: tamperedFile)
        XCTAssertFalse(status.isValid, "Should detect invalid device integrity")
    }
    
    func testFileImportWithDifferentDevice() {
        // Given
        let password = "testPassword"
        let message = "Test message"
        
        // Create file with current device
        guard let originalFile = fileManager.createFile(entries: [(password, message)]) else {
            XCTFail("Failed to create file")
            return
        }
        
        // Simulate different device by modifying device HMAC
        var importedFile = originalFile
        let fakeDeviceHMAC = Data(repeating: 0xFF, count: fileManager.deviceIntegrityHMACSize)
        importedFile.replaceSubrange(0..<fileManager.deviceIntegrityHMACSize, with: fakeDeviceHMAC)
        
        // When - Check integrity
        let status =  fileManager.verifyDeviceIntegrity(file: importedFile)
        
        // Then
        XCTAssertFalse(status.isValid, "Should detect file from different device")
        
        // When - Recalculate device integrity
        let recalculatedFile = fileManager.recalculateDeviceIntegrity(file: importedFile, password: password)
        
        // Then
        XCTAssertNotNil(recalculatedFile, "Should successfully recalculate device integrity")
        
        // Verify recalculated file works
        let newStatus =  fileManager.verifyDeviceIntegrity(file: recalculatedFile!)
        XCTAssertTrue(newStatus.isValid, "Recalculated file should have valid device integrity")
        
        // Verify we can decrypt
        let decrypted = fileManager.decryptFile(file: recalculatedFile!, password: password)
        XCTAssertEqual(decrypted?.message, message, "Should decrypt correctly after recalculation")
    }
    

    
    // MARK: - Updated Basic Functionality Tests
    
    func testCreateFileWithSingleEntry() {
        // Given
        let realPassword = "mySecretPassword123"
        let realMessage = "This is the real secret message"
        
        // When
        let fileData = fileManager.createFile(entries: [(realPassword, realMessage)])
        
        // Then
        XCTAssertNotNil(fileData, "File creation should succeed")
        XCTAssertTrue(fileData!.count > 0, "File data should not be empty")
        
        
        // Verify we can decrypt the real message
        let decrypted = fileManager.decryptFile(file: fileData!, password: realPassword)
        XCTAssertEqual(decrypted?.message, realMessage, "Should decrypt to original message")
        XCTAssertEqual(decrypted?.status, .valid)

    }
    
    func testDifferentPasswordsProduceDifferentResults() {
        // Given
        let password1 = "password1"
        let password2 = "password2"
        let message1 = "Message for password 1"
        let message2 = "Message for password 2"
        
        let fileData1 = fileManager.createFile(entries: [(password1, message1)])
        
        let fileData2 = fileManager.createFile(entries: [(password2, message2)])
        
        // Then
        XCTAssertNotNil(fileData1)
        XCTAssertNotNil(fileData2)
        XCTAssertNotEqual(fileData1, fileData2, "Different passwords should produce different encrypted files")
        
        // Cross-decryption should fail
        let crossDecrypt1 = fileManager.decryptFile(file: fileData1!, password: password2)
        let crossDecrypt2 = fileManager.decryptFile(file: fileData2!, password: password1)
        
        XCTAssertEqual(crossDecrypt1?.status, .invalidPassword, "Password2 should not decrypt file1")
        XCTAssertEqual(crossDecrypt2?.status, .invalidPassword, "Password1 should not decrypt file2")
    }
    
    
    func testCreateFileWithMultipleFakeEntries() {
        // Given
        let realPassword = "realPass"
        let realMessage = "Real secret data"
        let fakeEntries = [
            (password: "fake1", message: "Decoy message 1"),
            (password: "fake2", message: "Decoy message 2"),
            (password: "fake3", message: "Decoy message 3"),
            (password: realPassword, message: realMessage)
        ]
        
        // When
        let fileData = fileManager.createFile(entries: fakeEntries)
        
        // Then
        XCTAssertNotNil(fileData, "File creation with multiple fake entries should succeed")
        
        // Test real password decryption
        let realDecrypted = fileManager.decryptFile(file: fileData!, password: realPassword)
        XCTAssertEqual(realDecrypted?.message, realMessage, "Real password should decrypt real message")
        
        // Test fake password decryptions
        let fake1Decrypted = fileManager.decryptFile(file: fileData!, password: "fake1")
        XCTAssertEqual(fake1Decrypted?.message, "Decoy message 1", "Fake password 1 should decrypt fake message 1")
        
        let fake2Decrypted = fileManager.decryptFile(file: fileData!, password: "fake2")
        XCTAssertEqual(fake2Decrypted?.message, "Decoy message 2", "Fake password 2 should decrypt fake message 2")
        
        let fake3Decrypted = fileManager.decryptFile(file: fileData!, password: "fake3")
        XCTAssertEqual(fake3Decrypted?.message, "Decoy message 3", "Fake password 3 should decrypt fake message 3")
        }
    
    func testWrongPasswordReturnsInvalidPassword() {
        // Given
        let realPassword = "correctPassword"
        let realMessage = "Secret message"
        
        guard let fileData = fileManager.createFile(entries: [(realPassword, realMessage)]) else {
            XCTFail("File creation failed")
            return
        }
        
        // When & Then
        let status  = fileManager.verifyDeviceIntegrity(file:fileData)
        XCTAssertTrue(status.isValid)
        
        let wrongPasswordResult = fileManager.decryptFile(file: fileData, password: "wrongPassword")
        XCTAssertEqual(wrongPasswordResult?.status, .invalidPassword, "Wrong password should return nil")
    }
    
    // MARK: - Update Tests
    
    func testUpdateFileWithDeviceIntegrity() {
        // Given
        let password = "testPassword"
        let message = "Original message"
        let newMessage = "Updated message"
        
        guard let fileData = fileManager.createFile(entries: [(password, message)]) else {
            XCTFail("Failed to create file")
            return
        }
        
        // Get decryption info
        guard let decryptionResult = fileManager.decryptFile(file: fileData, password: password) else {
            XCTFail("Failed to decrypt original file")
            return
        }
        
        // When - Update file
        let updatedFile = fileManager.updateFile(
            file: fileData,
            password: password,
            saltIndex: decryptionResult.saltIndex,
            blockIndex: decryptionResult.blockIndex,
            newMessage: newMessage,
            allowDeviceChange: false
        )
        
        // Then
        XCTAssertNotNil(updatedFile, "Update should succeed")
        
        // Verify device integrity
        let status = fileManager.verifyDeviceIntegrity(file: updatedFile!)
        XCTAssertTrue(status.isValid, "Updated file should have valid device integrity")
        
        // Verify updated message
        let updatedDecryption = fileManager.decryptFile(file: updatedFile!, password: password)
        XCTAssertEqual(updatedDecryption?.message, newMessage, "Should decrypt to updated message")
    }
    

    
    func testUpdateContent() {
        
        let password = "testPassword"
        let message = "Original message"
        let newMessage = "Updated message"
        
        guard let fileData = fileManager.createFile(entries: [(password, message)]) else {
            XCTFail("Failed to create file")
            return
        }
        
        
        // Now decrypt
        guard let decryptInfo = fileManager.decryptFile(file: fileData, password: password) else {
            XCTFail("Failed to decrypt after recalculation")
            return
        }
        
        print("\(decryptInfo.message) == \(message)")

        XCTAssertTrue(decryptInfo.message == message)
        
        // When - Update with device change allowed
        let successfulUpdate = fileManager.updateFile(
            file: fileData,
            password: password,
            saltIndex: decryptInfo.saltIndex,
            blockIndex: decryptInfo.blockIndex,
            newMessage: newMessage,
            allowDeviceChange: false
        )
        
        // Then
        XCTAssertNotNil(successfulUpdate, "Update should succeed")
        
        // Now decrypt
        guard let decryptInfo2 = fileManager.decryptFile(file: successfulUpdate!, password: password) else {
            XCTFail("Failed to decrypt after recalculation")
            return
        }
        
        print("\(decryptInfo2.message) == \(newMessage)")
        
        XCTAssertTrue(decryptInfo2.message == newMessage)
        
        
    }
    
    func testUpdateFileFromDifferentDevice() {
        // Given
        let password = "testPassword"
        let message = "Original message"
        let newMessage = "Updated message"
        
        guard let fileData = fileManager.createFile(entries: [(password, message)]) else {
            XCTFail("Failed to create file")
            return
        }
        
        // Simulate file from different device
        var importedFile = fileData
        let fakeDeviceHMAC = Data(repeating: 0xFF, count: fileManager.deviceIntegrityHMACSize)
        importedFile.replaceSubrange(0..<fileManager.deviceIntegrityHMACSize, with: fakeDeviceHMAC)
        
        // Get decryption info (will fail due to device check)
        let decryptionResult = fileManager.decryptFile(file: importedFile, password: password)
        XCTAssertEqual(decryptionResult?.status , .invalidDevice, "Should not decrypt file from different device without recalculation")
        
        // First recalculate device integrity
        guard let recalculatedFile = fileManager.recalculateDeviceIntegrity(file: importedFile, password: password) else {
            XCTFail("Failed to recalculate device integrity")
            return
        }
        
        // Now decrypt
        guard let decryptInfo = fileManager.decryptFile(file: recalculatedFile, password: password) else {
            XCTFail("Failed to decrypt after recalculation")
            return
        }
        
        // When - Try to update without allowing device change (should fail)
        let failedUpdate = fileManager.updateFile(
            file: importedFile,
            password: password,
            saltIndex: decryptInfo.saltIndex,
            blockIndex: decryptInfo.blockIndex,
            newMessage: newMessage,
            allowDeviceChange: false
        )
        XCTAssertNil(failedUpdate, "Update should fail when device change not allowed")
        
        // When - Update with device change allowed
        let successfulUpdate = fileManager.updateFile(
            file: importedFile,
            password: password,
            saltIndex: decryptInfo.saltIndex,
            blockIndex: decryptInfo.blockIndex,
            newMessage: newMessage,
            allowDeviceChange: true
        )
        
        // Then
        XCTAssertNotNil(successfulUpdate, "Update should succeed with allowDeviceChange=true")
        
        // Verify new device integrity
        let newStatus = fileManager.verifyDeviceIntegrity(file: successfulUpdate!)
        XCTAssertTrue(newStatus.isValid, "Updated file should have valid device integrity for current device")
    }
    
    // MARK: - Backward Compatibility
    
    func testBackwardCompatibilityMethod() {
        // Given
        let password = "testPassword"
        let message = "Test message"
        
        guard let fileData = fileManager.createFile(entries: [(password, message)]) else {
            XCTFail("Failed to create file")
            return
        }
        
        // When - Use legacy method
        let verification  = fileManager.verifyDeviceIntegrity(file: fileData)
        
        // Then
        XCTAssertTrue(verification.isValid, "Legacy method should return valid")
    }
    
    
    // MARK: - Edge Cases
        
        func testEmptyMessages() {
            // Given
            let password = "password"
            let emptyMessage = ""
            
            // When
            let fileData = fileManager.createFile(entries: [(password, emptyMessage)])
            
            // Then
            XCTAssertNotNil(fileData, "Should handle empty messages")
            
            let decrypted = fileManager.decryptFile(file: fileData!, password: password)
            XCTAssertEqual(decrypted?.message, emptyMessage, "Should correctly decrypt empty message")
        }
        
        func testVeryLongMessages() {
            // Given
            let password = "longMessageTest"
            let longMessage = String(repeating: "This is a very long message. ", count: 100)
            
            // When
            let fileData = fileManager.createFile(entries: [(password, longMessage)])
            
            // Then
            XCTAssertNotNil(fileData, "Should handle very long messages")
            
            let decrypted = fileManager.decryptFile(file: fileData!, password: password)
            XCTAssertEqual(decrypted?.message, longMessage, "Should correctly decrypt long message")
        }
        
        func testUnicodeMessages() {
            // Given
            let password = "unicodeTest"
            let unicodeMessage = "Hello 世界! 🌍 Café naïve résumé 中文测试"
            
            // When
            let fileData = fileManager.createFile(entries: [(password, unicodeMessage)])
            
            // Then
            XCTAssertNotNil(fileData, "Should handle Unicode messages")
            
            let decrypted = fileManager.decryptFile(file: fileData!, password: password)
            XCTAssertEqual(decrypted?.message, unicodeMessage, "Should correctly decrypt Unicode message")
        }
        
        func testSpecialCharacterPasswords() {
            // Given
            let specialPassword = "P@ssw0rd!#$%^&*()_+-=[]{}|;':\",./<>?"
            let message = "Message with special char password"
            
            // When
            let fileData = fileManager.createFile(entries: [(specialPassword, message)])
            
            
            // Then
            XCTAssertNotNil(fileData, "Should handle passwords with special characters")
            
            let decrypted = fileManager.decryptFile(file: fileData!, password: specialPassword)
            XCTAssertEqual(decrypted?.message, message, "Should correctly decrypt with special char password")
        }
        
        // MARK: - Performance Tests
        
        func testPerformanceWithManyFakeEntries() {
            // Given
            let realPassword = "realPass"
            let realMessage = "Real message"
            var entries = (1...20).map { i in
                (password: "fake\(i)", message: "Fake message \(i)")
            }
            entries.append((realPassword,realMessage))
            
            // When & Then
            measure {
                let fileData = fileManager.createFile(entries: entries
                )
                XCTAssertNotNil(fileData, "Should handle many fake entries efficiently")
            }
        }
        
        func testDecryptionPerformance() {
            // Given
            let password = "performanceTest"
            let message = "Performance test message"
            var entries = (1...10).map { i in
                (password: "fake\(i)", message: "Fake message \(i)")
            }
            entries.append((password,message))
            
            guard let fileData = fileManager.createFile(entries: entries
            ) else {
                XCTFail("File creation failed")
                return
            }
            
            // When & Then
            measure {
                let decrypted = fileManager.decryptFile(file: fileData, password: password)
                XCTAssertEqual(decrypted?.message, message, "Should decrypt efficiently")
            }
        }
        
        // MARK: - Consistency Tests
        
        func testMultipleEncryptionsProduceDifferentFiles() {
            // Given
            let password = "consistencyTest"
            let message = "Same message"
            
            // When
            let fileData1 = fileManager.createFile(entries: [(password, message)])
            let fileData2 = fileManager.createFile(entries: [(password, message)])
            
            // Then
            XCTAssertNotNil(fileData1)
            XCTAssertNotNil(fileData2)
            XCTAssertNotEqual(fileData1, fileData2, "Multiple encryptions should produce different files (due to randomness)")
            
            // But both should decrypt to the same message
            let decrypted1 = fileManager.decryptFile(file: fileData1!, password: password)
            let decrypted2 = fileManager.decryptFile(file: fileData2!, password: password)
            
            XCTAssertEqual(decrypted1?.message, message)
            XCTAssertEqual(decrypted2?.message, message)
            XCTAssertEqual(decrypted1?.message, decrypted2?.message)
        }
        
        func testSingletonBehavior() {
            // Given & When
            let instance1 = DeniableFileManager.shared
            let instance2 = DeniableFileManager.shared
            
            // Then
            XCTAssertTrue(instance1 === instance2, "DeniableFileManager should be a singleton")
        }
        
}
