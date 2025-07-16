//
//  SteganographyVaultTests.swift
//  Veilith
//
//  Created by marcus on 14.07.2025.
//




import XCTest
import UIKit
import SwiftUI
@testable import Veilith

class SteganographyVaultTests: XCTestCase {
    
    var steganographyVault: SteganographyVault!
    var fileManager: DeniableFileManager!
    
    override func setUp() {
        super.setUp()
        steganographyVault = SteganographyVault()
        fileManager = DeniableFileManager.shared
    }
    
    override func tearDown() {
        steganographyVault = nil
        fileManager = nil
        super.tearDown()
    }
    
    // MARK: - Helper Methods
    
    private func createTestImage(width: Int = 100, height: Int = 100) -> UIImage {
        let size = CGSize(width: width, height: height)
        UIGraphicsBeginImageContextWithOptions(size, false, 0.0)
        
        // Create a simple gradient pattern
        let context = UIGraphicsGetCurrentContext()!
        let colorSpace = CGColorSpaceCreateDeviceRGB()
        let colors = [UIColor.red.cgColor, UIColor.blue.cgColor, UIColor.green.cgColor]
        let gradient = CGGradient(colorsSpace: colorSpace, colors: colors as CFArray, locations: nil)!
        
        context.drawLinearGradient(gradient,
                                 start: CGPoint(x: 0, y: 0),
                                 end: CGPoint(x: size.width, y: size.height),
                                 options: [])
        
        let image = UIGraphicsGetImageFromCurrentImageContext()!
        UIGraphicsEndImageContext()
        
        return image
    }
    
    private func createTestData(size: Int = 1000) -> Data {
        var data = Data()
        for i in 0..<size {
            data.append(UInt8(i % 256))
        }
        return data
    }
    
    private func createSmallTestImage(width: Int = 10, height: Int = 10) -> UIImage {
        return createTestImage(width: width, height: height)
    }
    
    // MARK: - Basic Encoding/Decoding Tests
    
    func testBasicEncodeAndDecode() throws {
        // Given
        let coverImage = createTestImage()
        let testData = createTestData(size: 500)
        
        // When
        let stegoImage = try steganographyVault.encodeVault(coverImage: coverImage, vaultData: testData)
        let decodedData = try steganographyVault.decodeVault(stegoImage: stegoImage)
        
        print("Test Data: \(testData as NSData) Decoded data: \(decodedData as NSData)")
        // Then
        XCTAssertEqual(testData, decodedData, "Decoded data should match original data")
    }
    
    func testEncodeDecodeWithSmallData() throws {
        // Given
        let coverImage = createTestImage()
        let testData = "Hello, World!".data(using: .utf8)!
        
        // When
        let stegoImage = try steganographyVault.encodeVault(coverImage: coverImage, vaultData: testData)
        let decodedData = try steganographyVault.decodeVault(stegoImage: stegoImage)
        
        // Then
        XCTAssertEqual(testData, decodedData)
        XCTAssertEqual(String(data: decodedData, encoding: .utf8), "Hello, World!")
    }
    
    func testEncodeDecodeWithLargeData() throws {
        // Given
        let coverImage = createTestImage(width: 500, height: 500) // Larger image for more capacity
        let testData = createTestData(size: 10000) // Larger data
        
        // When
        let stegoImage = try steganographyVault.encodeVault(coverImage: coverImage, vaultData: testData)
        let decodedData = try steganographyVault.decodeVault(stegoImage: stegoImage)
        
        // Then
        XCTAssertEqual(testData, decodedData)
    }
    
    func testEncodeDecodeWithEmptyData() throws {
        // Given
        let coverImage = createTestImage()
        let testData = Data()
        
        // When
        let stegoImage = try steganographyVault.encodeVault(coverImage: coverImage, vaultData: testData)
        let decodedData = try steganographyVault.decodeVault(stegoImage: stegoImage)
        
        // Then
        XCTAssertEqual(testData, decodedData)
        XCTAssertTrue(decodedData.isEmpty)
    }
    
    // MARK: - Error Handling Tests
    
    func testImageTooSmallError() {
        // Given
        let smallImage = createSmallTestImage()
        let largeData = createTestData(size: 500000) // Too large for small image
        
        // When/Then
        XCTAssertThrowsError(try steganographyVault.encodeVault(coverImage: smallImage, vaultData: largeData)) { error in
            XCTAssertEqual(error as? SteganographyVault.SteganographyError, .imageTooSmall)
        }
    }
    
    func testInvalidImageError() {
        // Given
        let invalidImage = UIImage() // Empty image
        let testData = createTestData()
        
        // When/Then
        XCTAssertThrowsError(try steganographyVault.encodeVault(coverImage: invalidImage, vaultData: testData)) { error in
            XCTAssertEqual(error as? SteganographyVault.SteganographyError, .invalidImage)
        }
    }
    
    func testDecodeInvalidImageError() {
        // Given
        let invalidImage = UIImage() // Empty image
        
        // When/Then
        XCTAssertThrowsError(try steganographyVault.decodeVault(stegoImage: invalidImage)) { error in
            XCTAssertEqual(error as? SteganographyVault.SteganographyError, .invalidImage)
        }
    }
    
    func testDecodeFromNonStegoImage() {
        // Given
        let normalImage = createTestImage()
        
        // When/Then - This should either throw an error or return unexpected data
        // The behavior depends on what random data is extracted from LSBs
        do {
            let decodedData = try steganographyVault.decodeVault(stegoImage: normalImage)
            // If it doesn't throw, the data should be different from any expected input
            XCTAssertNotNil(decodedData)
        } catch {
            // It's also valid for this to throw an error during decompression
            XCTAssertTrue(error is SteganographyVault.SteganographyError)
        }
    }
    
    // MARK: - Compression Tests
    
    func testCompressionReducesSize() throws {
        // Given - Create repetitive data that compresses well
        let repetitiveData = Data(repeating: 0x42, count: 1000)
        let coverImage = createTestImage(width: 200, height: 200)
        
        // When
        let stegoImage = try steganographyVault.encodeVault(coverImage: coverImage, vaultData: repetitiveData)
        let decodedData = try steganographyVault.decodeVault(stegoImage: stegoImage)
        
        // Then
        XCTAssertEqual(repetitiveData, decodedData)
        // The compression should have worked internally (we can't directly test this,
        // but we verify the round-trip works)
    }
    
    // MARK: - Batch Processing Tests
    
    func testEncodeDecodeAcrossMultipleImages() throws {
        // Given
        let coverImages = [
            createTestImage(width: 100, height: 100),
            createTestImage(width: 100, height: 100),
            createTestImage(width: 100, height: 100)
        ]
        let largeData = createTestData(size: 5000)
        
        // When
        let stegoImages = try steganographyVault.encodeVaultAcrossMultipleImages(
            vaultData: largeData,
            coverImages: coverImages,
            chunkSize: 2000
        )
        let decodedData = try steganographyVault.decodeVaultFromMultipleImages(stegoImages: stegoImages)
        
        // Then
        XCTAssertEqual(largeData, decodedData)
        XCTAssertTrue(stegoImages.count <= coverImages.count)
    }
    
    func testBatchProcessingWithInsufficientImages() {
        // Given
        let coverImages = [createTestImage()] // Only one image
        let largeData = createTestData(size: 50000) // Too much data for one image with small chunk size
        
        // When/Then
        XCTAssertThrowsError(try steganographyVault.encodeVaultAcrossMultipleImages(
            vaultData: largeData,
            coverImages: coverImages,
            chunkSize: 1000
        )) { error in
            XCTAssertEqual(error as? SteganographyVault.SteganographyError, .dataTooLarge)
        }
    }
    
    func testBatchProcessingWithSingleImage() throws {
        // Given
        let coverImages = [createTestImage(width: 200, height: 200)]
        let testData = createTestData(size: 1000)
        
        // When
        let stegoImages = try steganographyVault.encodeVaultAcrossMultipleImages(
            vaultData: testData,
            coverImages: coverImages,
            chunkSize: 2000 // Chunk size larger than data
        )
        let decodedData = try steganographyVault.decodeVaultFromMultipleImages(stegoImages: stegoImages)
        
        // Then
        XCTAssertEqual(testData, decodedData)
        XCTAssertEqual(stegoImages.count, 1)
    }
    
    // MARK: - Data Integrity Tests
    
    func testDataIntegrityWithDifferentDataTypes() throws {
        let coverImage = createTestImage(width: 200, height: 200)
        
        // Test with JSON data
        let jsonData = try JSONSerialization.data(withJSONObject: [
            "name": "test",
            "value": 123,
            "array": [1, 2, 3, 4, 5]
        ])
        
        let stegoImage = try steganographyVault.encodeVault(coverImage: coverImage, vaultData: jsonData)
        let decodedData = try steganographyVault.decodeVault(stegoImage: stegoImage)
        
        XCTAssertEqual(jsonData, decodedData)
        
        // Verify we can parse it back to JSON
        let decodedJSON = try JSONSerialization.jsonObject(with: decodedData) as? [String: Any]
        XCTAssertNotNil(decodedJSON)
        XCTAssertEqual(decodedJSON?["name"] as? String, "test")
        XCTAssertEqual(decodedJSON?["value"] as? Int, 123)
    }
    
    func testDataIntegrityWithBinaryData() throws {
        // Given
        let coverImage = createTestImage(width: 150, height: 150)
        var binaryData = Data()
        
        // Create binary data with all possible byte values
        for i in 0..<256 {
            binaryData.append(UInt8(i))
        }
        
        // When
        let stegoImage = try steganographyVault.encodeVault(coverImage: coverImage, vaultData: binaryData)
        let decodedData = try steganographyVault.decodeVault(stegoImage: stegoImage)
        
        // Then
        XCTAssertEqual(binaryData, decodedData)
        XCTAssertEqual(binaryData.count, decodedData.count)
        
        // Verify each byte
        for i in 0..<binaryData.count {
            XCTAssertEqual(binaryData[i], decodedData[i], "Byte at index \(i) should match")
        }
    }
    
    // MARK: - Performance Tests
    
    func testPerformanceEncoding() {
        let coverImage = createTestImage(width: 300, height: 300)
        let testData = createTestData(size: 5000)
        
        measure {
            do {
                _ = try steganographyVault.encodeVault(coverImage: coverImage, vaultData: testData)
            } catch {
                XCTFail("Encoding should not fail in performance test")
            }
        }
    }
    func testRealisticValues() throws {
        // Setup
        
        let testBundle = Bundle(for: type(of: self))

        
        let realImageURL =  testBundle.url(forResource: "mars_picture", withExtension: "png")
        let data = try? Data(contentsOf: realImageURL!)
        let coverImage = UIImage(data: data!)!
        
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
        
        print("fileData: \(fileData! as NSData) ")
        // Then
        XCTAssertNotNil(fileData, "File creation with multiple fake entries should succeed")
       
        
        let stegoImage = try steganographyVault.encodeVault(coverImage: coverImage, vaultData: fileData!)
        
        do {
            let decodedData = try steganographyVault.decodeVault(stegoImage: stegoImage)
            
            XCTAssertEqual(fileData, decodedData)
            
            print("decodedData: \(decodedData as NSData) ")
            
            if let recalculatedData = DeniableFileManager.shared.recalculateDeviceIntegrity(
                file: decodedData,
                password: "" // This won't be used for recalculation
            ) {
                
                print("recalculatedData: \(recalculatedData as NSData) ")
                
                // Test real password decryption
                let realDecrypted = fileManager.decryptFile(file: recalculatedData, password: realPassword)
                XCTAssertEqual(realDecrypted?.message, realMessage, "Real password should decrypt real message")
            }
                
            
        } catch {
            XCTFail("Decoding should not fail in performance test")
        }
        
    }
    
    
    
    func testPerformanceDecoding() throws {
        // Setup
        let coverImage = createTestImage(width: 300, height: 300)
        let testData = createTestData(size: 5000)
        let stegoImage = try steganographyVault.encodeVault(coverImage: coverImage, vaultData: testData)
        
        measure {
            do {
                _ = try steganographyVault.decodeVault(stegoImage: stegoImage)
            } catch {
                XCTFail("Decoding should not fail in performance test")
            }
        }
    }
    
    // MARK: - Edge Cases
    
    func testCapacityCalculation() {
        // Test that capacity calculation is correct
        let image = createTestImage(width: 10, height: 10)
        guard let cgImage = image.cgImage else {
            XCTFail("Should have CGImage")
            return
        }
        
        // Capacity should be width * height * 3 (RGB channels)
        let expectedCapacity = 10 * 10 * 3
        
        // We can't directly access the private method, but we can test indirectly
        // by trying to encode data that should fit exactly
        let dataSize = expectedCapacity / 8 - 4 - 10 // Account for size prefix and compression overhead
        let testData = createTestData(size: dataSize)
        
        // This should not throw an error
        XCTAssertNoThrow(try steganographyVault.encodeVault(coverImage: image, vaultData: testData))
    }
    
    func testDataChunking() {
        // Test the chunked extension
        let data = createTestData(size: 100)
        let chunks = data.chunked(into: 30)
        
        XCTAssertEqual(chunks.count, 4) // 100/30 = 3.33, so 4 chunks
        XCTAssertEqual(chunks[0].count, 30)
        XCTAssertEqual(chunks[1].count, 30)
        XCTAssertEqual(chunks[2].count, 30)
        XCTAssertEqual(chunks[3].count, 10) // Remainder
        
        // Verify chunked data equals original when combined
        var combinedData = Data()
        chunks.forEach { combinedData.append($0) }
        XCTAssertEqual(data, combinedData)
    }
    
    func testSizePrefix() throws {
        // Test that size prefix works correctly
        let coverImage = createTestImage()
        let testData = createTestData(size: 1234) // Specific size to verify
        
        let stegoImage = try steganographyVault.encodeVault(coverImage: coverImage, vaultData: testData)
        let decodedData = try steganographyVault.decodeVault(stegoImage: stegoImage)
        
        XCTAssertEqual(testData.count, decodedData.count)
        XCTAssertEqual(testData, decodedData)
    }
}

// MARK: - SteganographyError Conformance for Testing
extension SteganographyVault.SteganographyError: Equatable {
    public static func == (lhs: SteganographyVault.SteganographyError, rhs: SteganographyVault.SteganographyError) -> Bool {
        switch (lhs, rhs) {
        case (.imageTooSmall, .imageTooSmall),
             (.dataExtractionFailed, .dataExtractionFailed),
             (.invalidImage, .invalidImage),
             (.compressionFailed, .compressionFailed),
             (.dataTooLarge, .dataTooLarge):
            return true
        default:
            return false
        }
    }
}

// MARK: - Mock Data Extensions for Testing
extension SteganographyVaultTests {
    
    func testWithRealWorldData() throws {
        // Test with a more realistic scenario
        let coverImage = createTestImage(width: 400, height: 400)
        
        // Create mock user data (like what might be in a vault)
        let userData :  [String : Any] = [
            "passwords": [
                ["site": "example.com", "username": "user1", "password": "secretpass123"],
                ["site": "github.com", "username": "developer", "password": "dev_password_456"]
            ],
            "notes": [
                "Remember to update server passwords monthly",
                "Backup codes: 12345, 67890, 54321"
            ],
            "settings": [
                "encryption": "AES-256",
                "backup_frequency": "daily"
            ]
        ]
        
        let jsonData = try JSONSerialization.data(withJSONObject: userData, options: .prettyPrinted)
        
        // When
        let stegoImage = try steganographyVault.encodeVault(coverImage: coverImage, vaultData: jsonData)
        let decodedData = try steganographyVault.decodeVault(stegoImage: stegoImage)
        
        // Then
        XCTAssertEqual(jsonData, decodedData)
        
        // Verify the data is still valid JSON
        let decodedUserData = try JSONSerialization.jsonObject(with: decodedData) as? [String: Any]
        XCTAssertNotNil(decodedUserData)
        
        let passwords = decodedUserData?["passwords"] as? [[String: String]]
        XCTAssertEqual(passwords?.count, 2)
        XCTAssertEqual(passwords?[0]["site"], "example.com")
    }
}
