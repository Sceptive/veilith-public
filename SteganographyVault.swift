//
//  SteganographyVault.swift
//  Veilith
//
//  Created by marcus on 14.07.2025.
//


//
//  SteganographyVault.swift
//  PhantomVault
//
//  Created by marcus on 6.06.2025.
//
import UIKit
import Compression

// MARK: - Steganography Manager
class SteganographyVault {
    
    // MARK: - Error Types
    enum SteganographyError: Error {
        case imageTooSmall
        case dataExtractionFailed
        case invalidImage
        case compressionFailed
        case dataTooLarge
    }
    
    // MARK: - Main Encoding Function
    func encodeVault(coverImage: UIImage,
                     vaultData: Data) throws -> UIImage {
        
        // Step 1: Compress the vault data
        guard let compressedData = compress(data: vaultData) else {
            throw SteganographyError.compressionFailed
        }
        
        print("Original size: \(vaultData.count) bytes")
        print("Compressed size: \(compressedData.count) bytes")
        
        // Step 2: Prepare data with size prefix (4 bytes)
        let finalData = prepareDataWithSize(compressedData)
        
        // Step 3: Check image capacity
        guard let cgImage = coverImage.cgImage else {
            throw SteganographyError.invalidImage
        }
        
        let capacity = calculateCapacity(cgImage: cgImage)
        guard capacity >= finalData.count * 8 else {
            throw SteganographyError.imageTooSmall
        }
        
        // Step 4: Embed data into image
        let stegoImage = try embedData(cgImage: cgImage, data: finalData)
        
        return UIImage(cgImage: stegoImage)
    }
    
    // MARK: - Main Decoding Function
    func decodeVault(stegoImage: UIImage) throws -> Data {
        
        guard let cgImage = stegoImage.cgImage else {
            throw SteganographyError.invalidImage
        }
        
        // Step 1: Extract size first (4 bytes = 32 bits)
        let sizeData = try extractSize(cgImage: cgImage)
        let dataSize = sizeData.withUnsafeBytes { $0.load(as: UInt32.self).littleEndian }
        
        // Step 2: Extract the actual data
        let compressedData = try extractData(cgImage: cgImage,
                                           startOffset: 4,
                                           length: Int(dataSize))
        
        // Step 3: Decompress
        guard let decompressedData = decompress(data: compressedData) else {
            throw SteganographyError.dataExtractionFailed
        }
        
        return decompressedData
    }
    
    // MARK: - LSB Embedding
    private func embedData(cgImage: CGImage, data: Data) throws -> CGImage {
        let width = cgImage.width
        let height = cgImage.height
        let bitsPerComponent = 8
        let bytesPerPixel = 4
        let bytesPerRow = bytesPerPixel * width
        let totalBytes = height * bytesPerRow
        
        // Create bitmap context
        guard let colorSpace = cgImage.colorSpace,
              let context = CGContext(data: nil,
                                     width: width,
                                     height: height,
                                     bitsPerComponent: bitsPerComponent,
                                     bytesPerRow: bytesPerRow,
                                     space: colorSpace,
                                     bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else {
            throw SteganographyError.invalidImage
        }
        
        // Draw original image
        context.draw(cgImage, in: CGRect(x: 0, y: 0, width: width, height: height))
        
        // Get pixel data
        guard let pixelData = context.data else {
            throw SteganographyError.invalidImage
        }
        
        let pixels = pixelData.bindMemory(to: UInt8.self, capacity: totalBytes)
        
        // Convert data to bits
        var bits: [Bool] = []
        for byte in data {
            for i in (0..<8).reversed() {
                bits.append((byte >> i) & 1 == 1)
            }
        }
        
        // Embed bits into LSBs of RGB channels (skip alpha)
        var bitIndex = 0
        for pixelIndex in stride(from: 0, to: totalBytes, by: bytesPerPixel) {
            for channelOffset in 0..<3 { // RGB only, skip alpha
                if bitIndex < bits.count {
                    let channelIndex = pixelIndex + channelOffset
                    if bits[bitIndex] {
                        pixels[channelIndex] |= 0x01
                    } else {
                        pixels[channelIndex] &= 0xFE
                    }
                    bitIndex += 1
                } else {
                    break
                }
            }
            if bitIndex >= bits.count { break }
        }
        
        // Create new image from modified data
        guard let newCGImage = context.makeImage() else {
            throw SteganographyError.invalidImage
        }
        
        return newCGImage
    }
    
    // MARK: - Size Extraction
    private func extractSize(cgImage: CGImage) throws -> Data {
        let width = cgImage.width
        let height = cgImage.height
        let bytesPerPixel = 4
        let bytesPerRow = bytesPerPixel * width
        let totalBytes = height * bytesPerRow
        
        // Get pixel data
        guard let dataProvider = cgImage.dataProvider,
              let pixelData = dataProvider.data else {
            throw SteganographyError.invalidImage
        }
        
        let data: UnsafePointer<UInt8> = CFDataGetBytePtr(pixelData)
        
        // Extract first 32 bits (4 bytes) for size
        var sizeBits: [Bool] = []
        var bitIndex = 0
        
        for pixelIndex in stride(from: 0, to: totalBytes, by: bytesPerPixel) {
            for channelOffset in 0..<3 { // RGB only
                if bitIndex < 32 {
                    let channelIndex = pixelIndex + channelOffset
                    sizeBits.append(data[channelIndex] & 1 == 1)
                    bitIndex += 1
                }
            }
            if bitIndex >= 32 { break }
        }
        
        let sizeBytes = bitsToBytes(sizeBits)
        return Data(sizeBytes)
    }
    
    // MARK: - Data Extraction
    private func extractData(cgImage: CGImage, startOffset: Int, length: Int) throws -> Data {
        let width = cgImage.width
        let height = cgImage.height
        let bytesPerPixel = 4
        let bytesPerRow = bytesPerPixel * width
        let totalBytes = height * bytesPerRow
        
        // Get pixel data
        guard let dataProvider = cgImage.dataProvider,
              let pixelData = dataProvider.data else {
            throw SteganographyError.invalidImage
        }
        
        let data: UnsafePointer<UInt8> = CFDataGetBytePtr(pixelData)
        
        // Calculate total bits needed
        let skipBits = startOffset * 8
        let totalBitsNeeded = skipBits + (length * 8)
        
        var allBits: [Bool] = []
        var bitIndex = 0
        
        for pixelIndex in stride(from: 0, to: totalBytes, by: bytesPerPixel) {
            for channelOffset in 0..<3 { // RGB only
                if bitIndex >= skipBits && bitIndex < totalBitsNeeded {
                    let channelIndex = pixelIndex + channelOffset
                    allBits.append(data[channelIndex] & 1 == 1)
                }
                bitIndex += 1
                if bitIndex >= totalBitsNeeded { break }
            }
            if bitIndex >= totalBitsNeeded { break }
        }
        
        let dataBytes = bitsToBytes(allBits)
        return Data(dataBytes)
    }
    
    // MARK: - Helper Functions
    private func calculateCapacity(cgImage: CGImage) -> Int {
        let width = cgImage.width
        let height = cgImage.height
        return width * height * 3 // 3 channels (RGB) * 1 bit each
    }
    
    private func prepareDataWithSize(_ data: Data) -> Data {
        var result = Data()
        
        // Add size as 4-byte little-endian integer
        var size = UInt32(data.count).littleEndian
        result.append(Data(bytes: &size, count: 4))
        
        // Add the actual data
        result.append(data)
        
        return result
    }
    
    private func bitsToBytes(_ bits: [Bool]) -> [UInt8] {
        var bytes: [UInt8] = []
        
        for i in stride(from: 0, to: bits.count, by: 8) {
            var byte: UInt8 = 0
            for j in 0..<8 {
                if i + j < bits.count && bits[i + j] {
                    byte |= 1 << (7 - j)
                }
            }
            bytes.append(byte)
        }
        
        return bytes
    }
    
    // MARK: - Compression
    private func compress(data: Data) -> Data? {
        return data.compressed(using: .zlib)
    }
    
    private func decompress(data: Data) -> Data? {
        return data.decompressed(using: .zlib)
    }
}

// MARK: - Data Extension for Compression
extension Data {
    func compressed(using algorithm: NSData.CompressionAlgorithm) -> Data? {
        do {
            return  try  (self as NSData).compressed(using: algorithm) as Data?
        } catch {
            print("Could not compress data \(self)")
            return self;
        }
    }
    
    func decompressed(using algorithm: NSData.CompressionAlgorithm) -> Data? {
        do {
            return  try  (self as NSData).decompressed(using: algorithm) as Data?
        } catch {
            print("Could not decompress data \(self)")
            return self;
        }
    }
    
    func chunked(into size: Int) -> [Data] {
          var chunks: [Data] = []
          var offset = 0
          
          while offset < count {
              let chunkSize = Swift.min(size, count - offset)
              let chunk = subdata(in: offset..<offset + chunkSize)
              chunks.append(chunk)
              offset += chunkSize
          }
          
          return chunks
      }
}

extension NSData.CompressionAlgorithm {
    static let zlib = NSData.CompressionAlgorithm(rawValue: 0)
}

// MARK: - Batch Processing Extension
extension SteganographyVault {
    
    // Split large data across multiple images if needed
    func encodeVaultAcrossMultipleImages(vaultData: Data,
                                       coverImages: [UIImage],
                                       chunkSize: Int = 200_000) throws -> [UIImage] {
        
        var stegoImages: [UIImage] = []
        let chunks = vaultData.chunked(into: chunkSize)
        
        guard chunks.count <= coverImages.count else {
            throw SteganographyError.dataTooLarge
        }
        
        for (index, chunk) in chunks.enumerated() {
            let stegoImage = try encodeVault(coverImage: coverImages[index],
                                           vaultData: chunk)
            stegoImages.append(stegoImage)
        }
        
        return stegoImages
    }
    
    // Extract from multiple images
    func decodeVaultFromMultipleImages(stegoImages: [UIImage]) throws -> Data {
        var combinedData = Data()
        
        for image in stegoImages {
            let chunk = try decodeVault(stegoImage: image)
            combinedData.append(chunk)
        }
        
        return combinedData
    }
}
