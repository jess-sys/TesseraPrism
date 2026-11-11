#if os(iOS)
import SwiftUI
import VisionKit

/// QR scanner built on VisionKit's DataScannerViewController (iOS 16+).
struct QRScannerView: View {
    var onCode: (String) -> Void
    var body: some View {
        if DataScannerViewController.isSupported && DataScannerViewController.isAvailable {
            ScannerRepresentable(onCode: onCode).ignoresSafeArea()
        } else {
            ContentUnavailableView("Scanner unavailable", systemImage: "qrcode.viewfinder",
                                   description: Text("Camera access is denied or unsupported. Paste the otpauth:// URI instead."))
        }
    }
}

private struct ScannerRepresentable: UIViewControllerRepresentable {
    var onCode: (String) -> Void

    func makeUIViewController(context: Context) -> DataScannerViewController {
        let vc = DataScannerViewController(recognizedDataTypes: [.barcode(symbologies: [.qr])], isHighlightingEnabled: true)
        vc.delegate = context.coordinator
        try? vc.startScanning()
        return vc
    }
    func updateUIViewController(_ vc: DataScannerViewController, context: Context) {}
    func makeCoordinator() -> Coordinator { Coordinator(onCode: onCode) }

    final class Coordinator: NSObject, DataScannerViewControllerDelegate {
        let onCode: (String) -> Void
        var fired = false
        init(onCode: @escaping (String) -> Void) { self.onCode = onCode }
        func dataScanner(_ dataScanner: DataScannerViewController, didAdd addedItems: [RecognizedItem], allItems: [RecognizedItem]) {
            guard !fired else { return }
            for case .barcode(let b) in addedItems {
                if let s = b.payloadStringValue, s.hasPrefix("otpauth://") { fired = true; onCode(s); return }
            }
        }
    }
}
#endif
