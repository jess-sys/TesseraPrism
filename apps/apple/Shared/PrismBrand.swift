import SwiftUI

extension Color {
    /// Tessera burgundy (asset `AccentColor`: #7D2333, lighter rose in dark mode).
    static let prismBrand = Color("AccentColor")
}

extension View {
    /// Applies the brand tint explicitly: on macOS apps otherwise follow the user's system accent.
    func prismBranded() -> some View { tint(.prismBrand) }
}

/// The Tessera Prism logo (asset `PrismLogo`, shared with the AutoFill extensions). The artwork
/// carries its own rounded frame, so it is drawn as is.
struct PrismLogo: View {
    var size: CGFloat = 56

    var body: some View {
        Image("PrismLogo")
            .resizable()
            .interpolation(.high)
            .scaledToFit()
            .frame(width: size, height: size)
            .accessibilityLabel("Tessera Prism")
    }
}

/// Logo above the product name, for screens that introduce the app (connect, AutoFill).
struct PrismBrandHeader: View {
    var logoSize: CGFloat = 72
    var subtitle: String?

    var body: some View {
        VStack(spacing: 8) {
            PrismLogo(size: logoSize)
            Text("Tessera Prism")
                .font(.system(.title2, design: .rounded, weight: .bold))
            if let subtitle {
                Text(subtitle)
                    .font(.system(.subheadline, design: .rounded))
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }
        }
        .accessibilityElement(children: .combine)
    }
}

/// Compact logo + name for a navigation bar's principal slot.
struct PrismToolbarTitle: View {
    var body: some View {
        HStack(spacing: 6) {
            PrismLogo(size: 24)
            Text("Tessera Prism")
                .font(.system(.headline, design: .rounded))
        }
        .accessibilityElement(children: .combine)
    }
}
