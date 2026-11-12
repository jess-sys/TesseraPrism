import SwiftUI

/// What the Prism link is currently doing, shown by `PrismActivityView`.
enum PrismActivity: Equatable {
    case searching
    case connecting
    case pairing(code: String)
    case unlock
    case approve
    case working(String)
    case success(String)
    case failure(String)
}

/// Animated status card: large SF Symbol, rounded title and optional subtitle.
struct PrismActivityView: View {
    let activity: PrismActivity
    /// Replaces the default subtitle (e.g. which host an SSH sign-in is for).
    var detail: String?
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    /// Activity actually drawn. Lags behind `activity` briefly when leaving `.unlock`, so the
    /// padlock can animate open first.
    @State private var shown: PrismActivity
    @State private var unlocked = false
    @State private var tick = 0

    init(_ activity: PrismActivity, detail: String? = nil) {
        self.activity = activity
        self.detail = detail
        _shown = State(initialValue: activity)
    }

    var body: some View {
        VStack(spacing: 14) {
            if case .pairing(let code) = shown { codeView(code) }
            symbol
                .font(.system(size: 64))
                .foregroundStyle(symbolStyle)
                .frame(height: 76)
                .contentTransition(.symbolEffect(.replace))
            Text(title)
                .font(.system(.title2, design: .rounded, weight: .bold))
                .multilineTextAlignment(.center)
                .foregroundStyle(shown.isFailure ? AnyShapeStyle(.red) : AnyShapeStyle(.primary))
            if let subtitle {
                Text(subtitle)
                    .font(.system(.callout, design: .rounded))
                    .foregroundStyle(shown.isFailure ? AnyShapeStyle(.red.opacity(0.75)) : AnyShapeStyle(.secondary))
                    .multilineTextAlignment(.center)
            }
        }
        .id(shown.kind)
        .transition(.opacity.combined(with: .scale(0.9)))
        .frame(maxWidth: .infinity)
        .padding()
        .animation(.smooth, value: shown)
        .animation(.smooth, value: unlocked)
        .accessibilityElement(children: .combine)
        .onChange(of: activity) { old, new in
            if old == .unlock, new != .unlock {
                unlocked = true
                Task { @MainActor in
                    try? await Task.sleep(nanoseconds: 700_000_000)
                    unlocked = false
                    shown = new
                }
            } else {
                unlocked = false
                shown = new
            }
        }
        .task(id: shown == .unlock && !reduceMotion) {
            guard shown == .unlock, !reduceMotion else { return }
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 1_500_000_000)
                tick += 1
            }
        }
    }

    // MARK: pieces

    @ViewBuilder private var symbol: some View {
        let animate = !reduceMotion
        switch shown {
        case .searching:
            Image(systemName: "antenna.radiowaves.left.and.right")
                .symbolEffect(.variableColor.iterative.reversing, isActive: animate)
        case .connecting:
            Image(systemName: "lock.shield").symbolEffect(.pulse, isActive: animate)
        case .pairing:
            Image(systemName: "link").symbolEffect(.pulse, isActive: animate)
        case .unlock:
            Image(systemName: unlocked ? "lock.open.fill" : "lock.fill")
                .symbolEffect(.bounce, options: .nonRepeating, value: animate ? tick : 0)
        case .approve:
            Image(systemName: "hand.tap.fill").symbolEffect(.pulse, isActive: animate)
        case .working:
            Image(systemName: "ellipsis").symbolEffect(.variableColor.iterative, isActive: animate)
        case .success:
            Image(systemName: "checkmark.circle.fill").symbolEffect(.bounce, options: .nonRepeating, value: animate ? shown : .searching)
        case .failure:
            Image(systemName: "exclamationmark.triangle.fill").symbolEffect(.bounce, options: .nonRepeating, value: animate ? shown : .searching)
        }
    }

    private var symbolStyle: AnyShapeStyle {
        switch shown {
        case .success: AnyShapeStyle(.green)
        case .failure: AnyShapeStyle(.red)
        default: AnyShapeStyle(.tint)
        }
    }

    private func codeView(_ code: String) -> some View {
        let digits = Array(code.filter { !$0.isWhitespace })
        let text = digits.count == 6 ? String(digits[0..<3]) + " " + String(digits[3..<6]) : code
        return Text(text)
            .font(.system(size: 44, weight: .bold, design: .rounded).monospaced())
            .kerning(4)
            .contentTransition(.numericText())
            .minimumScaleFactor(0.5)
            .lineLimit(1)
    }

    private var title: String {
        switch shown {
        case .searching: "Looking for your Prism"
        case .connecting: "Connecting securely…"
        case .pairing: "Pairing code"
        case .unlock: unlocked ? "Unlocked" : "Unlock your Tessera Prism"
        case .approve: "Approve on your Prism"
        case .working(let t), .success(let t), .failure(let t): t
        }
    }

    private var subtitle: String? {
        if let detail, !detail.isEmpty { return detail }
        return switch shown {
        case .searching: "Make sure it is on and nearby"
        case .pairing: "Compare with the code on your Prism, then tap Confirm on the device"
        case .unlock: unlocked ? nil : "Enter your PIN on the device"
        default: String?.none
        }
    }
}

private extension PrismActivity {
    var isFailure: Bool { if case .failure = self { true } else { false } }
    /// Identity of the case ignoring payload, so text changes don't re-trigger the transition.
    var kind: Int {
        switch self {
        case .searching: 0
        case .connecting: 1
        case .pairing: 2
        case .unlock: 3
        case .approve: 4
        case .working: 5
        case .success: 6
        case .failure: 7
        }
    }
}

#Preview("Searching") { PrismActivityView(.searching).frame(width: 360, height: 260) }
#Preview("Connecting") { PrismActivityView(.connecting).frame(width: 360, height: 260) }
#Preview("Pairing") { PrismActivityView(.pairing(code: "123456")).frame(width: 360, height: 260) }
#Preview("Unlock") { PrismActivityView(.unlock).frame(width: 360, height: 260) }
#Preview("Approve") { PrismActivityView(.approve).frame(width: 360, height: 260) }
#Preview("Working") { PrismActivityView(.working("Syncing…")).frame(width: 360, height: 260) }
#Preview("Success") { PrismActivityView(.success("Done")).frame(width: 360, height: 260) }
#Preview("Failure") { PrismActivityView(.failure("Could not reach your Prism")).frame(width: 360, height: 260) }
