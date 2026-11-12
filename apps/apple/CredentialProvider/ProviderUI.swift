import SwiftUI
import PrismKit

/// State shown inside the AutoFill sheet.
@MainActor
final class ProviderModel: ObservableObject {
    @Published var status = "Connecting to Prism..."
    @Published var sas: String?
    @Published var activity: PrismActivity = .searching
    @Published var busy = true
    @Published var choices: [EntrySummary] = []
    @Published var error: String?
    var onPick: ((EntrySummary) -> Void)?
    var onCancel: (() -> Void)?
}

struct ProviderView: View {
    @ObservedObject var model: ProviderModel

    var body: some View {
        NavigationStack {
            content
                .toolbar {
                    ToolbarItem(placement: .principal) { PrismToolbarTitle() }
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Cancel") { model.onCancel?() }
                            .keyboardShortcut(.cancelAction) // Escape
                    }
                }
                #if os(iOS)
                .navigationBarTitleDisplayMode(.inline)
                #endif
        }
        #if os(macOS)
        .frame(minWidth: 360, minHeight: 320)
        .onExitCommand { model.onCancel?() } // Escape, even when the button isn't focusable
        #endif
    }

    @ViewBuilder private var content: some View {
        if let e = model.error {
            centered { PrismActivityView(.failure(e)) }
        } else if !model.choices.isEmpty {
            List {
                Section {
                    ForEach(model.choices) { c in
                        Button { model.onPick?(c) } label: { ChoiceRow(entry: c) }
                            .buttonStyle(.plain)
                    }
                } header: {
                    Text("Choose a login")
                }
            }
            #if os(iOS)
            .listStyle(.insetGrouped)
            #else
            .listStyle(.inset)
            #endif
        } else if model.busy {
            centered {
                PrismActivityView(model.activity)
                Text("Keep your Prism nearby and unlocked.")
                    .font(.footnote)
                    .foregroundStyle(.tertiary)
            }
        } else {
            centered {
                PrismBrandHeader(logoSize: 64)
                Text(model.status)
                    .font(.system(.callout, design: .rounded))
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }
        }
    }

    /// Vertically centred content with comfortable side margins.
    private func centered<C: View>(@ViewBuilder _ c: () -> C) -> some View {
        VStack(spacing: 16) {
            Spacer(minLength: 12)
            c()
            Spacer(minLength: 12)
        }
        .padding(.horizontal, 24)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

private struct ChoiceRow: View {
    let entry: EntrySummary

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: entry.kind == .totp ? "clock.badge.checkmark" : "key.fill")
                .font(.system(size: 15, weight: .semibold))
                .foregroundStyle(.tint)
                .frame(width: 34, height: 34)
                .background(.tint.opacity(0.14), in: RoundedRectangle(cornerRadius: 9, style: .continuous))
            VStack(alignment: .leading, spacing: 2) {
                Text(entry.title).font(.body.weight(.medium)).lineLimit(1)
                if !detail.isEmpty {
                    Text(detail).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                }
            }
            Spacer(minLength: 8)
            Image(systemName: "chevron.right").font(.caption.weight(.semibold)).foregroundStyle(.tertiary)
        }
        .padding(.vertical, 4)
        .contentShape(Rectangle())
    }

    private var detail: String {
        let host = entry.url.flatMap { URL(string: $0)?.host ?? $0 }
        return [entry.subtitle, host].compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: " · ")
    }
}
