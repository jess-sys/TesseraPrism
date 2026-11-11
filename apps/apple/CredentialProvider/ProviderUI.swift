import SwiftUI
import PrismKit

/// State shown inside the AutoFill sheet.
@MainActor
final class ProviderModel: ObservableObject {
    @Published var status = "Connecting to Prism..."
    @Published var sas: String?
    @Published var busy = true
    @Published var choices: [EntrySummary] = []
    @Published var error: String?
    var onPick: ((EntrySummary) -> Void)?
    var onCancel: (() -> Void)?
}

struct ProviderView: View {
    @ObservedObject var model: ProviderModel

    var body: some View {
        VStack(spacing: 16) {
            HStack {
                Text("Prism").font(.headline)
                Spacer()
                Button("Cancel") { model.onCancel?() }
            }
            if let sas = model.sas {
                Text("Pairing code").font(.subheadline)
                Text(sas).font(.system(size: 40, weight: .bold, design: .monospaced))
                Text("Confirm on your Prism.").foregroundStyle(.secondary)
            }
            if let e = model.error {
                Text(e).foregroundStyle(.red).multilineTextAlignment(.center)
            } else if !model.choices.isEmpty {
                List(model.choices) { c in
                    Button { model.onPick?(c) } label: {
                        VStack(alignment: .leading) { Text(c.title); Text(c.subtitle).font(.caption).foregroundStyle(.secondary) }
                    }
                }
            } else {
                if model.busy { ProgressView() }
                Text(model.status).foregroundStyle(.secondary).multilineTextAlignment(.center)
            }
            Spacer(minLength: 0)
        }
        .padding()
        .frame(minWidth: 320, minHeight: 280)
    }
}
