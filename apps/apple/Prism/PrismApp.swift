import SwiftUI
import PrismKit

@main
struct PrismApp: App {
    @StateObject private var model = AppModel()

    init() {
        #if os(macOS)
        Task { @MainActor in AgentHUDController.shared.start() }
        #endif
    }

    var body: some Scene {
        WindowGroup {
            RootView().environmentObject(model).prismBranded()
        }
        #if os(macOS)
        MenuBarExtra("Prism", systemImage: model.isConnected ? "key.fill" : "key") {
            MenuBarView().environmentObject(model).prismBranded()
        }
        .menuBarExtraStyle(.window)
        SwiftUI.Settings {
            SettingsView().environmentObject(model).frame(width: 480, height: 520).prismBranded()
        }
        #endif
    }
}
