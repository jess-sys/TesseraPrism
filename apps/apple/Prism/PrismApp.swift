import SwiftUI
import PrismKit

@main
struct PrismApp: App {
    @StateObject private var model = AppModel()

    var body: some Scene {
        WindowGroup {
            RootView().environmentObject(model)
        }
        #if os(macOS)
        MenuBarExtra("Prism", systemImage: model.isConnected ? "key.fill" : "key") {
            MenuBarView().environmentObject(model)
        }
        .menuBarExtraStyle(.window)
        SwiftUI.Settings {
            SettingsView().environmentObject(model).frame(width: 480, height: 520)
        }
        #endif
    }
}
