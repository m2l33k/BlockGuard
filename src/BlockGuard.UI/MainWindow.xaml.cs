using System.Windows;
using BlockGuard.UI.ViewModels;

namespace BlockGuard.UI;

public partial class MainWindow : Window
{
    private bool _isInitialized;

    public MainWindow()
    {
        InitializeComponent();
        _isInitialized = true;
        Loaded += MainWindow_Loaded;
    }

    private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        if (DataContext is MainViewModel vm)
        {
            await vm.InitializeAsync();
        }
    }

    // ----- Page Navigation -----

    private void ShowPage(string pageName)
    {
        if (!_isInitialized) return;

        DashboardPage.Visibility = Visibility.Collapsed;
        ProtectedFilesPage.Visibility = Visibility.Collapsed;
        ActivityPage.Visibility = Visibility.Collapsed;
        SettingsPage.Visibility = Visibility.Collapsed;

        switch (pageName)
        {
            case "Dashboard":
                DashboardPage.Visibility = Visibility.Visible;
                break;
            case "ProtectedFiles":
                ProtectedFilesPage.Visibility = Visibility.Visible;
                break;
            case "Activity":
                ActivityPage.Visibility = Visibility.Visible;
                break;
            case "Settings":
                SettingsPage.Visibility = Visibility.Visible;
                break;
        }
    }

    private void Nav_Dashboard(object sender, RoutedEventArgs e) => ShowPage("Dashboard");
    private void Nav_ProtectedFiles(object sender, RoutedEventArgs e) => ShowPage("ProtectedFiles");
    private void Nav_Activity(object sender, RoutedEventArgs e) => ShowPage("Activity");
    private void Nav_Settings(object sender, RoutedEventArgs e) => ShowPage("Settings");
}