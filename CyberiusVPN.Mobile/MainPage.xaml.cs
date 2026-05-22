#if ANDROID
using Android.Content;
using CyberiusVPN.Mobile.Platforms.Android;
#endif

namespace CyberiusVPN.Mobile;

public partial class MainPage : ContentPage
{
    private bool _isConnected = false;

    public MainPage()
    {
        InitializeComponent();
        LoadSavedSettings();
    }

    private async void OnConnectClicked(object sender, EventArgs e)
    {
        if (_isConnected)
        {
            DisconnectVpn();
        }
        else
        {
            if (!ValidateInputs()) return;
            await ConnectVpnAsync();
        }
    }

    private async Task ConnectVpnAsync()
    {
        // Запрашиваем разрешение VPN у пользователя
#if ANDROID
        var intent = Android.Net.VpnService.Prepare(
            Platform.CurrentActivity!.ApplicationContext);

        if (intent != null)
        {
            // Нужно разрешение пользователя
            Platform.CurrentActivity.StartActivityForResult(intent, 0);
            await Task.Delay(500);
        }

        // Сохраняем настройки
        SaveSettings();

        // Запускаем VPN сервис
        var serviceIntent = new Intent(
            Platform.CurrentActivity.ApplicationContext,
            typeof(CyberiusVpnService));

        serviceIntent.SetAction(CyberiusVpnService.ActionStart);
        serviceIntent.PutExtra(CyberiusVpnService.ExtraServer, ServerEntry.Text);
        serviceIntent.PutExtra(CyberiusVpnService.ExtraPort, int.Parse(PortEntry.Text));
        serviceIntent.PutExtra(CyberiusVpnService.ExtraPubKey, PubKeyEntry.Text);
        serviceIntent.PutExtra(CyberiusVpnService.ExtraPrivKey, PrivKeyEntry.Text);
        serviceIntent.PutExtra(CyberiusVpnService.ExtraSni, SniEntry.Text);

        Platform.CurrentActivity.ApplicationContext
            .StartForegroundService(serviceIntent);
#endif
        SetConnectedState(true);
    }

    private void DisconnectVpn()
    {
#if ANDROID
        var serviceIntent = new Intent(
            Platform.CurrentActivity!.ApplicationContext,
            typeof(CyberiusVpnService));
        serviceIntent.SetAction(CyberiusVpnService.ActionStop);
        Platform.CurrentActivity.ApplicationContext
            .StartService(serviceIntent);
#endif
        SetConnectedState(false);
    }

    private void SetConnectedState(bool connected)
    {
        _isConnected = connected;

        StatusLabel.Text = connected ? "Подключено" : "Отключено";
        StatusLabel.TextColor = connected
            ? Color.FromArgb("#00B4D8")
            : Color.FromArgb("#E94560");
        StatusIcon.Text = connected ? "🔓" : "🔒";
        ConnectBtn.Text = connected ? "Отключить" : "Подключить";
        ConnectBtn.BackgroundColor = connected
            ? Color.FromArgb("#00B4D8")
            : Color.FromArgb("#E94560");

        IpLabel.Text = connected ? $"Сервер: {ServerEntry.Text}" : "";
    }

    private bool ValidateInputs()
    {
        if (string.IsNullOrWhiteSpace(ServerEntry.Text))
        {
            DisplayAlertAsync("Ошибка", "Введите адрес сервера", "OK");
            return false;
        }
        if (string.IsNullOrWhiteSpace(PubKeyEntry.Text))
        {
            DisplayAlertAsync("Ошибка", "Введите публичный ключ сервера", "OK");
            return false;
        }
        if (string.IsNullOrWhiteSpace(PrivKeyEntry.Text))
        {
            DisplayAlertAsync("Ошибка", "Введите приватный ключ клиента", "OK");
            return false;
        }
        return true;
    }

    private void SaveSettings()
    {
        Preferences.Set("server", ServerEntry.Text);
        Preferences.Set("port", PortEntry.Text);
        Preferences.Set("sni", SniEntry.Text);
        Preferences.Set("pub_key", PubKeyEntry.Text);
        Preferences.Set("priv_key", PrivKeyEntry.Text);
    }

    private void LoadSavedSettings()
    {
        ServerEntry.Text = Preferences.Get("server", "service.cyberius.site");
        PortEntry.Text = Preferences.Get("port", "3443");
        SniEntry.Text = Preferences.Get("sni", "www.microsoft.com");
        PubKeyEntry.Text = Preferences.Get("pub_key", "");
        PrivKeyEntry.Text = Preferences.Get("priv_key", "");
    }
}