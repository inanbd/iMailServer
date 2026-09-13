using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using MailServer.Domain.Enums;

namespace MailServer.Admin.Resources;

/// <summary>Maps a <see cref="HealthState"/> to its brush.</summary>
/// <remarks>
/// Colour is always accompanied by the state's name in the UI. Colour alone would be
/// unreadable to a red/green colour-blind operator, which is roughly one man in twelve.
/// </remarks>
public sealed class HealthStateToBrushConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        string key = value is HealthState state
            ? state switch
            {
                HealthState.Healthy => "State.Healthy",
                HealthState.Warning => "State.Warning",
                HealthState.Critical => "State.Critical",
                _ => "State.Unknown",
            }
            : "State.Unknown";

        return System.Windows.Application.Current?.TryFindResource(key) as Brush ?? Brushes.Gray;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

/// <summary>Maps a <see cref="DomainStatus"/> to its brush, reusing the health vocabulary.</summary>
public sealed class DomainStatusToBrushConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        string key = value is DomainStatus status
            ? status switch
            {
                DomainStatus.Active => "State.Healthy",
                DomainStatus.Pending => "State.Warning",
                DomainStatus.Disabled => "State.Unknown",
                DomainStatus.PendingDeletion => "State.Critical",
                _ => "State.Unknown",
            }
            : "State.Unknown";

        return System.Windows.Application.Current?.TryFindResource(key) as Brush ?? Brushes.Gray;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

/// <summary>Formats a byte count using binary units.</summary>
public sealed class ByteSizeConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is long bytes
            ? Domain.ValueObjects.QuotaBytes.FormatBytes(bytes)
            : "-";

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

/// <summary>True becomes Visible; false becomes Collapsed.</summary>
public sealed class BoolToVisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        bool flag = value is bool b && b;

        if (parameter is string s && s.Equals("Invert", StringComparison.OrdinalIgnoreCase))
        {
            flag = !flag;
        }

        return flag ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

/// <summary>Non-empty string becomes Visible; null or whitespace becomes Collapsed.</summary>
public sealed class StringToVisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        string.IsNullOrWhiteSpace(value as string) ? Visibility.Collapsed : Visibility.Visible;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

/// <summary>Shows an element only when the server is NOT in Normal maintenance mode.</summary>
public sealed class MaintenanceModeToVisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is MaintenanceMode mode && mode != MaintenanceMode.Normal
            ? Visibility.Visible
            : Visibility.Collapsed;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

/// <summary>Inverts a boolean. Used to disable controls while a page is busy.</summary>
public sealed class InverseBooleanConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is not bool b || !b;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is bool b && !b;
}
