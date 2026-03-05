// -----------------------------------------------------------------------
// BlockGuard.UI - InverseBoolConverter.cs
// Value converter that inverts a boolean value.
// Used to disable the toggle switch while the agent is being toggled.
// -----------------------------------------------------------------------

using System.Globalization;
using System.Windows.Data;

namespace BlockGuard.UI;

/// <summary>
/// Converts true → false and false → true.
/// Used as {x:Static local:InverseBoolConverter.Instance} in XAML.
/// </summary>
public sealed class InverseBoolConverter : IValueConverter
{
    public static readonly InverseBoolConverter Instance = new();

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is bool b)
            return !b;
        return value;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is bool b)
            return !b;
        return value;
    }
}
