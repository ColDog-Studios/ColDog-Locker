using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;

namespace ColDogStudios.ColDogLocker.Desktop
{
    public static class Converters
    {
        public class BooleanToStatusColorConverter : IValueConverter
        {
            public static readonly BooleanToStatusColorConverter Instance = new();

            public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
            {
                if (value is bool isLocked)
                {
                    return isLocked ? Brushes.Red : Brushes.Green;
                }
                return Brushes.Gray;
            }

            public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
            {
                throw new NotImplementedException();
            }
        }

        public class BooleanToOperationTextConverter : IValueConverter
        {
            public static readonly BooleanToOperationTextConverter Instance = new();

            public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
            {
                if (value is bool isInProgress)
                {
                    return isInProgress ? "Operation in progress..." : "Ready";
                }
                return "Ready";
            }

            public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
            {
                throw new NotImplementedException();
            }
        }

        public class BooleanToVisibilityConverter : IValueConverter
        {
            public static readonly BooleanToVisibilityConverter Instance = new();

            public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
            {
                if (value is bool boolValue)
                {
                    return boolValue ? Visibility.Visible : Visibility.Collapsed;
                }
                return Visibility.Collapsed;
            }

            public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
            {
                return value is Visibility visibility && visibility == Visibility.Visible;
            }
        }
    }

    public class InverseBooleanToVisibilityConverter : IValueConverter
    {
        public static readonly InverseBooleanToVisibilityConverter Instance = new();

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is bool boolValue)
            {
                return boolValue ? Visibility.Collapsed : Visibility.Visible;
            }
            return Visibility.Visible;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return value is Visibility visibility && visibility == Visibility.Collapsed;
        }
    }
}
