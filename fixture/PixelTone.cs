using System;
using System.Globalization;
using System.Runtime.CompilerServices;

namespace Dysphasia.Fixture
{
    internal static class PixelTone
    {
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static int ClampByte(int value)
        {
            return value < 0 ? 0 : value > 255 ? 255 : value;
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static int AdjustChannel(int value, int brightness, int contrast)
        {
            return ClampByte(((value - 128) * contrast) / 100 + 128 + brightness);
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static int[] ApplyPreset(int r, int g, int b, string preset)
        {
            if (preset == "mono")
            {
                int y = (77 * r + 150 * g + 29 * b + 128) >> 8;
                return new int[] { y, y, y };
            }
            if (preset == "warm")
                return new int[] { ClampByte(r + 12), ClampByte(g + 3), ClampByte(b - 9) };
            return new int[] { r, g, b };
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static uint Fingerprint(int[] channels)
        {
            uint h = 2166136261U;
            for (int i = 0; i < channels.Length; i++)
                h = unchecked((h ^ (uint)channels[i]) * 16777619U);
            return h;
        }

        private static int ReadInt(string text, int minimum, int maximum)
        {
            int value;
            if (!Int32.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out value)
                || value < minimum || value > maximum)
                throw new ArgumentException("integer out of range");
            return value;
        }

        private static int Main(string[] args)
        {
            if (args.Length == 1 && args[0] == "--help")
            {
                Console.WriteLine("PixelTone R G B brightness contrast preset");
                Console.WriteLine("R/G/B: 0..255; brightness: -100..100; contrast: 0..200; preset: neutral|mono|warm");
                return 0;
            }
            try
            {
                if (args.Length != 6) throw new ArgumentException("expected 6 arguments; use --help");
                int r = ReadInt(args[0], 0, 255);
                int g = ReadInt(args[1], 0, 255);
                int b = ReadInt(args[2], 0, 255);
                int brightness = ReadInt(args[3], -100, 100);
                int contrast = ReadInt(args[4], 0, 200);
                string preset = args[5];
                if (preset != "neutral" && preset != "mono" && preset != "warm")
                    throw new ArgumentException("unknown preset");
                int[] result = ApplyPreset(AdjustChannel(r, brightness, contrast),
                    AdjustChannel(g, brightness, contrast), AdjustChannel(b, brightness, contrast), preset);
                Console.WriteLine("{0},{1},{2}|{3:X8}", result[0], result[1], result[2], Fingerprint(result));
                return 0;
            }
            catch (ArgumentException ex)
            {
                Console.Error.WriteLine("ERROR: " + ex.Message);
                return 2;
            }
        }
    }
}
