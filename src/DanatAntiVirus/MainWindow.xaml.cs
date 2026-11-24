using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;

namespace DanatAntiVirus
{
    public partial class MainWindow : Window
    {
        private string _scanTarget;
        private bool _scanRunning;

        public MainWindow()
        {
            InitializeComponent();
            Loaded += async (s, e) => await RefreshDefenderStatusAsync();
        }

        private void ChooseFolder_Click(object sender, RoutedEventArgs e)
        {
            using (var dialog = new System.Windows.Forms.FolderBrowserDialog())
            {
                dialog.Description = "Choose a file or folder for Microsoft Defender to scan";
                dialog.ShowNewFolderButton = false;
                if (dialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
                {
                    _scanTarget = dialog.SelectedPath;
                    TargetFolderText.Text = _scanTarget;
                }
            }
        }

        private async void RefreshStatus_Click(object sender, RoutedEventArgs e)
        {
            await RefreshDefenderStatusAsync();
        }

        private async Task RefreshDefenderStatusAsync()
        {
            RefreshStatusButton.IsEnabled = false;
            DefenderStatusText.Text = "Checking Microsoft Defender status…";
            try
            {
                string result = await Task.Run(GetDefenderStatus);
                string[] fields = result.Split('|');
                if (fields.Length >= 2 && fields[0] == "DANAT_UNAVAILABLE")
                {
                    DefenderStatusText.Text = "DEFENDER STATUS UNAVAILABLE — " + fields[1];
                    DefenderStatusText.Foreground = new SolidColorBrush(Color.FromRgb(255, 198, 92));
                    SignatureAgeText.Text = "Danat will not claim that real-time protection is active until Windows Defender can be verified.";
                    return;
                }
                if (fields.Length != 6 || fields[0] != "DANAT")
                    throw new InvalidOperationException("Windows did not return a valid Defender status.");

                string mode = fields[1];
                bool service = ParseBoolean(fields[2]);
                bool antivirus = ParseBoolean(fields[3]);
                bool realtime = ParseBoolean(fields[4]);
                string signatureAge = fields[5];
                long signatureAgeDays;
                if (!long.TryParse(signatureAge, out signatureAgeDays) || signatureAgeDays < 0)
                    throw new InvalidOperationException("Defender returned an unreadable security-intelligence age.");

                if (mode.Equals("Normal", StringComparison.OrdinalIgnoreCase) && service && antivirus && realtime && signatureAgeDays <= 3)
                {
                    DefenderStatusText.Text = "ACTIVE — Microsoft Defender Antivirus is running in normal mode; real-time protection is enabled and signatures are recent.";
                    DefenderStatusText.Foreground = new SolidColorBrush(Color.FromRgb(112, 210, 133));
                }
                else if (mode.Equals("Normal", StringComparison.OrdinalIgnoreCase) && service && antivirus && realtime && signatureAgeDays > 3)
                {
                    DefenderStatusText.Text = "WARNING — real-time protection is enabled, but security intelligence is older than 3 days. Update Defender before relying on this PC for protection.";
                    DefenderStatusText.Foreground = new SolidColorBrush(Color.FromRgb(255, 198, 92));
                }
                else if (mode.IndexOf("Passive", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    DefenderStatusText.Text = "PASSIVE MODE — another antivirus may be the primary provider. Defender is not confirmed as the active real-time protector.";
                    DefenderStatusText.Foreground = new SolidColorBrush(Color.FromRgb(255, 198, 92));
                }
                else
                {
                    DefenderStatusText.Text = "NOT FULLY ACTIVE — service: " + service + ", antivirus: " + antivirus + ", real-time protection: " + realtime + ", mode: " + mode;
                    DefenderStatusText.Foreground = new SolidColorBrush(Color.FromRgb(255, 120, 100));
                }

                SignatureAgeText.Text = "Security intelligence age: " + signatureAge + " day(s). Windows manages Defender updates.";
            }
            catch (Exception ex)
            {
                DefenderStatusText.Text = "STATUS UNAVAILABLE — " + ex.Message;
                DefenderStatusText.Foreground = new SolidColorBrush(Color.FromRgb(255, 120, 100));
                SignatureAgeText.Text = "Danat cannot confirm that Microsoft Defender protection is active.";
            }
            finally
            {
                RefreshStatusButton.IsEnabled = true;
            }
        }

        private static string GetDefenderStatus()
        {
            const string script = "$ErrorActionPreference='Stop'; try { Import-Module Defender -ErrorAction Stop; $s=Get-MpComputerStatus -ErrorAction Stop; Write-Output ('DANAT|' + [string]$s.AMRunningMode + '|' + [string]$s.AMServiceEnabled + '|' + [string]$s.AntivirusEnabled + '|' + [string]$s.RealTimeProtectionEnabled + '|' + [string]$s.AntivirusSignatureAge) } catch { $m=$_.Exception.Message -replace '[\\r\\n|]+',' '; Write-Output ('DANAT_UNAVAILABLE|' + $m); exit 0 }";
            var info = new ProcessStartInfo
            {
                FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe"),
                Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command " + QuoteArgument(script),
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            using (var process = Process.Start(info))
            {
                Task<string> outputTask = process.StandardOutput.ReadToEndAsync();
                Task<string> errorTask = process.StandardError.ReadToEndAsync();
                if (!process.WaitForExit(20000))
                {
                    process.Kill();
                    throw new TimeoutException("Defender status check timed out.");
                }
                Task.WaitAll(outputTask, errorTask);
                string output = outputTask.Result.Trim();
                string error = errorTask.Result.Trim();
                if (process.ExitCode != 0)
                    throw new InvalidOperationException(string.IsNullOrWhiteSpace(error) ? "Get-MpComputerStatus failed." : error);
                return output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).LastOrDefault() ?? string.Empty;
            }
        }

        private static bool ParseBoolean(string value)
        {
            bool parsed;
            if (!bool.TryParse(value, out parsed))
                throw new InvalidOperationException("Defender returned an unreadable status value.");
            return parsed;
        }

        private static string FindMpCmdRun()
        {
            string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            string platformRoot = Path.Combine(programData, "Microsoft", "Windows Defender", "Platform");
            if (Directory.Exists(platformRoot))
            {
                var versions = Directory.GetDirectories(platformRoot)
                    .Select(path => new { Path = path, Version = ParseVersion(Path.GetFileName(path)) })
                    .Where(item => item.Version != null)
                    .OrderByDescending(item => item.Version)
                    .ToList();

                foreach (var item in versions)
                {
                    string candidate = Path.Combine(item.Path, "MpCmdRun.exe");
                    if (File.Exists(candidate)) return candidate;
                }
            }

            string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            string programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
            string[] fallbacks =
            {
                Path.Combine(programFiles, "Windows Defender", "MpCmdRun.exe"),
                Path.Combine(programFilesX86, "Windows Defender", "MpCmdRun.exe"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "Microsoft", "Windows Defender", "Platform", "MpCmdRun.exe")
            };
            foreach (string fallback in fallbacks)
                if (File.Exists(fallback)) return fallback;
            return null;
        }

        private static Version ParseVersion(string value)
        {
            Version version;
            return Version.TryParse(value, out version) ? version : null;
        }

        private async void StartScan_Click(object sender, RoutedEventArgs e)
        {
            if (_scanRunning) return;
            if (string.IsNullOrWhiteSpace(_scanTarget) || !Directory.Exists(_scanTarget) && !File.Exists(_scanTarget))
            {
                SetScanStatus("Choose an existing file or folder first.", true);
                return;
            }

            string scanner = FindMpCmdRun();
            if (scanner == null)
            {
                SetScanStatus("Microsoft Defender's scan engine (MpCmdRun.exe) was not found. This PC may not have Microsoft Defender Antivirus installed or enabled. Danat cannot scan files without the genuine Microsoft Defender engine.", true);
                return;
            }

            bool allowRemediation = AllowRemediationCheckBox.IsChecked == true;
            if (allowRemediation)
            {
                MessageBoxResult consent = MessageBox.Show(
                    "You are authorizing Microsoft Defender to take its normal action on threats found in this scan. Defender may quarantine or remove detected files. Continue?",
                    "Authorize Defender remediation",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Warning);
                if (consent != MessageBoxResult.Yes) return;
            }

            _scanRunning = true;
            StartScanButton.IsEnabled = false;
            ChooseFolderButton.IsEnabled = false;
            ScanLogBox.Clear();
            SetScanStatus("Starting Microsoft Defender custom scan… Windows may display a security prompt.", false);

            try
            {
                int exitCode = await RunDefenderScanAsync(scanner, _scanTarget, allowRemediation);
                if (exitCode == 0)
                    SetScanStatus(allowRemediation
                        ? "Defender completed the scan (exit code 0). Defender reports no unresolved threat; review Windows Security Protection history for any actions taken."
                        : "Defender completed the report-only scan (exit code 0). Review the scan output above; detected files were not remediated by this scan request.", false);
                else if (exitCode == 2)
                    SetScanStatus("Defender returned exit code 2. A threat may remain unremediated, user action may be required, or a scan error occurred. Treat this result as unresolved; inspect scan output and Protection history.", true);
                else
                    SetScanStatus("Defender scan returned unexpected exit code " + exitCode + ". Treat this result as unresolved.", true);
            }
            catch (Exception ex)
            {
                SetScanStatus("Defender scan could not be completed: " + ex.Message, true);
                AppendLog(ex.ToString());
            }
            finally
            {
                _scanRunning = false;
                StartScanButton.IsEnabled = true;
                ChooseFolderButton.IsEnabled = true;
            }
        }

        private async Task<int> RunDefenderScanAsync(string scanner, string target, bool allowRemediation)
        {
            var info = new ProcessStartInfo
            {
                FileName = scanner,
                Arguments = "-Scan -ScanType 3 -File " + QuoteArgument(target) + (allowRemediation ? string.Empty : " -DisableRemediation"),
                WorkingDirectory = Path.GetDirectoryName(scanner),
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            using (var process = new Process { StartInfo = info, EnableRaisingEvents = true })
            {
                process.OutputDataReceived += (s, e) =>
                {
                    if (!string.IsNullOrEmpty(e.Data))
                        Dispatcher.BeginInvoke(new Action(() => AppendLog(e.Data)));
                };
                process.ErrorDataReceived += (s, e) =>
                {
                    if (!string.IsNullOrEmpty(e.Data))
                        Dispatcher.BeginInvoke(new Action(() => AppendLog("ERROR: " + e.Data)));
                };

                if (!process.Start())
                    throw new InvalidOperationException("Windows could not start Microsoft Defender.");

                process.BeginOutputReadLine();
                process.BeginErrorReadLine();
                await Task.Run(() => process.WaitForExit());
                process.WaitForExit();
                return process.ExitCode;
            }
        }

        private void OpenProtectionHistory_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "ms-settings:windowsdefender-threats",
                    UseShellExecute = true
                });
            }
            catch (Exception ex)
            {
                SetScanStatus("Could not open Windows Security Protection history: " + ex.Message, true);
            }
        }

        private static string QuoteArgument(string value)
        {
            var result = new StringBuilder("\"");
            int slashes = 0;
            foreach (char c in value)
            {
                if (c == '\\') { slashes++; continue; }
                if (c == '"')
                {
                    result.Append('\\', slashes * 2 + 1);
                    result.Append('"');
                    slashes = 0;
                    continue;
                }
                if (slashes > 0) { result.Append('\\', slashes); slashes = 0; }
                result.Append(c);
            }
            if (slashes > 0) result.Append('\\', slashes * 2);
            result.Append('"');
            return result.ToString();
        }

        private void SetScanStatus(string message, bool warning)
        {
            ScanStatusText.Text = message;
            ScanStatusText.Foreground = warning
                ? new SolidColorBrush(Color.FromRgb(255, 198, 92))
                : new SolidColorBrush(Color.FromRgb(112, 210, 133));
        }

        private void AppendLog(string line)
        {
            ScanLogBox.AppendText(line + Environment.NewLine);
            ScanLogBox.ScrollToEnd();
        }
    }
}
