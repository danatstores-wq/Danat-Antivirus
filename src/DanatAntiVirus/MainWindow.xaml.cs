using System;
using System.Diagnostics;
using System.IO;
using System.Globalization;
using System.Text.RegularExpressions;
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
        private bool _maintenanceRunning;

        public MainWindow()
        {
            InitializeComponent();
            Loaded += async (s, e) =>
            {
                await RefreshDefenderStatusAsync();
                await RefreshControlledFolderAccessAsync();
                SetupClamAVButton.Content = FindClamScan() == null ? "SET UP CLAMAV" : "UPDATE CLAMAV";
            };
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
            if (_scanRunning || _maintenanceRunning) return;
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
                        ? "Defender scan process completed successfully (exit code 0). Review Windows Security Protection history for detections and any actions taken; Danat does not infer that the device is clean from the exit code alone."
                        : "Defender report-only scan process completed (exit code 0). No remediation was authorized by Danat. Review Windows Security Protection history for detections; Danat does not infer that the device is clean from the exit code alone.", false);
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

        private static Version GetClamAVVersion(string scanner)
        {
            var info = new ProcessStartInfo
            {
                FileName = scanner,
                Arguments = "--version",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            using (var process = Process.Start(info))
            {
                if (process == null)
                    throw new InvalidOperationException("Windows could not start ClamAV to check its version.");
                Task<string> outputTask = process.StandardOutput.ReadToEndAsync();
                Task<string> errorTask = process.StandardError.ReadToEndAsync();
                if (!process.WaitForExit(10000))
                {
                    try { process.Kill(); } catch { }
                    throw new TimeoutException("ClamAV version check timed out.");
                }
                Task.WaitAll(outputTask, errorTask);
                if (process.ExitCode != 0)
                    throw new InvalidOperationException("ClamAV version check failed: " + errorTask.Result.Trim());
                Match match = Regex.Match(outputTask.Result, @"ClamAV\s+(\d+\.\d+\.\d+)", RegexOptions.IgnoreCase);
                Version version;
                if (!match.Success || !Version.TryParse(match.Groups[1].Value, out version))
                    throw new InvalidOperationException("Danat could not verify the installed ClamAV version.");
                return version;
            }
        }

        private static void RequireSecureClamAVVersion(string scanner)
        {
            Version installed = GetClamAVVersion(scanner);
            Version minimum = new Version(1, 5, 5);
            if (installed < minimum)
                throw new InvalidOperationException("ClamAV " + installed + " is too old for this Danat preview. Version 1.5.5 or later is required because it includes fixes for security vulnerabilities affecting earlier releases. Select UPDATE CLAMAV before scanning.");
        }

        private static string FindClamScan()
        {
            string pathValue = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
            foreach (string entry in pathValue.Split(Path.PathSeparator))
            {
                string directory = entry.Trim().Trim('"');
                if (directory.Length == 0) continue;
                string candidate = Path.Combine(directory, "clamscan.exe");
                if (File.Exists(candidate)) return candidate;
            }
            string pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            string pf86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
            string[] candidates = {
                Path.Combine(pf, "ClamAV", "clamscan.exe"),
                Path.Combine(pf86, "ClamAV", "clamscan.exe")
            };
            return candidates.FirstOrDefault(File.Exists);
        }


        private static string FindWinget()
        {
            // App Installer exposes WinGet through this per-user execution-alias path.
            // Check it directly because WindowsApps is not always present in a process PATH.
            string windowsApps = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Microsoft", "WindowsApps", "winget.exe");
            if (File.Exists(windowsApps)) return windowsApps;

            var info = new ProcessStartInfo
            {
                FileName = "where.exe",
                Arguments = "winget.exe",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using (var process = Process.Start(info))
            {
                if (process == null) return null;
                Task<string> outputTask = process.StandardOutput.ReadToEndAsync();
                if (!process.WaitForExit(5000))
                {
                    try { process.Kill(); } catch { }
                    return null;
                }
                string output = outputTask.GetAwaiter().GetResult();
                return output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                    .Select(path => path.Trim())
                    .FirstOrDefault(File.Exists);
            }
        }

        private static string GetClamDatabaseDirectory()
        {
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "DanatAntiVirus", "ClamAV", "Database");
        }


        private static bool ClamDatabaseNeedsUpdate()
        {
            string database = GetClamDatabaseDirectory();
            bool hasDatabase = Directory.Exists(database) &&
                (Directory.GetFiles(database, "*.cvd").Length > 0 || Directory.GetFiles(database, "*.cld").Length > 0);
            if (!hasDatabase) return true;

            string marker = Path.Combine(database, ".last-successful-update");
            if (!File.Exists(marker)) return true;
            DateTime lastUpdate;
            if (!DateTime.TryParse(File.ReadAllText(marker), CultureInfo.InvariantCulture,
                DateTimeStyles.RoundtripKind, out lastUpdate))
                return true;
            return DateTime.UtcNow - lastUpdate.ToUniversalTime() >= TimeSpan.FromHours(4);
        }

        private static string EnsureClamFreshclamConfig(string scanner)
        {
            string root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "DanatAntiVirus", "ClamAV");
            string database = GetClamDatabaseDirectory();
            Directory.CreateDirectory(root);
            Directory.CreateDirectory(database);

            string config = Path.Combine(root, "freshclam.conf");
            string scannerDirectory = Path.GetDirectoryName(scanner);
            string certs = Path.Combine(scannerDirectory, "certs");
            var contents = new StringBuilder();
            contents.AppendLine("# Managed by Danat Anti-Virus. Do not add credentials to this file.");
            contents.AppendLine("DatabaseDirectory \"" + database + "\"");
            contents.AppendLine("DatabaseMirror database.clamav.net");
            contents.AppendLine("DNSDatabaseInfo current.cvd.clamav.net");
            contents.AppendLine("ConnectTimeout 30");
            contents.AppendLine("ReceiveTimeout 90");
            contents.AppendLine("ScriptedUpdates yes");
            contents.AppendLine("LogTime yes");
            if (Directory.Exists(certs))
                contents.AppendLine("CVDCertsDirectory \"" + certs + "\"");
            File.WriteAllText(config, contents.ToString(), Encoding.UTF8);
            return config;
        }

        private async Task<int> RunFreshClamAsync(string freshclam, string config)
        {
            var info = new ProcessStartInfo
            {
                FileName = freshclam,
                Arguments = "--config-file=" + QuoteArgument(config),
                WorkingDirectory = Path.GetDirectoryName(freshclam),
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
                        Dispatcher.BeginInvoke(new Action(() => AppendLog("CLAMAV UPDATE: " + e.Data)));
                };
                process.ErrorDataReceived += (s, e) =>
                {
                    if (!string.IsNullOrEmpty(e.Data))
                        Dispatcher.BeginInvoke(new Action(() => AppendLog("CLAMAV UPDATE: " + e.Data)));
                };
                if (!process.Start()) throw new InvalidOperationException("Windows could not start ClamAV FreshClam.");
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();
                bool exited = await Task.Run(() => process.WaitForExit(600000));
                if (!exited)
                {
                    try { process.Kill(); } catch { }
                    throw new TimeoutException("ClamAV signature update exceeded 10 minutes.");
                }
                process.WaitForExit();
                if (process.ExitCode == 0)
                {
                    string marker = Path.Combine(GetClamDatabaseDirectory(), ".last-successful-update");
                    File.WriteAllText(marker, DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture));
                }
                return process.ExitCode;
            }
        }

        private async Task<int> RunWingetInstallAsync(string winget, bool upgrade)
        {
            var info = new ProcessStartInfo
            {
                FileName = winget,
                Arguments = upgrade
                    ? "upgrade --id Cisco.ClamAV --exact --source winget"
                    : "install --id Cisco.ClamAV --exact --source winget",
                UseShellExecute = true,
                CreateNoWindow = false
            };
            using (var process = Process.Start(info))
            {
                if (process == null) throw new InvalidOperationException("Windows could not start Windows Package Manager.");
                bool exited = await Task.Run(() => process.WaitForExit(1200000));
                if (!exited)
                {
                    try { process.Kill(); } catch { }
                    throw new TimeoutException("ClamAV setup or update exceeded 20 minutes.");
                }
                return process.ExitCode;
            }
        }

        private async void SetupClamAV_Click(object sender, RoutedEventArgs e)
        {
            if (_scanRunning) return;
            string scanner = FindClamScan();
            bool alreadyInstalled = scanner != null;
            string action = alreadyInstalled ? "check for and install an available ClamAV engine update" : "download and install ClamAV from the Cisco-Talos official release";
            MessageBoxResult consent = MessageBox.Show(
                "Danat Anti-Virus will use Windows Package Manager to " + action + ". Windows may display an installation or license confirmation. The community-maintained Cisco.ClamAV WinGet manifest points to the official Cisco-Talos ClamAV GitHub release and provides the SHA-256 hash checked by WinGet. The manifest is not maintained by Cisco and does not imply Cisco endorsement of Danat. ClamAV is separate GPL-2.0 software; Danat does not bundle, modify, or link to it. Continue?",
                "Danat ClamAV setup",
                MessageBoxButton.YesNo,
                MessageBoxImage.Information);
            if (consent != MessageBoxResult.Yes) return;

            string winget;
            try { winget = FindWinget(); }
            catch (Exception ex)
            {
                SetScanStatus("Could not check for Windows Package Manager: " + ex.Message, true);
                return;
            }
            if (winget == null)
            {
                SetScanStatus("Windows Package Manager (WinGet) is not available on this Windows account. Danat cannot securely automate ClamAV setup on this PC.", true);
                return;
            }

            _scanRunning = true;
            SetupClamAVButton.IsEnabled = false;
            ClamScanButton.IsEnabled = false;
            ChooseFolderButton.IsEnabled = false;
            ScanLogBox.Clear();
            try
            {
                SetScanStatus(alreadyInstalled ? "Checking for a ClamAV engine update…" : "Installing ClamAV through Windows Package Manager… follow any Windows or license prompts.", false);
                int installCode = await RunWingetInstallAsync(winget, alreadyInstalled);
                if (installCode != 0)
                {
                    SetScanStatus("ClamAV setup/update did not complete (WinGet exit code " + installCode + "). No scan was started.", true);
                    return;
                }

                scanner = FindClamScan();
                if (scanner == null)
                {
                    for (int attempt = 0; attempt < 20 && scanner == null; attempt++)
                    {
                        await Task.Delay(1000);
                        scanner = FindClamScan();
                    }
                }
                if (scanner == null)
                    throw new InvalidOperationException("WinGet completed, but Danat could not locate clamscan.exe.");

                RequireSecureClamAVVersion(scanner);
                string freshclam = Path.Combine(Path.GetDirectoryName(scanner), "freshclam.exe");
                if (!File.Exists(freshclam))
                    throw new FileNotFoundException("The ClamAV installation did not include freshclam.exe.", freshclam);

                string config = EnsureClamFreshclamConfig(scanner);
                SetScanStatus("ClamAV is installed. Downloading and verifying the latest virus signatures…", false);
                int updateCode = await RunFreshClamAsync(freshclam, config);
                if (updateCode != 0)
                    throw new InvalidOperationException("FreshClam returned exit code " + updateCode + ". The signature database is not confirmed current.");

                SetScanStatus("ClamAV is installed and its virus signatures are updated. Danat checks signature freshness before each ClamAV scan and refreshes at least every four hours.", false);
                SetupClamAVButton.Content = "UPDATE CLAMAV";
            }
            catch (Exception ex)
            {
                SetScanStatus("ClamAV setup/update failed: " + ex.Message, true);
                AppendLog(ex.ToString());
            }
            finally
            {
                _scanRunning = false;
                SetupClamAVButton.IsEnabled = true;
                ClamScanButton.IsEnabled = true;
                ChooseFolderButton.IsEnabled = true;
            }
        }

        private async void ClamScan_Click(object sender, RoutedEventArgs e)
        {
            if (_scanRunning) return;
            if (string.IsNullOrWhiteSpace(_scanTarget) || (!Directory.Exists(_scanTarget) && !File.Exists(_scanTarget)))
            {
                SetScanStatus("Choose an existing file or folder first.", true);
                return;
            }
            string scanner = FindClamScan();
            if (scanner == null)
            {
                SetScanStatus("ClamAV is not set up yet. Use the SET UP CLAMAV button; Danat will handle installation and signature configuration.", true);
                return;
            }
            try
            {
                RequireSecureClamAVVersion(scanner);
            }
            catch (Exception ex)
            {
                SetScanStatus("ClamAV version check failed: " + ex.Message, true);
                return;
            }
            string freshclam = Path.Combine(Path.GetDirectoryName(scanner), "freshclam.exe");
            if (!File.Exists(freshclam))
            {
                SetScanStatus("ClamAV FreshClam updater was not found. Use UPDATE CLAMAV to repair the setup.", true);
                return;
            }
            _scanRunning = true;
            StartScanButton.IsEnabled = false;
            ClamScanButton.IsEnabled = false;
            SetupClamAVButton.IsEnabled = false;
            ChooseFolderButton.IsEnabled = false;
            ScanLogBox.Clear();
            SetScanStatus("Updating ClamAV virus signatures before the on-demand scan…", false);
            try
            {
                string config = EnsureClamFreshclamConfig(scanner);
                if (ClamDatabaseNeedsUpdate())
                {
                    int updateCode = await RunFreshClamAsync(freshclam, config);
                    if (updateCode != 0)
                    {
                        SetScanStatus("ClamAV signature update failed (exit code " + updateCode + "). Scan cancelled because current signatures could not be confirmed.", true);
                        return;
                    }
                }
                else
                {
                    AppendLog("ClamAV signatures were successfully checked within the last four hours; no repeat download was needed.");
                }
                SetScanStatus("Signatures are current. Starting ClamAV on-demand scan. This is not real-time protection.", false);
                int code = await RunClamScanAsync(scanner, _scanTarget, GetClamDatabaseDirectory());
                if (code == 0)
                    SetScanStatus("ClamAV reported no infected files in this scan. This does not guarantee the system is malware-free.", false);
                else if (code == 1)
                    SetScanStatus("ClamAV reported infected file(s). Review the output. Danat has not deleted or quarantined anything.", true);
                else
                    SetScanStatus("ClamAV returned error code " + code + ". Treat this scan as incomplete.", true);
            }
            catch (Exception ex)
            {
                SetScanStatus("ClamAV scan could not be completed: " + ex.Message, true);
                AppendLog(ex.ToString());
            }
            finally
            {
                _scanRunning = false;
                StartScanButton.IsEnabled = true;
                ClamScanButton.IsEnabled = true;
                SetupClamAVButton.IsEnabled = true;
                ChooseFolderButton.IsEnabled = true;
            }
        }

        private async Task<int> RunClamScanAsync(string scanner, string target, string databaseDirectory)
        {
            var info = new ProcessStartInfo
            {
                FileName = scanner,
                Arguments = "--database=" + QuoteArgument(databaseDirectory) + " --infected --no-summary --stdout " + QuoteArgument(target),
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
                        Dispatcher.BeginInvoke(new Action(() => AppendLog("CLAMAV: " + e.Data)));
                };
                if (!process.Start()) throw new InvalidOperationException("Windows could not start ClamAV.");
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();
                // Bound the scan duration so an unresponsive scanner cannot leave Danat
                // appearing busy forever. A timeout is reported as an incomplete scan.
                bool exited = await Task.Run(() => process.WaitForExit(4 * 60 * 60 * 1000));
                if (!exited)
                {
                    try { process.Kill(); } catch { }
                    throw new TimeoutException("ClamAV scan exceeded four hours and was stopped. Treat the scan as incomplete.");
                }
                process.WaitForExit();
                return process.ExitCode;
            }
        }

        private async Task<int> RunDefenderScanAsync(string scanner, string target, bool allowRemediation)
        {
            // MpCmdRun requires elevation. Elevate only this Microsoft-signed scan process;
            // the Danat UI and ClamAV scanner remain at the signed-in user's privilege level.
            var info = new ProcessStartInfo
            {
                FileName = scanner,
                Arguments = "-Scan -ScanType 3 -File " + QuoteArgument(target) + (allowRemediation ? string.Empty : " -DisableRemediation"),
                WorkingDirectory = Path.GetDirectoryName(scanner),
                UseShellExecute = true,
                Verb = "runas",
                CreateNoWindow = false
            };

            using (var process = Process.Start(info))
            {
                if (process == null)
                    throw new InvalidOperationException("Windows could not start Microsoft Defender. Approve the Windows elevation prompt to continue.");
                AppendLog("Microsoft Defender scan started in a separately elevated process. Danat and ClamAV remain unelevated.");
                bool exited = await Task.Run(() => process.WaitForExit(30 * 60 * 1000));
                if (!exited)
                {
                    try { process.Kill(); } catch { }
                    throw new TimeoutException("Microsoft Defender scan exceeded 30 minutes.");
                }
                AppendLog("Microsoft Defender process exit code: " + process.ExitCode);
                return process.ExitCode;
            }
        }

        private async Task RefreshControlledFolderAccessAsync()
        {
            CfaStatusText.Text = "Checking Windows Controlled Folder Access…";
            try
            {
                string result = await Task.Run(GetControlledFolderAccessStatus);
                string[] fields = result.Split('|');
                if (fields.Length != 2 || fields[0] != "DANAT_CFA")
                    throw new InvalidOperationException("Windows returned an unreadable ransomware-protection status.");

                int mode;
                if (!int.TryParse(fields[1], out mode))
                    throw new InvalidOperationException("Windows returned an unknown Controlled Folder Access mode.");

                if (mode == 1)
                {
                    CfaStatusText.Text = "ON — Windows Controlled Folder Access is enabled. Windows controls which apps may modify protected folders.";
                    CfaStatusText.Foreground = new SolidColorBrush(Color.FromRgb(112, 210, 133));
                }
                else if (mode == 2)
                {
                    CfaStatusText.Text = "AUDIT MODE — Windows records blocked-app events but does not actively block changes.";
                    CfaStatusText.Foreground = new SolidColorBrush(Color.FromRgb(255, 198, 92));
                }
                else if (mode == 0)
                {
                    CfaStatusText.Text = "OFF — Windows Controlled Folder Access is disabled. Open Windows settings to review this protection.";
                    CfaStatusText.Foreground = new SolidColorBrush(Color.FromRgb(255, 120, 100));
                }
                else if (mode == 3)
                {
                    CfaStatusText.Text = "PARTIAL PROTECTION — Windows blocks disk modification only; folder changes are not blocked by this mode.";
                    CfaStatusText.Foreground = new SolidColorBrush(Color.FromRgb(255, 198, 92));
                }
                else if (mode == 4)
                {
                    CfaStatusText.Text = "AUDIT MODE (DISK MODIFICATION ONLY) — Windows records disk-modification attempts but does not block them.";
                    CfaStatusText.Foreground = new SolidColorBrush(Color.FromRgb(255, 198, 92));
                }
                else
                {
                    CfaStatusText.Text = "UNKNOWN MODE (" + mode + ") — review the Windows Security ransomware-protection page.";
                    CfaStatusText.Foreground = new SolidColorBrush(Color.FromRgb(255, 198, 92));
                }
            }
            catch (Exception ex)
            {
                CfaStatusText.Text = "STATUS UNAVAILABLE — " + ex.Message + " Danat has not changed this Windows setting.";
                CfaStatusText.Foreground = new SolidColorBrush(Color.FromRgb(255, 198, 92));
            }
        }

        private static string GetControlledFolderAccessStatus()
        {
            const string script = "$ErrorActionPreference='Stop'; Import-Module Defender -ErrorAction Stop; $p=Get-MpPreference -ErrorAction Stop; Write-Output ('DANAT_CFA|' + [string]$p.EnableControlledFolderAccess)";
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
                    throw new TimeoutException("Controlled Folder Access status check timed out.");
                }
                Task.WaitAll(outputTask, errorTask);
                string output = outputTask.Result.Trim();
                string error = errorTask.Result.Trim();
                if (process.ExitCode != 0)
                    throw new InvalidOperationException(string.IsNullOrWhiteSpace(error) ? "Get-MpPreference failed." : error);
                return output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).LastOrDefault() ?? string.Empty;
            }
        }

        private void OpenRansomwareSettings_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "ms-settings:windowsdefender-ransomware",
                    UseShellExecute = true
                });
            }
            catch (Exception ex)
            {
                SetScanStatus("Could not open Windows ransomware-protection settings: " + ex.Message, true);
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


        // Windows maintenance tools. Cleanup is restricted to the current user's TEMP
        // directory and only removes files older than seven days; locked files are skipped.
        private async void CleanTemp_Click(object sender, RoutedEventArgs e)
        {
            if (_scanRunning) return;
            MessageBoxResult answer = MessageBox.Show(
                "Danat will remove files older than seven days from your Windows user TEMP folder only. Files in use will be skipped. Personal folders, Downloads, browser profiles, and the Windows system directory will not be touched. Continue?",
                "Clean temporary files", MessageBoxButton.YesNo, MessageBoxImage.Warning);
            if (answer != MessageBoxResult.Yes) return;

            SetMaintenanceBusy(true, "Cleaning old files in your user TEMP folder…");
            try
            {
                var result = await Task.Run(() => CleanUserTempFiles());
                MaintenanceStatusText.Text = "Cleanup finished. Deleted " + result.Item1 +
                    " file(s); skipped " + result.Item2 + " file(s).";
                AppendMaintenanceLog("User TEMP cleanup: " + result.Item1 + " deleted; " + result.Item2 + " skipped.");
            }
            catch (Exception ex)
            {
                MaintenanceStatusText.Text = "Cleanup could not be completed: " + ex.Message;
                AppendMaintenanceLog(ex.ToString());
            }
            finally { SetMaintenanceBusy(false, null); }
        }

        private static Tuple<int, int> CleanUserTempFiles()
        {
            string temp = Path.GetFullPath(Path.GetTempPath());
            string local = Path.GetFullPath(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));
            if (string.IsNullOrWhiteSpace(temp) || !temp.StartsWith(local.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("The resolved TEMP path is not inside this user's Local AppData folder.");
            if (!Directory.Exists(temp)) return Tuple.Create(0, 0);

            DateTime cutoff = DateTime.Now.AddDays(-7);
            int deleted = 0, skipped = 0;
            var pending = new System.Collections.Generic.Stack<string>();
            var visited = new System.Collections.Generic.List<string>();
            pending.Push(temp);

            // Walk only inside TEMP and never follow junctions or symbolic links.
            while (pending.Count > 0)
            {
                string current = pending.Pop();
                visited.Add(current);
                try
                {
                    foreach (string file in Directory.GetFiles(current, "*", SearchOption.TopDirectoryOnly))
                    {
                        try
                        {
                            if ((File.GetAttributes(file) & FileAttributes.ReparsePoint) != 0) { skipped++; continue; }
                            if (File.GetLastWriteTime(file) >= cutoff) continue;
                            File.Delete(file);
                            deleted++;
                        }
                        catch { skipped++; }
                    }

                    foreach (string directory in Directory.GetDirectories(current, "*", SearchOption.TopDirectoryOnly))
                    {
                        try
                        {
                            if ((File.GetAttributes(directory) & FileAttributes.ReparsePoint) == 0)
                                pending.Push(directory);
                        }
                        catch { skipped++; }
                    }
                }
                catch { skipped++; }
            }

            // Remove directories only when empty; never recursively delete a directory tree.
            foreach (string directory in visited.OrderByDescending(p => p.Length))
            {
                if (string.Equals(directory, temp, StringComparison.OrdinalIgnoreCase)) continue;
                try
                {
                    if (!Directory.EnumerateFileSystemEntries(directory).Any())
                        Directory.Delete(directory, false);
                }
                catch { }
            }
            return Tuple.Create(deleted, skipped);
        }

        private async void ClearThumbnailCache_Click(object sender, RoutedEventArgs e)
        {
            if (_scanRunning || _maintenanceRunning) return;
            if (MessageBox.Show("This removes Windows thumbnail-cache database files for the current user only. Windows will rebuild thumbnails as needed. Files currently in use will be skipped. Continue?",
                "Clear thumbnail cache", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
            SetMaintenanceBusy(true, "Clearing the current user's Windows thumbnail cache…");
            try
            {
                var result = await Task.Run(() =>
                {
                    string folder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                        "Microsoft", "Windows", "Explorer");
                    if (!Directory.Exists(folder)) return Tuple.Create(0, 0);
                    int deleted = 0, skipped = 0;
                    foreach (string file in Directory.GetFiles(folder, "thumbcache_*.db", SearchOption.TopDirectoryOnly))
                    {
                        try { File.Delete(file); deleted++; }
                        catch { skipped++; }
                    }
                    return Tuple.Create(deleted, skipped);
                });
                MaintenanceStatusText.Text = "Thumbnail cache cleanup finished. Deleted " + result.Item1 +
                    " file(s); skipped " + result.Item2 + " file(s). Windows will rebuild thumbnails.";
                AppendMaintenanceLog("Thumbnail cache: " + result.Item1 + " deleted; " + result.Item2 + " skipped.");
            }
            catch (Exception ex) { MaintenanceStatusText.Text = "Thumbnail cache could not be cleared: " + ex.Message; }
            finally { SetMaintenanceBusy(false, null); }
        }

        private async void FlushDns_Click(object sender, RoutedEventArgs e)
        {
            if (_scanRunning) return;
            if (MessageBox.Show("This clears the Windows DNS resolver cache. It does not delete browsing history or saved passwords. Continue?",
                "Flush DNS cache", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
            SetMaintenanceBusy(true, "Flushing the Windows DNS cache…");
            try
            {
                await RunElevatedCommandAsync("ipconfig.exe", "/flushdns", 30000);
                AppendMaintenanceLog("ipconfig /flushdns process finished. Review the visible Windows console for its confirmation.");
                MaintenanceStatusText.Text = "DNS cache command finished. Review the Windows console for confirmation.";
            }
            catch (Exception ex) { MaintenanceStatusText.Text = "DNS cache could not be flushed: " + ex.Message; }
            finally { SetMaintenanceBusy(false, null); }
        }

        private async void CheckDisk_Click(object sender, RoutedEventArgs e)
        {
            if (_scanRunning) return;
            if (MessageBox.Show("This runs the Windows online NTFS scan (chkdsk on the Windows system drive with /scan). It checks the system drive without scheduling an offline repair. Continue?",
                "Check system drive", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
            SetMaintenanceBusy(true, "Starting the Windows online disk scan…");
            try
            {
                string systemDrive = Path.GetPathRoot(Environment.SystemDirectory);
                await RunElevatedCommandAsync("chkdsk.exe", systemDrive.TrimEnd(Path.DirectorySeparatorChar) + " /scan", 60 * 60 * 1000);
                MaintenanceStatusText.Text = "Disk check process finished. Read the CHKDSK window for its findings.";
                AppendMaintenanceLog("CHKDSK /scan finished. Review the visible Windows console for the detailed report.");
            }
            catch (Exception ex) { MaintenanceStatusText.Text = "Disk check could not be completed: " + ex.Message; }
            finally { SetMaintenanceBusy(false, null); }
        }

        private async void RepairWindows_Click(object sender, RoutedEventArgs e)
        {
            if (_scanRunning) return;
            if (MessageBox.Show("DISM /Online /Cleanup-Image /RestoreHealth repairs the Windows component store. It may take a long time and uses Windows Update when needed. Save your work first. Continue?",
                "Repair Windows image", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
            SetMaintenanceBusy(true, "DISM repair is starting. A Windows administrator approval prompt will appear…");
            try
            {
                await RunElevatedCommandAsync("dism.exe", "/Online /Cleanup-Image /RestoreHealth", 90 * 60 * 1000);
                MaintenanceStatusText.Text = "DISM process finished. Review its console output for the final result; restart Windows if DISM requests it.";
                AppendMaintenanceLog("DISM /RestoreHealth process finished. Danat does not infer success without reviewing DISM's final console result.");
            }
            catch (Exception ex) { MaintenanceStatusText.Text = "DISM could not be completed: " + ex.Message; }
            finally { SetMaintenanceBusy(false, null); }
        }

        private async void RepairSystemFiles_Click(object sender, RoutedEventArgs e)
        {
            if (_scanRunning) return;
            if (MessageBox.Show("SFC /scannow checks protected Windows system files and repairs corruption when possible. It may take several minutes. Save your work first. Continue?",
                "Repair Windows system files", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
            SetMaintenanceBusy(true, "System File Checker is starting. A Windows administrator approval prompt will appear…");
            try
            {
                await RunElevatedCommandAsync("sfc.exe", "/scannow", 60 * 60 * 1000);
                MaintenanceStatusText.Text = "SFC process finished. Review its console output for whether corruption was found and repaired.";
                AppendMaintenanceLog("SFC /scannow process finished. Review the visible Windows console for the detailed result.");
            }
            catch (Exception ex) { MaintenanceStatusText.Text = "System File Checker could not be completed: " + ex.Message; }
            finally { SetMaintenanceBusy(false, null); }
        }

        private static string RunCapturedCommand(string executable, string arguments, int timeoutMs)
        {
            var info = new ProcessStartInfo
            {
                FileName = executable, Arguments = arguments, UseShellExecute = false,
                CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true
            };
            using (var process = Process.Start(info))
            {
                if (process == null) throw new InvalidOperationException("Windows could not start " + executable + ".");
                Task<string> stdout = process.StandardOutput.ReadToEndAsync();
                Task<string> stderr = process.StandardError.ReadToEndAsync();
                if (!process.WaitForExit(timeoutMs))
                {
                    try { process.Kill(); } catch { }
                    throw new TimeoutException(executable + " exceeded its time limit.");
                }
                Task.WaitAll(stdout, stderr);
                string output = (stdout.Result + Environment.NewLine + stderr.Result).Trim();
                if (process.ExitCode != 0)
                    throw new InvalidOperationException(string.IsNullOrWhiteSpace(output) ? executable + " returned exit code " + process.ExitCode : output);
                return string.IsNullOrWhiteSpace(output) ? executable + " completed successfully." : output;
            }
        }

        private async Task RunElevatedCommandAsync(string executable, string arguments, int timeoutMs)
        {
            await Task.Run(() =>
            {
                var info = new ProcessStartInfo
                {
                    FileName = executable, Arguments = arguments, UseShellExecute = true,
                    Verb = "runas", CreateNoWindow = false
                };
                using (var process = Process.Start(info))
                {
                    if (process == null) throw new InvalidOperationException("Windows did not start " + executable + ".");
                    if (!process.WaitForExit(timeoutMs))
                    {
                        try { process.Kill(); } catch { }
                        throw new TimeoutException(executable + " exceeded its time limit. Treat the operation as incomplete.");
                    }
                    if (process.ExitCode != 0)
                        throw new InvalidOperationException(executable + " returned exit code " + process.ExitCode + ". Review its console output.");
                }
            });
        }

        private void SetMaintenanceBusy(bool busy, string message)
        {
            _maintenanceRunning = busy;
            SetMaintenanceButtonsEnabled(MaintenancePanel, !busy);
            if (busy && !string.IsNullOrWhiteSpace(message)) MaintenanceStatusText.Text = message;
        }

        private static void SetMaintenanceButtonsEnabled(DependencyObject parent, bool enabled)
        {
            foreach (object child in LogicalTreeHelper.GetChildren(parent))
            {
                var button = child as System.Windows.Controls.Button;
                if (button != null) button.IsEnabled = enabled;
                var dependencyObject = child as DependencyObject;
                if (dependencyObject != null) SetMaintenanceButtonsEnabled(dependencyObject, enabled);
            }
        }

        private void AppendMaintenanceLog(string line)
        {
            MaintenanceLogBox.AppendText(line + Environment.NewLine);
            MaintenanceLogBox.ScrollToEnd();
        }

        private void OpenStorageSettings_Click(object sender, RoutedEventArgs e) { OpenSettingsPage("ms-settings:storagesense"); }
        private void OpenStartupSettings_Click(object sender, RoutedEventArgs e) { OpenSettingsPage("ms-settings:startupapps"); }
        private void OpenNetworkSettings_Click(object sender, RoutedEventArgs e) { OpenSettingsPage("ms-settings:network-status"); }

        private void OpenDriveOptimization_Click(object sender, RoutedEventArgs e)
        {
            try { Process.Start(new ProcessStartInfo { FileName = "dfrgui.exe", UseShellExecute = true }); }
            catch (Exception ex) { MaintenanceStatusText.Text = "Could not open Drive Optimization: " + ex.Message; }
        }

        private void OpenSettingsPage(string uri)
        {
            try { Process.Start(new ProcessStartInfo { FileName = uri, UseShellExecute = true }); }
            catch (Exception ex) { MaintenanceStatusText.Text = "Could not open Windows Settings: " + ex.Message; }
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
