using System;
using System.Diagnostics;
using System.IO;
using System.Globalization;
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
                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit(5000);
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
            string action = alreadyInstalled ? "check for and install an available ClamAV engine update" : "download and install the official ClamAV scanning engine";
            MessageBoxResult consent = MessageBox.Show(
                "Danat Anti-Virus will use Windows Package Manager to " + action + ". Windows may display an installation or license confirmation. The installer is obtained from the Cisco.ClamAV WinGet package, whose installer hash is checked by WinGet. ClamAV is licensed under GPL-2.0. Continue?",
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

                string freshclam = Path.Combine(Path.GetDirectoryName(scanner), "freshclam.exe");
                if (!File.Exists(freshclam))
                    throw new FileNotFoundException("The ClamAV installation did not include freshclam.exe.", freshclam);

                string config = EnsureClamFreshclamConfig(scanner);
                SetScanStatus("ClamAV is installed. Downloading and verifying the latest virus signatures…", false);
                int updateCode = await RunFreshClamAsync(freshclam, config);
                if (updateCode != 0)
                    throw new InvalidOperationException("FreshClam returned exit code " + updateCode + ". The signature database is not confirmed current.");

                SetScanStatus("ClamAV is installed and its virus signatures are updated. Danat will refresh signatures before each ClamAV scan.", false);
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
                await Task.Run(() => process.WaitForExit());
                process.WaitForExit();
                return process.ExitCode;
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
