using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using Microsoft.Win32;

namespace DanatAntiVirus
{
    public partial class MainWindow : Window
    {
        private string _scanTarget;
        private CancellationTokenSource _scanCancellation;

        public MainWindow() { InitializeComponent(); }

        private void BrowseScanner_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFileDialog
            {
                Title = "Select the installed ClamAV scanner",
                Filter = "ClamAV scanner (clamscan.exe)|clamscan.exe|Executable files (*.exe)|*.exe",
                CheckFileExists = true
            };
            if (dialog.ShowDialog() == true)
            {
                if (!string.Equals(Path.GetFileName(dialog.FileName), "clamscan.exe", StringComparison.OrdinalIgnoreCase))
                {
                    SetStatus("Please select the official clamscan.exe executable.", true);
                    return;
                }
                ScannerPathBox.Text = dialog.FileName;
                SetStatus("Scanner selected. Select its signature database folder and a folder to scan.", false);
            }
        }

        private void BrowseDatabase_Click(object sender, RoutedEventArgs e)
        {
            using (var dialog = new System.Windows.Forms.FolderBrowserDialog())
            {
                dialog.Description = "Select the folder containing ClamAV main and daily signature databases";
                dialog.ShowNewFolderButton = false;
                if (dialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
                    DatabasePathBox.Text = dialog.SelectedPath;
            }
        }

        private void ChooseFolder_Click(object sender, RoutedEventArgs e)
        {
            using (var dialog = new System.Windows.Forms.FolderBrowserDialog())
            {
                dialog.Description = "Choose the folder to scan";
                dialog.ShowNewFolderButton = false;
                if (dialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
                {
                    _scanTarget = dialog.SelectedPath;
                    TargetFolderText.Text = _scanTarget;
                }
            }
        }

        private async void StartScan_Click(object sender, RoutedEventArgs e)
        {
            if (_scanCancellation != null) return;
            string scanner = ScannerPathBox.Text.Trim();
            string database = DatabasePathBox.Text.Trim();
            if (!File.Exists(scanner) || !string.Equals(Path.GetFileName(scanner), "clamscan.exe", StringComparison.OrdinalIgnoreCase))
            {
                SetStatus("Select a valid clamscan.exe first. No scan was started.", true);
                return;
            }
            if (!Directory.Exists(database) || !Directory.Exists(_scanTarget ?? string.Empty))
            {
                SetStatus("Select the signature database folder and the folder to scan.", true);
                return;
            }

            string databaseError;
            if (!HasFreshDatabases(database, out databaseError))
            {
                SetStatus(databaseError + " Scan blocked; no clean result can be reported.", true);
                return;
            }

            StartScanButton.IsEnabled = false;
            CancelScanButton.IsEnabled = true;
            ScanLogBox.Clear();
            _scanCancellation = new CancellationTokenSource();
            try
            {
                SetStatus("Checking scanner identity…", false);
                string version = await Task.Run(() => GetScannerVersion(scanner));
                if (string.IsNullOrWhiteSpace(version) || !version.StartsWith("ClamAV ", StringComparison.OrdinalIgnoreCase))
                {
                    SetStatus("The selected executable did not identify itself as ClamAV. Scan blocked.", true);
                    return;
                }

                SetStatus("Scanning in progress. Keep this window open…", false);
                int exitCode = await RunScannerAsync(scanner, database, _scanTarget, _scanCancellation.Token);
                if (exitCode == 0)
                    SetStatus("Scan completed: ClamAV reported no detections. This is not a guarantee that the folder is malware-free.", false);
                else if (exitCode == 1)
                    SetStatus("Scan completed: ClamAV reported one or more detections. Review the results below; files were not changed.", true);
                else
                    SetStatus("Scanner error (exit code " + exitCode + "). This is NOT a clean scan. Check the log and signature database.", true);
            }
            catch (OperationCanceledException)
            {
                SetStatus("Scan cancelled. No clean result is available.", true);
            }
            catch (Exception ex)
            {
                SetStatus("Scan failed: " + ex.Message + ". No clean result is available.", true);
                AppendLog(ex.ToString());
            }
            finally
            {
                if (_scanCancellation != null) _scanCancellation.Dispose();
                _scanCancellation = null;
                StartScanButton.IsEnabled = true;
                CancelScanButton.IsEnabled = false;
            }
        }

        private void CancelScan_Click(object sender, RoutedEventArgs e)
        {
            if (_scanCancellation != null) _scanCancellation.Cancel();
        }

        private static bool HasFreshDatabases(string directory, out string error)
        {
            error = null;
            string[] names = { "main.cvd", "main.cld", "daily.cvd", "daily.cld" };
            string main = names.Take(2).Select(n => Path.Combine(directory, n)).FirstOrDefault(File.Exists);
            string daily = names.Skip(2).Select(n => Path.Combine(directory, n)).FirstOrDefault(File.Exists);
            if (main == null || daily == null)
            {
                error = "The selected database folder must contain both main.cvd/main.cld and daily.cvd/daily.cld.";
                return false;
            }
            foreach (string file in new[] { main, daily })
            {
                DateTime updated = File.GetLastWriteTimeUtc(file);
                if (updated > DateTime.UtcNow.AddMinutes(5) || DateTime.UtcNow - updated > TimeSpan.FromDays(7))
                {
                    error = "A required signature database is older than 7 days or has an invalid timestamp.";
                    return false;
                }
            }
            return true;
        }

        private static string GetScannerVersion(string scanner)
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
                if (!process.WaitForExit(10000))
                {
                    process.Kill();
                    throw new TimeoutException("ClamAV version check timed out");
                }
                string output = process.StandardOutput.ReadToEnd();
                if (process.ExitCode != 0) output += process.StandardError.ReadToEnd();
                return output.Trim();
            }
        }

        private async Task<int> RunScannerAsync(string scanner, string database, string target, CancellationToken token)
        {
            var info = new ProcessStartInfo
            {
                FileName = scanner,
                Arguments = "--database=" + QuoteArgument(database) + " --infected --recursive --no-summary --stdout " + QuoteArgument(target),
                WorkingDirectory = Path.GetDirectoryName(scanner),
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using (var process = new Process { StartInfo = info, EnableRaisingEvents = true })
            using (token.Register(() => { try { if (!process.HasExited) process.Kill(); } catch { } }))
            {
                process.OutputDataReceived += (s, e) => { if (!string.IsNullOrEmpty(e.Data)) Dispatcher.BeginInvoke(new Action(() => AppendLog(e.Data))); };
                process.ErrorDataReceived += (s, e) => { if (!string.IsNullOrEmpty(e.Data)) Dispatcher.BeginInvoke(new Action(() => AppendLog("ERROR: " + e.Data))); };
                if (!process.Start()) throw new InvalidOperationException("Could not start ClamAV.");
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();
                await Task.Run(() => process.WaitForExit());
                token.ThrowIfCancellationRequested();
                return process.ExitCode;
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

        private void SetStatus(string message, bool warning)
        {
            ScanStatusText.Text = message;
            ScanStatusText.Foreground = warning ?
                new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(255, 198, 92)) :
                new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(214, 166, 46));
        }

        private void AppendLog(string line)
        {
            ScanLogBox.AppendText(line + Environment.NewLine);
            ScanLogBox.ScrollToEnd();
        }
    }
}
