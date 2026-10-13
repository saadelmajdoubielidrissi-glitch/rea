using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using System.Text;

namespace Rea.WindowsGui
{
    public sealed class ReaGuiOutputLine
    {
        public ReaGuiOutputLine(string stream, string text)
        {
            Stream = stream;
            Text = text;
        }

        public string Stream { get; private set; }
        public string Text { get; private set; }
    }

    public sealed class ReaGuiProcessRunner : IDisposable
    {
        private const uint JobObjectExtendedLimitInformation = 9;
        private const uint JobObjectLimitKillOnJobClose = 0x2000;
        private readonly ConcurrentQueue<ReaGuiOutputLine> _output =
            new ConcurrentQueue<ReaGuiOutputLine>();
        private readonly Process _process;
        private static readonly object OwnerJobLock = new object();
        private static IntPtr _ownerJob;

        public ReaGuiProcessRunner(ProcessStartInfo startInfo)
        {
            if (startInfo == null)
            {
                throw new ArgumentNullException("startInfo");
            }

            startInfo.UseShellExecute = false;
            startInfo.CreateNoWindow = true;
            startInfo.RedirectStandardOutput = true;
            startInfo.RedirectStandardError = true;
            startInfo.StandardOutputEncoding = Encoding.UTF8;
            startInfo.StandardErrorEncoding = Encoding.UTF8;

            _process = new Process();
            _process.StartInfo = startInfo;
            _process.OutputDataReceived += delegate(object sender, DataReceivedEventArgs args)
            {
                if (args.Data != null)
                {
                    _output.Enqueue(new ReaGuiOutputLine("stdout", args.Data));
                }
            };
            _process.ErrorDataReceived += delegate(object sender, DataReceivedEventArgs args)
            {
                if (args.Data != null)
                {
                    _output.Enqueue(new ReaGuiOutputLine("stderr", args.Data));
                }
            };
        }

        public static bool IsLocalPath(string path)
        {
            if (String.IsNullOrWhiteSpace(path))
            {
                return false;
            }

            string root = Path.GetPathRoot(path);
            if (String.IsNullOrEmpty(root) || root.StartsWith(@"\\", StringComparison.Ordinal))
            {
                return false;
            }

            uint driveType = GetDriveType(root);
            return driveType == 2 || driveType == 3 || driveType == 5 || driveType == 6;
        }

        public static bool IsLocalTargetPath(string path)
        {
            if (!IsLocalPath(path))
            {
                return false;
            }

            using (SafeFileHandle handle = CreateFile(
                path,
                0,
                FileShare.Read | FileShare.Write | FileShare.Delete,
                IntPtr.Zero,
                FileMode.Open,
                0x02000000,
                IntPtr.Zero
            ))
            {
                if (handle.IsInvalid)
                {
                    throw new System.ComponentModel.Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "The selected target's final path could not be resolved."
                    );
                }

                var finalPath = new StringBuilder(512);
                uint length = GetFinalPathNameByHandle(handle, finalPath, (uint)finalPath.Capacity, 0);
                if (length == 0)
                {
                    throw new System.ComponentModel.Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "The selected target's final path could not be read."
                    );
                }
                if (length >= finalPath.Capacity)
                {
                    finalPath = new StringBuilder(checked((int)length + 1));
                    length = GetFinalPathNameByHandle(handle, finalPath, (uint)finalPath.Capacity, 0);
                    if (length == 0 || length >= finalPath.Capacity)
                    {
                        throw new System.ComponentModel.Win32Exception(
                            Marshal.GetLastWin32Error(),
                            "The selected target's final path could not be read."
                        );
                    }
                }

                string resolvedPath = finalPath.ToString();
                if (resolvedPath.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }
                if (resolvedPath.StartsWith(@"\\?\", StringComparison.Ordinal))
                {
                    resolvedPath = resolvedPath.Substring(4);
                }

                return IsLocalPath(resolvedPath);
            }
        }

        public bool HasExited
        {
            get { return _process.HasExited; }
        }

        public int ExitCode
        {
            get { return _process.ExitCode; }
        }

        public bool IsOwnedByOwnerJob
        {
            get
            {
                EnsureOwnerJob();
                bool isOwned;
                if (!IsProcessInJob(_process.Handle, _ownerJob, out isOwned))
                {
                    throw new System.ComponentModel.Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "REA CLI Job Object membership could not be verified."
                    );
                }

                return isOwned;
            }
        }

        public void Start()
        {
            EnsureOwnerJob();
            if (!_process.Start())
            {
                throw new InvalidOperationException("REA CLI 프로세스를 시작하지 못했습니다.");
            }

            _process.BeginOutputReadLine();
            _process.BeginErrorReadLine();
        }

        public void WaitForExit()
        {
            _process.WaitForExit();
        }

        public bool TryDequeue(out ReaGuiOutputLine line)
        {
            return _output.TryDequeue(out line);
        }

        public void Dispose()
        {
            _process.Dispose();
        }

        private static void EnsureOwnerJob()
        {
            if (_ownerJob != IntPtr.Zero)
            {
                return;
            }

            lock (OwnerJobLock)
            {
                if (_ownerJob != IntPtr.Zero)
                {
                    return;
                }

                IntPtr job = CreateJobObject(IntPtr.Zero, null);
                if (job == IntPtr.Zero)
                {
                    throw new System.ComponentModel.Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "REA CLI Job Object could not be created."
                    );
                }

                var limits = new JobObjectExtendedLimitInformationData();
                limits.BasicLimitInformation.LimitFlags = JobObjectLimitKillOnJobClose;
                if (!SetInformationJobObject(
                    job,
                    JobObjectExtendedLimitInformation,
                    ref limits,
                    (uint)Marshal.SizeOf(typeof(JobObjectExtendedLimitInformationData))
                ))
                {
                    int error = Marshal.GetLastWin32Error();
                    CloseHandle(job);
                    throw new System.ComponentModel.Win32Exception(
                        error,
                        "REA CLI kill-on-owner-close policy could not be applied."
                    );
                }

                if (!AssignProcessToJobObject(job, GetCurrentProcess()))
                {
                    int error = Marshal.GetLastWin32Error();
                    CloseHandle(job);
                    throw new System.ComponentModel.Win32Exception(
                        error,
                        "The GUI process could not own its REA CLI process tree."
                    );
                }

                // Keep this handle for the GUI process lifetime; closing it kills all active descendants.
                _ownerJob = job;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JobObjectBasicLimitInformationData
        {
            public long PerProcessUserTimeLimit;
            public long PerJobUserTimeLimit;
            public uint LimitFlags;
            public UIntPtr MinimumWorkingSetSize;
            public UIntPtr MaximumWorkingSetSize;
            public uint ActiveProcessLimit;
            public UIntPtr Affinity;
            public uint PriorityClass;
            public uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IoCounters
        {
            public ulong ReadOperationCount;
            public ulong WriteOperationCount;
            public ulong OtherOperationCount;
            public ulong ReadTransferCount;
            public ulong WriteTransferCount;
            public ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JobObjectExtendedLimitInformationData
        {
            public JobObjectBasicLimitInformationData BasicLimitInformation;
            public IoCounters IoInfo;
            public UIntPtr ProcessMemoryLimit;
            public UIntPtr JobMemoryLimit;
            public UIntPtr PeakProcessMemoryUsed;
            public UIntPtr PeakJobMemoryUsed;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateJobObject(IntPtr jobAttributes, string name);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetInformationJobObject(
            IntPtr job,
            uint informationClass,
            ref JobObjectExtendedLimitInformationData information,
            uint informationLength
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool IsProcessInJob(IntPtr process, IntPtr job, out bool result);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CreateFileW")]
        private static extern SafeFileHandle CreateFile(
            string fileName,
            uint desiredAccess,
            FileShare shareMode,
            IntPtr securityAttributes,
            FileMode creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile
        );

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetFinalPathNameByHandle(
            SafeFileHandle file,
            StringBuilder path,
            uint pathLength,
            uint flags
        );

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        private static extern uint GetDriveType(string rootPathName);
    }
}
