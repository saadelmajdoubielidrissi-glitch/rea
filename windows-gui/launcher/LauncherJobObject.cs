using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Rea.WindowsGui.Launcher
{
    public static class LauncherJobObject
    {
        private const uint JobObjectExtendedLimitInformation = 9;
        private const uint JobObjectLimitKillOnJobClose = 0x2000;
        private static IntPtr _processLifetimeHandle;

        public static void AssignCurrentProcess()
        {
            if (_processLifetimeHandle != IntPtr.Zero)
            {
                return;
            }

            var rawHandle = CreateJobObject(IntPtr.Zero, null);
            if (rawHandle == IntPtr.Zero)
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "The launcher Job Object could not be created."
                );
            }

            try
            {
                var limits = new JobObjectExtendedLimitInformationData();
                limits.BasicLimitInformation.LimitFlags = JobObjectLimitKillOnJobClose;
                if (!SetInformationJobObject(
                    rawHandle,
                    JobObjectExtendedLimitInformation,
                    ref limits,
                    (uint)Marshal.SizeOf(typeof(JobObjectExtendedLimitInformationData))
                ))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "The launcher kill-on-close policy could not be applied."
                    );
                }

                if (!AssignProcessToJobObject(rawHandle, GetCurrentProcess()))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "The launcher could not own its child process tree."
                    );
                }

                // Keep the raw handle open until the OS tears down this process.
                // Closing a kill-on-close job while its owner is running would kill the owner.
                _processLifetimeHandle = rawHandle;
            }
            catch
            {
                CloseHandle(rawHandle);
                throw;
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
        private static extern bool CloseHandle(IntPtr handle);
    }
}
