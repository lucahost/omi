using System;
using System.Management.Automation;

namespace PSWSMan
{
    public class OnModuleImportAndRemove : IModuleAssemblyInitializer, IModuleAssemblyCleanup
    {
        private Resolver? resolver = null;

        public void OnImport()
        {
            // TODO: Add auto resolver for libpsrpclient
        }

        public void OnRemove(PSModuleInfo module)
        {
            resolver?.Dispose();
        }
    }
}
