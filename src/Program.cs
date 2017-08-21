using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO.Packaging;
using Tectil.NCommand;

namespace NuGetSign
{
    class Program
    {
        static void Main(string[] args)
        {
            NCommands commands = new NCommands();

            //commands.Context.AutodetectCommandAssemblies(); // Loads all assemblies in bin folder and checks for CommandAttribute

            //commands.Context.Configuration.DisplayExceptionDetails = false;

            // commands.Context.Configuration.Notation = ParserNotation.Unix;

            commands.RunConsole(args);
        }
    }
}
