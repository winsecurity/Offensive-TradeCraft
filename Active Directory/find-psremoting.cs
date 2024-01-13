using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.ActiveDirectory;
using System.Collections.Specialized;
using System.Collections;
using System.Security.Principal;
using System.Security.AccessControl;
using System.Management.Automation;
using System.Management.Automation.Remoting;
using System.Management.Automation.Runspaces;


   public static void checkpsremoting(string computername)
        {
            var wsmaninfo = new WSManConnectionInfo();
            wsmaninfo.AuthenticationMechanism = AuthenticationMechanism.Kerberos;
            wsmaninfo.ComputerName = computername;


            Runspace rs= RunspaceFactory.CreateRunspace(wsmaninfo);

            try
            {
                rs.Open();
                Console.WriteLine(computername);
            }
            catch
            {

            }
            rs.Close();


        }


        public static void findpsremoting(string domaindn)
        {
            DirectoryEntry de = new DirectoryEntry("LDAP://" + domaindn);

            DirectorySearcher ds = new DirectorySearcher(de);
            ds.SearchScope = SearchScope.Subtree;
            ds.Filter = "(&(objectclass=computer))";

            SearchResultCollection src = ds.FindAll();
            foreach (SearchResult sr in src)
            {
                string computername = sr.Properties["dnshostname"][0].ToString();
                checkpsremoting(computername);

            }
        }
