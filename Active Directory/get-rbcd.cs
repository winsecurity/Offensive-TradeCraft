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



 public static void getrbcd(string domaindn)
        {
            DirectoryEntry de = new DirectoryEntry("LDAP://" + domaindn);

            DirectorySearcher ds = new DirectorySearcher(de);
            ds.SearchScope = SearchScope.Subtree;
            ds.Filter = "(&(objectclass=computer))";

            SearchResultCollection src = ds.FindAll();
            foreach (SearchResult sr in src)
            {

                DirectoryEntry computer = sr.GetDirectoryEntry();
                var ads = computer.ObjectSecurity.GetAccessRules(true,true,typeof(NTAccount));

                Console.WriteLine(computer.Name);
                foreach(ActiveDirectoryAccessRule ar in ads)
                {
                    if (ar.ActiveDirectoryRights.ToString().ToLower().Contains("write") ||
                        ar.ActiveDirectoryRights.ToString().ToLower().Contains("generic all") ||
                        ar.ActiveDirectoryRights.ToString().ToLower().Contains("generic all")
                        || ar.ActiveDirectoryRights.ToString().ToLower().Contains("generic write"))
                    {

                        if(ar.IdentityReference.ToString().ToLower().Contains("builtin")||
                            ar.IdentityReference.ToString().ToLower().Contains("nt authority"))
                        {
                            continue;
                        }

                        Console.WriteLine("{0}", ar.IdentityReference.ToString());
                        Console.WriteLine("{0}", ar.ActiveDirectoryRights.ToString());
                        Console.WriteLine("{0}", ar.AccessControlType.ToString());

                    }



                }

                Console.WriteLine();

                Console.WriteLine();

            }
        }
