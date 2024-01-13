
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


 public static void getasreproastable(string domaindn)
        {
            DirectoryEntry de = new DirectoryEntry("LDAP://" + domaindn);

            DirectorySearcher ds = new DirectorySearcher(de);
            ds.SearchScope = SearchScope.Subtree;
            ds.Filter = "(&(objectclass=user))";

            SearchResultCollection src = ds.FindAll();
            foreach (SearchResult sr in src)
            {
                foreach (string propertyname in sr.Properties.PropertyNames)
                {

                    if (propertyname == "useraccountcontrol")
                    {
                        int uacvalue = (int) sr.Properties["useraccountcontrol"][0];
                        string[] uacflags = decodeuac(uacvalue);

                        foreach(string j in uacflags)
                        {
                            if(j== "DONT_REQ_PREAUTH")
                            {
                                Console.WriteLine(sr.GetDirectoryEntry().Name);
                                Console.WriteLine("{0,-20}: {1}",
                        propertyname, sr.Properties[propertyname][0]);
                            
                            
                            }
                        }

                    }

                    
                }

                Console.WriteLine();

            }
        }

