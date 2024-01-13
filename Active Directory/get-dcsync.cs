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



public static void getdcsync(string domaindn)
        {
            DirectoryEntry de = new DirectoryEntry("LDAP://" + domaindn);

            Hashtable ht = new Hashtable();
            ht.Add("DS-Replication-Get-Changes", "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2");
            ht.Add("DS-Replication-Get-Changes-All", "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2");
            ht.Add("DS-Replication-Get-Changes-In-Filtered-Set", "89e95b76-444d-4c62-991a-0facbeda640c");
            ht.Add("DS-Replication-Manage-Topology", "1131f6ac-9c07-11d1-f79f-00c04fc2dcd2");
            ht.Add("DS-Replication-Monitor-Topology", "f98340fb-7c5b-4cdb-a00b-2ebdfa115a96");
            ht.Add("DS-Replication-Synchronize", "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2");


            DirectorySearcher ds = new DirectorySearcher(de);
            //ds.SearchScope = SearchScope.Base;
            ds.SearchRoot = de;
            //ds.Filter = "(&(objectclass=*))";

            SearchResultCollection src = ds.FindAll();
            foreach (SearchResult sr in src)
            {
                try
                {
                    // DC=tech69,DC=local
                    if (sr.Properties["distinguishedname"][0].ToString().ToLower() != domaindn.ToLower())
                    {
                        continue;
                    }

                    DirectoryEntry computer = sr.GetDirectoryEntry();
                AuthorizationRuleCollection ads = computer.ObjectSecurity.GetAccessRules(true, true, typeof(NTAccount));
                
                    
                    Console.WriteLine(sr.Properties["distinguishedname"][0].ToString());
                    foreach (ActiveDirectoryAccessRule arc in ads)
                    {

                        foreach (DictionaryEntry entry in ht)
                        {
                            //Console.WriteLine(entry.Value.ToString().ToLower());
                            //arc.ObjectType.ToString().ToLower();
                            if (entry.Value.ToString() == arc.ObjectType.ToString())
                            {
                                Console.WriteLine(sr.Properties["distinguishedname"][0].ToString()); ;
                                Console.WriteLine(arc.IdentityReference.ToString());
                                Console.WriteLine(arc.ActiveDirectoryRights.ToString());
                                Console.WriteLine(arc.ObjectType.ToString());
                                Console.WriteLine();
                            }
                        }

                    }
                }
                catch(Exception e)
                {
                    
                }

                
                

                Console.WriteLine();

               

            }
        }
