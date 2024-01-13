 public static string[] decodeuac(int uac)
        {

            OrderedDictionary od = new OrderedDictionary();
            od.Add("PARTIAL_SECRETS_ACCOUNT", 0x04000000);
            od.Add("TRUSTED_TO_AUTH_FOR_DELEGATION", 0x1000000);
            od.Add("PASSWORD_EXPIRED", 0x800000);
            od.Add("DONT_REQ_PREAUTH", 0x400000);
            od.Add("USE_DES_KEY_ONLY", 0x200000);
            od.Add("NOT_DELEGATED", 0x100000);
            od.Add("TRUSTED_FOR_DELEGATION", 0x80000);
            od.Add("SMARTCARD_REQUIRED", 0x40000);
            od.Add("MNS_LOGON_ACCOUNT", 0x20000);
            od.Add("DONT_EXPIRE_PASSWORD", 0x10000);
            od.Add("SERVER_TRUST_ACCOUNT", 0x2000);
            od.Add("WORKSTATION_TRUST_ACCOUNT", 0x1000);
            od.Add("INTERDOMAIN_TRUST_ACCOUNT", 0x0800);
            od.Add("NORMAL_ACCOUNT", 0x0200);
            od.Add("TEMP_DUPLICATE_ACCOUNT", 0x0100);
            od.Add("ENCRYPTED_TEXT_PWD_ALLOWED", 0x0080);
            od.Add("PASSWD_CANT_CHANGE", 0x0040);
            od.Add("PASSWD_NOTREQD", 0x0020);
            od.Add("LOCKOUT", 0x0010);
            od.Add("HOMEDIR_REQUIRED", 0x0008);
            od.Add("ACCOUNTDISABLE", 2);
            od.Add("SCRIPT", 1); ;

            string[] uacvalues = new string[od.Count];

            int temp = uac;
            int counter = 0;
            foreach (DictionaryEntry de in od)
            {
                // uac = 0x80000
                if ((temp | Convert.ToInt32(de.Value)) == temp)
                {
                    uacvalues[counter] = de.Key.ToString();
                    counter += 1;
                    temp = temp - Convert.ToInt32(de.Value);
                }
            }

            return uacvalues;

        }

