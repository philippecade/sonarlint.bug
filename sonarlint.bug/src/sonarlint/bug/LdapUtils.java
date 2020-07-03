package sonarlint.bug;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Hashtable;
import java.util.List;
import java.util.StringTokenizer;

import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.NoPermissionException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.ldap.LdapContext;

/*****************************************************************************
 * LDAP Utils<br>
 * see:<a href="http://www.selfadsi.de/user-attributes-w2k3.htm">Attributes for
 * LDAP</a>
 * 
 * @author XGRS / XUTT (prev.)
 * @since Nov 9, 2012
 * 
 ****************************************************************************/
public class LdapUtils {

	/**
	 * Actually this will enable SSL/TLS protocol as negotiated. Don't be fooled by
	 * the name SSL, this is using TLS if supported by the VM.
	 **/
	private static final String ACTIVATE_SECURE_CONNECTION = "ssl";
	private static final String DOMAIN = "Domain";
	private static final String TLD = "TLD";

	public static final String TAG_GUID_EQUAL = "<GUID=";
	public static final String AREA = "Area ";

	private static LdapUtils instance = null;

	private DirContext dirContext = null;
	private String defaultNamingContext;

	/***********************************************************************
	 * Method for creating a connection to a LDAP
	 * 
	 * @param ldapURL
	 * @param ldap_User     User for LDAP work
	 * @param ldap_Password password of the ldap_User, must be plain text!
	 * @return the LDAP Connection as a DirContext(Hashtable)
	 * @throws NamingException      if this appears mostly the ldap_OU is wrong, or
	 *                              any other input.
	 * @throws UnknownHostException IP could not be determined in
	 *                              {@link #getLdapIP(ldap_Domain, ldap_TLD)}
	 */
	private static final String NAMING_EX_STR = "Could not communicate with LDAP-server. (NamingException)";
	private static final String CLOSE_EX_STR = "Error resetting {0}, could not communicate with LDAP-server. (NamingException)";
	private static final String PERMISSION_EX_STR = "Your LDAP account does not have sufficient rights to perform this action";
	private static final String CONST_LDAP_AREA_NAME = "";
	public static final int CONST_LDAP_PARAM = 1000;
	private static final String CONST_LDAP_FACTORIES_CONTROL = "com.sun.jndi.ldap.ControlFactory";
	private static final String CONST_LDAP_CTXFACTORY = "com.sun.jndi.ldap.LdapCtxFactory";
	private static final String CONST_LDAP_AUTHENTICATIONMETHOD = "simple";
	private static final String CONST_LDAP_STATEFACTORIES = "PersonStateFactory";
	private static final String CONST_LDAP_OBJECTFACTORIES = "PersonObjectFactory";
	private static final String PASS_EX_STR = "The password cannot be decoded.";

	private LdapUtils() {
		super();
	}

	public static LdapUtils getInstance() {
		if (instance == null) {
			instance = new LdapUtils();
		}
		return instance;
	}
	
	static class LdapException extends RuntimeException {

		/*************************************************************************
		 * Constructor
		 * @param string
		 ************************************************************************/
		public LdapException(String string) {
			super();
			
		}

		/*************************************************************************
		 * Constructor
		 * @param message
		 * @param e
		 ************************************************************************/
		public LdapException(String message, NamingException e) {
			super();
			
		}
		
	}

	/*************************************************************************
	 * Method creates a connection to a LDAP
	 * 
	 * @return DirContext whit the Connection to LDAP
	 * @throws LdapException
	 * 
	 ************************************************************************/
	private DirContext createLDAPConnection() throws LdapException {
		return createLDAPConnection(null, null, null);
	}

	/**
	 * lazy administrative DirContext initialization
	 */
	private DirContext getLdapSuperUserDirContext() throws LdapException {
		if (this.dirContext == null) {
			this.dirContext = createLDAPConnection();
			getDefaultNamingContext();
		}
		return this.dirContext;
	}

	/*************************************************************************
	 * Retrieves the defaultNamingContext from the root node
	 * @throws LdapException 
	 ************************************************************************/
	private void getDefaultNamingContext() throws LdapException {
		try {
			String defaultNamingContextAttrName = "";
			String rootNode = "";
			Attributes attributes = this.dirContext.getAttributes(rootNode, new String[] {defaultNamingContextAttrName});
			Attribute attribute = attributes.get(defaultNamingContextAttrName);
			if (attribute != null) {
				this.defaultNamingContext = (String) attribute.get();
			}
		} catch (NamingException e) {
			throw new LdapException(e.getMessage(), e);
		}
	}
	
	/*************************************************************************
	 * Returns the domain to use for display. Retrieves this information from the
	 * default naming context if available or from the LDAP URL.
	 * 
	 * @return Domain separated with periods
	 * @throws LdapException
	 ************************************************************************/
	private String getDomainForDisplay() throws LdapException {
		if (this.defaultNamingContext != null) {
			return this.defaultNamingContext.replace("DC=", "").replace(',', '.');
		}
		return getContextfromLDAPctx(DOMAIN) + "." + getContextfromLDAPctx(TLD);
	}
	
	/*************************************************************************
	 * Returns the domain used for searching. Retrieves this information from the
	 * default naming context if available or from the LDAP URL.
	 * 
	 * @return Format: DC=example,DC=com
	 * @throws LdapException
	 ************************************************************************/
	private String getDomainForSearch() throws LdapException {
		if (this.defaultNamingContext != null) {
			return this.defaultNamingContext;
		}
		StringBuilder sb = new StringBuilder("DC=");
		sb.append(getContextfromLDAPctx(DOMAIN));
		sb.append(",DC=").append(getContextfromLDAPctx(TLD));
		return sb.toString();
	}

	/*************************************************************************
	 * connect to any of the configured LDAP servers
	 * 
	 * @param loginSign       to check a user authentication, or null
	 * @param encodedPassword for user authentication
	 * @param alias           for user authentication
	 * @return directory service interface if successful
	 * @throws LdapException if not successful
	 ************************************************************************/
	public DirContext createLDAPConnection(String loginSign, String encodedPassword, String alias)
			throws LdapException {
		// check LDAP parameter
		if (ldapParamCheck()) {
			// the parameter might contain multiple LDAP URLs separated by a blank
			final String ldapParamS = "";
			List<String> ldapUrls = splitLdapUrls(ldapParamS);
			LdapException lastException = new LdapException(
					"Could not split LDAP configuration parameter " + CONST_LDAP_PARAM);
			for (String ldapString : ldapUrls) {
				try {
					return createLDAPConnection(loginSign, encodedPassword, alias, ldapString);
				} catch (LdapException e) {
					// the exception is ignored, as we have another LDAP to check
					lastException = e;
				}
			}
			// unsuccessful
			throw lastException;
		} else {
			String error = "No valid LDAP-server found. Please check setup of parameter " + CONST_LDAP_PARAM;
			throw new LdapException(error);
		}
	}

	/*************************************************************************
	 * @param ldapParamS with possibly multiple LDAP URLs separated by blanks
	 * @return a list of LDAP URL strings
	 ************************************************************************/
	static List<String> splitLdapUrls(String ldapParamS) {
		List<String> ldapUrlList = new ArrayList<>();
		int position = 0;
		int nextOffset = ldapParamS.toLowerCase().indexOf(" ldap");
		String ldapString;
		while (nextOffset > 0) {
			ldapString = ldapParamS.substring(position, position + nextOffset);
			ldapUrlList.add(ldapString.trim());

			position = position + nextOffset + 1; // start of next ldap
			nextOffset = ldapParamS.substring(position).toLowerCase().indexOf(" ldap");
		}
		ldapString = ldapParamS.substring(position);
		ldapUrlList.add(ldapString.trim());
		return ldapUrlList;
	}

	/*************************************************************************
	 * @param loginSign       to check a user authentication, or null
	 * @param encodedPassword for user authentication
	 * @param alias           for user authentication
	 * @param ldapString      the ldap string for 1 server
	 * @return directory service interface if successful
	 * @throws LdapException             if not successful
	 ************************************************************************/
	private static DirContext createLDAPConnection(String loginSign, String encodedPassword, String alias,
			String ldapString) throws LdapException {
		String ldapUser;
		String ldapPassword = null;
		String ldapTLD = null;
		String ldapDomain = null;

		// prepare from ldap string
		int id = ldapString.lastIndexOf('/');
		String ldapURL = ldapString.substring(0, id);
		if (loginSign == null) {
			ldapAreaCheck();

			List<String> list = formatingLdapURL(ldapURL);
			ldapTLD = list.get(0);
			ldapDomain = list.get(1);
		} else {
			ldapUser = ldapString.substring(id + 1);
		}

		// LDAP Hashtable
		Hashtable<String, String> ldapEnv = new Hashtable<>();
		ldapEnv.put(LdapContext.CONTROL_FACTORIES, CONST_LDAP_FACTORIES_CONTROL);
		ldapEnv.put(Context.INITIAL_CONTEXT_FACTORY, CONST_LDAP_CTXFACTORY);
		ldapEnv.put(Context.PROVIDER_URL, ldapURL);
		ldapEnv.put(Context.SECURITY_AUTHENTICATION, CONST_LDAP_AUTHENTICATIONMETHOD);
		ldapEnv.put(Context.SECURITY_PRINCIPAL, "");
		ldapEnv.put(Context.SECURITY_CREDENTIALS, ldapPassword);
		ldapEnv.put(Context.STATE_FACTORIES, CONST_LDAP_STATEFACTORIES);
		ldapEnv.put(Context.OBJECT_FACTORIES, CONST_LDAP_OBJECTFACTORIES);
		if (loginSign == null) {
			ldapEnv.put("java.naming.ldap.attributes.binary", "objectGUID");
			ldapEnv.put(TLD, ldapTLD);
			ldapEnv.put(DOMAIN, ldapDomain);
		}

		// LDAPS:
		if (ldapURL.toLowerCase().startsWith("ldaps")) {
			ldapEnv.put(Context.PROVIDER_URL, ldapURL);
			ldapEnv.put(Context.SECURITY_PROTOCOL, ACTIVATE_SECURE_CONNECTION);
		}

		// create LDAP Connection from ldap_env Hashtable
		try {
			return new InitialDirContext(ldapEnv);
		} catch (AuthenticationException ex) {
			String errorStr = "";
			throw new LdapException(errorStr, ex);
		} catch (NamingException namEx) {
			String errorStr = NAMING_EX_STR + "'" + ldapURL + "': " + namEx.toString(true); // debug info
			throw new LdapException(errorStr, namEx);
		}
	}

	/*************************************************************************
	 * Method splitting the domain parts of ldapURL
	 * 
	 * @param ldapURL
	 * @return List<String> with the TLD0 and domain1
	 * @throws LdapException
	 */
	static List<String> formatingLdapURL(String ldapURL) throws LdapException {
		// ldap param remove protocol
		String serverString = ldapURL.substring(ldapURL.lastIndexOf("//") + 2);
		if (serverString.contains(":")) {
			// use string until port
			serverString = serverString.substring(0, serverString.indexOf(':'));
		} else {
			// no port use string until /
			int lastSlash = serverString.lastIndexOf('/');
			if (lastSlash > 0) {
				serverString = serverString.substring(0, lastSlash);
			}
		}
		StringTokenizer strTk = new StringTokenizer(serverString, ".");
		List<String> list = new ArrayList<>();
		while (strTk.hasMoreElements()) {
			list.add(strTk.nextToken());
		}
		Collections.reverse(list);

		if (list.size() < 2) {
			throw new LdapException("System Parameter " + CONST_LDAP_PARAM + " not correct!");
		} else {
			return list;
		}
	}

	/*************************************************************************
	 * Method to Delete a LDAPUser Account DirContext from
	 * 
	 * @param ctx  {@link #createLDAPConnection(String, String, String, String, String, String)}
	 * 
	 * @param guid is the GUID from the User Account in the LDAP you want to modify
	 * @throws LdapException
	 ***********************************************************************/
	public void deleteLDAPUser(String guid) throws LdapException {
		DirContext ctx = getLdapSuperUserDirContext();
		String strGUID = TAG_GUID_EQUAL + guid + ">";
		try {
			ctx.destroySubcontext(strGUID);
		} catch (NoPermissionException e) {
			throw new LdapException(PERMISSION_EX_STR, e);
		} catch (NamingException e) {
			resetContext();
			throw new LdapException(NAMING_EX_STR, e);
		}

	}

	private void resetContext() {
		if (this.dirContext != null) {
			try {
				this.dirContext.close();
				this.dirContext = null;
			} catch (NamingException e) {
				this.dirContext = null;
			}
		}

	}

	/*************************************************************************
	 * Method to add/replace Attributes of an LDAPAccount/User
	 * 
	 * @param ctx               DirContext from
	 *                          {@link #createLDAPConnection(String, String, String, String, String, String)}
	 * @param guid              is the GUID from the User Account in the LDAP you
	 *                          want to modify
	 * @param attributeTOUpdate is the attribute to be modified
	 * @param valueofAttribute  is the new value of the Attribute
	 * @throws LdapException
	 ************************************************************************/
	public void setLDAPUserAttribute(String guid, String attributeTOUpdate, String valueofAttribute)
			throws LdapException {
		DirContext ctx = getLdapSuperUserDirContext();
		if ("".equals(valueofAttribute) || valueofAttribute == null) {
			valueofAttribute = " ";
		}
		if ("sAMAccountName".equals(attributeTOUpdate) || "userPrincipalName".equals(attributeTOUpdate)
				|| "name".equals(attributeTOUpdate)) {
			// No Changes allowed
			return;
		}
		String strGUID = TAG_GUID_EQUAL + guid + ">";
		Attributes attri = new BasicAttributes(true);
		Attribute oc = new BasicAttribute(attributeTOUpdate);
		oc.add(valueofAttribute);
		attri.put(oc);
		try {
			ctx.modifyAttributes(strGUID, DirContext.REPLACE_ATTRIBUTE, attri);
		} catch (NoPermissionException e) {
			throw new LdapException(PERMISSION_EX_STR, e);
		} catch (NamingException e) {
			resetContext();
			throw new LdapException(NAMING_EX_STR, e);
		}
	}

	/*************************************************************************
	 * Method to get Infos from a User in the LDAP
	 * 
	 * @param ctx       DirContext from
	 *                  {@link #createLDAPConnection(String, String, String, String, String, String)}
	 * @param guid      new globally unique identifier from LdapExplorer
	 * @param attribute is the Attribute you want to get from the uSign e.g "mail"
	 *                  or "c" for country
	 * @return the attribute as a String
	 * @throws LdapException
	 ************************************************************************/
	public String getLDAPUserAttribute(String guid, String attribute) throws LdapException {
		DirContext ctx = getLdapSuperUserDirContext();

		String[] returnedAtts = { attribute };
		String strGUID = TAG_GUID_EQUAL + guid + ">";
		Attributes attr;
		try {
			attr = ctx.getAttributes(strGUID, returnedAtts);
			int c = attribute.length() + 2;
			String result = attr.get(attribute).toString().substring(c);
			if ("".equals(result.trim())) {
				return null;
			}
			return result;
		} catch (NoPermissionException e) {
			throw new LdapException(PERMISSION_EX_STR, e);
		} catch (NullPointerException e) {
			// requested attribute is empty
			return null;
		} catch (NamingException e) {
			resetContext();
			throw new LdapException(NAMING_EX_STR, e);
		}

	}

	/*************************************************************************
	 * Method to get the GUID of an idou
	 * 
	 * @param attrs Attributes from
	 *              {@link #createLDAPConnection(String, String, String, String, String, String)}
	 * @return the GUID
	 * @throws LdapException
	 */
	public static String getLDAPUserGUID(Attributes attrs) throws LdapException {
		try {
			byte[] guid = (byte[]) attrs.get("objectGUID").get();
			return buildStringGuid(guid);
		} catch (NamingException e) {
			throw new LdapException(NAMING_EX_STR, e);
		}
	}

	/*************************************************************************
	 * @param guid 16 bytes
	 * @return GUID String representation
	 ************************************************************************/
	public static String buildStringGuid(byte[] guid) {
		StringBuilder strGUID = new StringBuilder();
		// convert the byteGUID into string format
		strGUID.append(addLeadingZero(guid[3] & 0xFF));
		strGUID.append(addLeadingZero(guid[2] & 0xFF));
		strGUID.append(addLeadingZero(guid[1] & 0xFF));
		strGUID.append(addLeadingZero(guid[0] & 0xFF));
		strGUID.append("-");
		strGUID.append(addLeadingZero(guid[5] & 0xFF));
		strGUID.append(addLeadingZero(guid[4] & 0xFF));
		strGUID.append("-");
		strGUID.append(addLeadingZero(guid[7] & 0xFF));
		strGUID.append(addLeadingZero(guid[6] & 0xFF));
		strGUID.append("-");
		strGUID.append(addLeadingZero(guid[8] & 0xFF));
		strGUID.append(addLeadingZero(guid[9] & 0xFF));
		strGUID.append("-");
		strGUID.append(addLeadingZero(guid[10] & 0xFF));
		strGUID.append(addLeadingZero(guid[11] & 0xFF));
		strGUID.append(addLeadingZero(guid[12] & 0xFF));
		strGUID.append(addLeadingZero(guid[13] & 0xFF));
		strGUID.append(addLeadingZero(guid[14] & 0xFF));
		strGUID.append(addLeadingZero(guid[15] & 0xFF));

		return strGUID.toString();
	}

	/*************************************************************************
	 * Helper Method for {@link #getLDAPUserGUID(DirContext, String)}
	 ************************************************************************/
	private static String addLeadingZero(int k) {
		return (k <= 0xF) ? new StringBuilder("0").append(Integer.toHexString(k)).toString() : Integer.toHexString(k);
	}

	/*************************************************************************
	 * Method to get a Context from the ctx(ldap_env) Hashtable
	 * 
	 * @param ctx DirContext from
	 *            {@link #createLDAPConnection(String, String, String, String, String, String)}
	 * @param key Context key
	 * @return a value of Context
	 * @throws LdapException
	 * @throws NamingException           if this appears mostly the ldap_OU is
	 *                                   wrong, or any other input.
	 ************************************************************************/
	public String getContextfromLDAPctx(String key) throws LdapException {
		DirContext ctx = getLdapSuperUserDirContext();

		try {
			return ctx.getEnvironment().get(key).toString();
		} catch (NamingException e) {
			resetContext();
			return null;
		}
	}

	/*************************************************************************
	 * @return true if LdapParam check was successful.
	 ************************************************************************/
	public static boolean ldapParamCheck() {
		String stringValue = "";
		return true;
	}

	/***********************************************************************
	 * @throws LdapException if Area check was not successful
	 **********************************************************************/
	public static void ldapAreaCheck() throws LdapException {
	}

	/*************************************************************************
	 * @param guidGUID to be validated¨
	 * @return true if GUID is valid.
	 * @throws LdapException
	 ************************************************************************/
	public static boolean validateLdapGuid(String guid) throws LdapException {
		String erro = "A fatal error occurred during the processing LDAP_GUID: \"" + guid
				+ "\" LDAP_GUID is incorrect or flawed!";
		if (guid.length() < 36) {
			throw new LdapException(erro);
		}
		int count = 0;
		if (count != 4) {
			throw new LdapException(erro);
		} else {
			return true;
		}
	}

	/**
	 * *********************************************************************** The
	 * method builds nodes for ldapTreeTable
	 * 
	 * @param ouName
	 * @return
	 * @throws LdapException
	 ***********************************************************************
	 */

	public String buildTree(String ouName) throws LdapException {
		return "";
	}

}
