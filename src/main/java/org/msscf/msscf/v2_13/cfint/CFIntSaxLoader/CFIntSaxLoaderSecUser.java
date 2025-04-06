
// Description: Java 11 XML SAX Element Handler for SecUser

/*
 *	org.msscf.msscf.CFInt
 *
 *	Copyright (c) 2020 Mark Stephen Sobkow
 *	
 *	MSS Code Factory CFSec 2.13 Security Essentials
 *	
 *	Copyright 2020-2021 Mark Stephen Sobkow mark.sobkow@gmail.com
 *	
 *	Licensed under the Apache License, Version 2.0 (the "License");
 *	you may not use this file except in compliance with the License.
 *	You may obtain a copy of the License at
 *	
 *	http://www.apache.org/licenses/LICENSE-2.0
 *	
 *	Unless required by applicable law or agreed to in writing, software
 *	distributed under the License is distributed on an "AS IS" BASIS,
 *	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *	See the License for the specific language governing permissions and
 *	limitations under the License.
 *
 *	Manufactured by MSS Code Factory 2.12
 */

package org.msscf.msscf.v2_13.cfint.CFIntSaxLoader;

import java.math.*;
import java.sql.*;
import java.text.*;
import java.util.*;
import org.apache.commons.codec.binary.Base64;
import org.xml.sax.*;
import org.msscf.msscf.v2_13.cflib.CFLib.*;
import org.msscf.msscf.v2_13.cfsec.CFSec.*;
import org.msscf.msscf.v2_13.cfint.CFInt.*;
import org.msscf.msscf.v2_13.cfsec.CFSecObj.*;
import org.msscf.msscf.v2_13.cfint.CFIntObj.*;

/*
 *	CFIntSaxLoaderSecUserParse XML SAX Element Handler implementation
 *	for SecUser.
 */
public class CFIntSaxLoaderSecUser
	extends CFLibXmlCoreElementHandler
{
	public CFIntSaxLoaderSecUser( CFIntSaxLoader saxLoader ) {
		super( saxLoader );
	}

	public void startElement(
		String		uri,
		String		localName,
		String		qName,
		Attributes	attrs )
	throws SAXException
	{
		final String S_ProcName = "startElement";
		ICFIntSecUserObj origBuff = null;
		ICFIntSecUserEditObj editBuff = null;
		// Common XML Attributes
		String attrId = null;
		// SecUser Attributes
		String attrLoginId = null;
		String attrEMailAddress = null;
		String attrEMailConfirmUuid = null;
		String attrPasswordHash = null;
		String attrPasswordResetUuid = null;
		String attrDefDev = null;
		// SecUser References
		ICFIntSecDeviceObj refDefDev = null;
		// Attribute Extraction
		String attrLocalName;
		int numAttrs;
		int idxAttr;
		final String S_LocalName = "LocalName";
		try {
			assert qName.equals( "SecUser" );

			CFIntSaxLoader saxLoader = (CFIntSaxLoader)getParser();
			if( saxLoader == null ) {
				throw new CFLibNullArgumentException( getClass(),
					S_ProcName,
					0,
					"getParser()" );
			}

			ICFIntSchemaObj schemaObj = saxLoader.getSchemaObj();
			if( schemaObj == null ) {
				throw new CFLibNullArgumentException( getClass(),
					S_ProcName,
					0,
					"getParser().getSchemaObj()" );
			}

			// Instantiate an edit buffer for the parsed information
			origBuff = (ICFIntSecUserObj)schemaObj.getSecUserTableObj().newInstance();
			editBuff = (ICFIntSecUserEditObj)origBuff.beginEdit();

			// Extract Attributes
			numAttrs = attrs.getLength();
			for( idxAttr = 0; idxAttr < numAttrs; idxAttr++ ) {
				attrLocalName = attrs.getLocalName( idxAttr );
				if( attrLocalName.equals( "Id" ) ) {
					if( attrId != null ) {
						throw new CFLibUniqueIndexViolationException( getClass(),
							S_ProcName,
							S_LocalName,
							attrLocalName );
					}
					attrId = attrs.getValue( idxAttr );
				}
				else if( attrLocalName.equals( "LoginId" ) ) {
					if( attrLoginId != null ) {
						throw new CFLibUniqueIndexViolationException( getClass(),
							S_ProcName,
							S_LocalName,
							attrLocalName );
					}
					attrLoginId = attrs.getValue( idxAttr );
				}
				else if( attrLocalName.equals( "EMailAddress" ) ) {
					if( attrEMailAddress != null ) {
						throw new CFLibUniqueIndexViolationException( getClass(),
							S_ProcName,
							S_LocalName,
							attrLocalName );
					}
					attrEMailAddress = attrs.getValue( idxAttr );
				}
				else if( attrLocalName.equals( "EMailConfirmUuid" ) ) {
					if( attrEMailConfirmUuid != null ) {
						throw new CFLibUniqueIndexViolationException( getClass(),
							S_ProcName,
							S_LocalName,
							attrLocalName );
					}
					attrEMailConfirmUuid = attrs.getValue( idxAttr );
				}
				else if( attrLocalName.equals( "PasswordHash" ) ) {
					if( attrPasswordHash != null ) {
						throw new CFLibUniqueIndexViolationException( getClass(),
							S_ProcName,
							S_LocalName,
							attrLocalName );
					}
					attrPasswordHash = attrs.getValue( idxAttr );
				}
				else if( attrLocalName.equals( "PasswordResetUuid" ) ) {
					if( attrPasswordResetUuid != null ) {
						throw new CFLibUniqueIndexViolationException( getClass(),
							S_ProcName,
							S_LocalName,
							attrLocalName );
					}
					attrPasswordResetUuid = attrs.getValue( idxAttr );
				}
				else if( attrLocalName.equals( "DefDev" ) ) {
					if( attrDefDev != null ) {
						throw new CFLibUniqueIndexViolationException( getClass(),
							S_ProcName,
							S_LocalName,
							attrLocalName );
					}
					attrDefDev = attrs.getValue( idxAttr );
				}
				else if( attrLocalName.equals( "schemaLocation" ) ) {
					// ignored
				}
				else {
					throw new CFLibUnrecognizedAttributeException( getClass(),
						S_ProcName,
						getParser().getLocationInfo(),
						attrLocalName );
				}
			}

			// Ensure that required attributes have values
			if( attrLoginId == null ) {
				throw new CFLibNullArgumentException( getClass(),
					S_ProcName,
					0,
					"LoginId" );
			}
			if( attrEMailAddress == null ) {
				throw new CFLibNullArgumentException( getClass(),
					S_ProcName,
					0,
					"EMailAddress" );
			}
			if( attrPasswordHash == null ) {
				throw new CFLibNullArgumentException( getClass(),
					S_ProcName,
					0,
					"PasswordHash" );
			}

			// Save named attributes to context
			CFLibXmlCoreContext curContext = getParser().getCurContext();
			curContext.putNamedValue( "Id", attrId );
			curContext.putNamedValue( "LoginId", attrLoginId );
			curContext.putNamedValue( "EMailAddress", attrEMailAddress );
			curContext.putNamedValue( "EMailConfirmUuid", attrEMailConfirmUuid );
			curContext.putNamedValue( "PasswordHash", attrPasswordHash );
			curContext.putNamedValue( "PasswordResetUuid", attrPasswordResetUuid );
			curContext.putNamedValue( "DefDev", attrDefDev );

			// Convert string attributes to native Java types
			// and apply the converted attributes to the editBuff.

			Integer natId;
			if( ( attrId != null ) && ( attrId.length() > 0 ) ) {
				natId = Integer.valueOf( Integer.parseInt( attrId ) );
			}
			else {
				natId = null;
			}
			String natLoginId = attrLoginId;
			editBuff.setRequiredLoginId( natLoginId );

			String natEMailAddress = attrEMailAddress;
			editBuff.setRequiredEMailAddress( natEMailAddress );

			UUID natEMailConfirmUuid;
			if( ( attrEMailConfirmUuid == null ) || ( attrEMailConfirmUuid.length() <= 0 ) ) {
				natEMailConfirmUuid = null;
			}
			else {
				natEMailConfirmUuid = UUID.fromString( attrEMailConfirmUuid );
			}
			editBuff.setOptionalEMailConfirmUuid( natEMailConfirmUuid );

			String natPasswordHash = attrPasswordHash;
			editBuff.setRequiredPasswordHash( natPasswordHash );

			UUID natPasswordResetUuid;
			if( ( attrPasswordResetUuid == null ) || ( attrPasswordResetUuid.length() <= 0 ) ) {
				natPasswordResetUuid = null;
			}
			else {
				natPasswordResetUuid = UUID.fromString( attrPasswordResetUuid );
			}
			editBuff.setOptionalPasswordResetUuid( natPasswordResetUuid );

			// Get the scope/container object

			CFLibXmlCoreContext parentContext = curContext.getPrevContext();
			Object scopeObj;
			if( parentContext != null ) {
				scopeObj = parentContext.getNamedValue( "Object" );
			}
			else {
				scopeObj = null;
			}

			// Lookup refDefDev by key name value attr
			if( ( attrDefDev != null ) && ( attrDefDev.length() > 0 ) ) {
				refDefDev = (ICFIntSecDeviceObj)schemaObj.getSecDeviceTableObj().readSecDeviceByNameIdx( editBuff.getOptionalDfltDevUserId(),
				attrDefDev );
				if( refDefDev == null ) {
					throw new CFLibNullArgumentException( getClass(),
						S_ProcName,
						0,
						"Resolve DefDev reference named \"" + attrDefDev + "\" to table SecDevice" );
				}
			}
			else {
				refDefDev = null;
			}
			editBuff.setOptionalLookupDefDev( refDefDev );

			CFIntSaxLoader.LoaderBehaviourEnum loaderBehaviour = saxLoader.getSecUserLoaderBehaviour();
			ICFIntSecUserEditObj editSecUser = null;
			ICFIntSecUserObj origSecUser = (ICFIntSecUserObj)schemaObj.getSecUserTableObj().readSecUserByULoginIdx( editBuff.getRequiredLoginId() );
			if( origSecUser == null ) {
				editSecUser = editBuff;
			}
			else {
				switch( loaderBehaviour ) {
					case Insert:
						break;
					case Update:
						editSecUser = (ICFIntSecUserEditObj)origSecUser.beginEdit();
						editSecUser.setRequiredLoginId( editBuff.getRequiredLoginId() );
						editSecUser.setRequiredEMailAddress( editBuff.getRequiredEMailAddress() );
						editSecUser.setOptionalEMailConfirmUuid( editBuff.getOptionalEMailConfirmUuid() );
						editSecUser.setRequiredPasswordHash( editBuff.getRequiredPasswordHash() );
						editSecUser.setOptionalPasswordResetUuid( editBuff.getOptionalPasswordResetUuid() );
						editSecUser.setOptionalLookupDefDev( editBuff.getOptionalLookupDefDev() );
						break;
					case Replace:
						editSecUser = (ICFIntSecUserEditObj)origSecUser.beginEdit();
						editSecUser.deleteInstance();
						editSecUser = null;
						origSecUser = null;
						editSecUser = editBuff;
						break;
				}
			}

			if( editSecUser != null ) {
				if( origSecUser != null ) {
					editSecUser.update();
				}
				else {
					origSecUser = (ICFIntSecUserObj)editSecUser.create();
				}
				editSecUser = null;
			}

			curContext.putNamedValue( "Object", origSecUser );
		}
		catch( RuntimeException e ) {
			throw new SAXException( "Near " + getParser().getLocationInfo() + ": Caught and rethrew " + e.getClass().getName() + " - " + e.getMessage(),
				e );
		}
		catch( Error e ) {
			throw new SAXException( "Near " + getParser().getLocationInfo() + ": Caught and rethrew " + e.getClass().getName() + " - " + e.getMessage() );
		}
	}

	public void endElement(
		String		uri,
		String		localName,
		String		qName )
	throws SAXException
	{
	}
}
