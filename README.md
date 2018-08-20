# usc-utils-api

usc-utils-api is a java api for converting Ulord private key to Ulord-Sidechain private key and vice-versa.

To use the api, download and copy the usc-utils-api-1.0-SNAPSHOT-all.jar file into libs directory of the project, 
and add the following in build.gradle dependencies section:-

compile fileTree(dir: 'libs', include: '*.jar')

import utils.UscConversionUtils;

//To convert Ulord private key to USC private key  
String uscPrivKey = UscConversionUtils.privKeyToUscFormat("UlordPrivateKey");  

//To get the USC address  
String address = UscConversionUtils.getUscAddress("uscPrivKey").toLowerCase();

//To convert USC private key to Ulord private key  
//First Parameter can be either ("main", "test")  
//@main to generate private key for mainnet.  
//@test to generate Private key for testnet.  
String ulordPrivateKey = UscConversionUtils.getUldPrivateKey("test","UscPrivateKey")
