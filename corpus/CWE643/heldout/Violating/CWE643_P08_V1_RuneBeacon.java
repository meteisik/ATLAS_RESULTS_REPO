import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P08_V1_RuneBeacon {

    public void runRuneBeacon() throws XPathExpressionException {
        String data;
        data = System.getenv("RUNE_BEACON_ADD");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE643_P08_V1_RuneBeaconSink()).sinkRuneBeacon(dataArray);
    }
}

class CWE643_P08_V1_RuneBeaconSink {

    public void sinkRuneBeacon(String[] dataArray) throws XPathExpressionException {
        String data = dataArray[2];
        String runeBeaconXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            runeBeaconXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            runeBeaconXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] runeBeaconTokens = data.split("||");
            if (runeBeaconTokens.length < 2) {
                return;
            }
            String runeBeaconUser = runeBeaconTokens[0];
            String runeBeaconPass = runeBeaconTokens[1];
            XPath runeBeaconXPath = XPathFactory.newInstance().newXPath();
            InputSource runeBeaconXml = new InputSource(runeBeaconXmlFile);
            String runeBeaconQuery = "//users/user[name/text()='" + runeBeaconUser
                    + "' and pass/text()='" + runeBeaconPass + "']" + "/secret/text()";
            String runeBeaconSecret = (String) runeBeaconXPath.evaluate(runeBeaconQuery, runeBeaconXml, XPathConstants.STRING);
            System.out.println(runeBeaconSecret);
        }
    }
}
