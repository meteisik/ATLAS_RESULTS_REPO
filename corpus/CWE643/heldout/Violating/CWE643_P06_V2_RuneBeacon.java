import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P06_V2_RuneBeacon {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runRuneBeacon() throws XPathExpressionException {
        String data;
        if (IO.staticFive == 5) {
            data = System.getenv("RUNE_BEACON_ADD");
        } else {
            data = null;
        }
        (new CWE643_P06_V2_RuneBeaconSink()).sinkRuneBeacon(data);
    }
}

class CWE643_P06_V2_RuneBeaconSink {

    public void sinkRuneBeacon(String data) throws XPathExpressionException {
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
