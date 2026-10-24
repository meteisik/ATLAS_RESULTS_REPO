import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P05_V2_RuneHarbor {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private String runeHarborData;

    private void sinkRuneHarbor() throws XPathExpressionException {
        String data = runeHarborData;
        String runeHarborXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            runeHarborXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            runeHarborXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] runeHarborTokens = data.split("||");
            if (runeHarborTokens.length < 2) {
                return;
            }
            String runeHarborUser = runeHarborTokens[0];
            String runeHarborPass = runeHarborTokens[1];
            XPath runeHarborXPath = XPathFactory.newInstance().newXPath();
            InputSource runeHarborXml = new InputSource(runeHarborXmlFile);
            String runeHarborQuery = "//users/user[name/text()='" + runeHarborUser
                    + "' and pass/text()='" + runeHarborPass + "']" + "/secret/text()";
            String runeHarborSecret = (String) runeHarborXPath.evaluate(runeHarborQuery, runeHarborXml, XPathConstants.STRING);
            System.out.println(runeHarborSecret);
        }
    }

    public void runRuneHarbor() throws XPathExpressionException {
        String data;
        if (IO.staticFive == 5) {
            data = System.getenv("RUNE_HARBOR_ADD");
        } else {
            data = null;
        }
        runeHarborData = data;
        sinkRuneHarbor();
    }
}
