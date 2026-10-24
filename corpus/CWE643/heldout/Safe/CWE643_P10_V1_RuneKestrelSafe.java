import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P10_V1_RuneKestrelSafe {

    public static String data;

    public void runRuneKestrel() throws XPathExpressionException {
        data = "foo";
        (new CWE643_P10_V1_RuneKestrelSafeSink()).sinkRuneKestrel();
    }
}

class CWE643_P10_V1_RuneKestrelSafeSink {

    public void sinkRuneKestrel() throws XPathExpressionException {
        String data = CWE643_P10_V1_RuneKestrelSafe.data;
        String runeKestrelXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            runeKestrelXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            runeKestrelXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] runeKestrelTokens = data.split("||");
            if (runeKestrelTokens.length < 2) {
                return;
            }
            String runeKestrelUser = runeKestrelTokens[0];
            String runeKestrelPass = runeKestrelTokens[1];
            XPath runeKestrelXPath = XPathFactory.newInstance().newXPath();
            InputSource runeKestrelXml = new InputSource(runeKestrelXmlFile);
            String runeKestrelQuery = "//users/user[name/text()='" + runeKestrelUser
                    + "' and pass/text()='" + runeKestrelPass + "']" + "/secret/text()";
            String runeKestrelSecret = (String) runeKestrelXPath.evaluate(runeKestrelQuery, runeKestrelXml, XPathConstants.STRING);
            System.out.println(runeKestrelSecret);
        }
    }
}
