import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P05_V2_RuneKestrelSafe {

    private String runeKestrelData;

    private void sinkRuneKestrel() throws XPathExpressionException {
        String data = runeKestrelData;
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

    public void runRuneKestrel() throws XPathExpressionException {
        String data;
        while (true) {
            data = "foo";
            break;
        }
        runeKestrelData = data;
        sinkRuneKestrel();
    }
}
