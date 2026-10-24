import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P05_V2_RuneRavenSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    private String runeRavenData;

    private void sinkRuneRaven() throws XPathExpressionException {
        String data = runeRavenData;
        String runeRavenXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            runeRavenXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            runeRavenXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] runeRavenTokens = data.split("||");
            if (runeRavenTokens.length < 2) {
                return;
            }
            String runeRavenUser = runeRavenTokens[0];
            String runeRavenPass = runeRavenTokens[1];
            XPath runeRavenXPath = XPathFactory.newInstance().newXPath();
            InputSource runeRavenXml = new InputSource(runeRavenXmlFile);
            String runeRavenQuery = "//users/user[name/text()='" + runeRavenUser
                    + "' and pass/text()='" + runeRavenPass + "']" + "/secret/text()";
            String runeRavenSecret = (String) runeRavenXPath.evaluate(runeRavenQuery, runeRavenXml, XPathConstants.STRING);
            System.out.println(runeRavenSecret);
        }
    }

    public void runRuneRaven() throws XPathExpressionException {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = "foo";
        } else {
            data = null;
        }
        runeRavenData = data;
        sinkRuneRaven();
    }
}
