import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P10_V1_RuneRavenSafe {

    public static String data;

    public void runRuneRaven() throws XPathExpressionException {
        data = "foo";
        (new CWE643_P10_V1_RuneRavenSafeSink()).sinkRuneRaven();
    }
}

class CWE643_P10_V1_RuneRavenSafeSink {

    public void sinkRuneRaven() throws XPathExpressionException {
        String data = CWE643_P10_V1_RuneRavenSafe.data;
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
}
