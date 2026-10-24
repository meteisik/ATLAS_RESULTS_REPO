import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P06_V2_RuneRaven {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void runRuneRaven() throws XPathExpressionException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("RUNE_RAVEN_ADD");
        } else {
            data = null;
        }
        (new CWE643_P06_V2_RuneRavenSink()).sinkRuneRaven(data);
    }
}

class CWE643_P06_V2_RuneRavenSink {

    public void sinkRuneRaven(String data) throws XPathExpressionException {
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
