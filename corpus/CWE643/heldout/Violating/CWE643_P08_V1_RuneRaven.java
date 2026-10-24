import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P08_V1_RuneRaven {

    public void runRuneRaven() throws XPathExpressionException {
        String data;
        data = System.getenv("RUNE_RAVEN_ADD");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE643_P08_V1_RuneRavenSink()).sinkRuneRaven(dataArray);
    }
}

class CWE643_P08_V1_RuneRavenSink {

    public void sinkRuneRaven(String[] dataArray) throws XPathExpressionException {
        String data = dataArray[2];
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
